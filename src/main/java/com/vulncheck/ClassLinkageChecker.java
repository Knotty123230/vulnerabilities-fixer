package com.vulncheck;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * Static binary-compatibility checker: indexes a classpath, then walks the bytecode of chosen
 * targets looking for symbol references that the classpath cannot satisfy — the static
 * equivalent of {@code NoClassDefFoundError} / {@code NoSuchMethodError} at runtime.
 *
 * <p>Absence of evidence is treated carefully. When resolution walks into a type that is not in
 * the index (a JDK class, or a genuinely optional dependency the build never had), the checker
 * answers {@link Resolution#UNKNOWN} rather than "missing". Reporting those as errors is what
 * makes naive linkage checkers unusable — a single {@code java/lang/Object} superclass would
 * otherwise turn every inherited method call into a false {@code NoSuchMethodError}.
 */
public final class ClassLinkageChecker {

    public enum ErrorType {
        NO_CLASS_DEF_FOUND,
        NO_SUCH_METHOD,
        NO_SUCH_FIELD,
        INCOMPATIBLE_CLASS_CHANGE,
        ILLEGAL_ACCESS
    }

    public enum Severity { CRITICAL, HIGH, MEDIUM }

    public record Finding(ErrorType type, Severity severity, String referencedFrom, String target, String detail) {

        /**
         * Identity used when diffing two runs. Deliberately excludes {@code detail}, which
         * carries the bytecode context and would make otherwise-identical findings look new.
         */
        public String key() {
            return type + "|" + referencedFrom + "|" + target;
        }

        public String render() {
            return "[" + type + "] " + referencedFrom + " -> " + target + ": " + detail;
        }
    }

    private record MemberInfo(int access, String descriptor) {
    }

    private enum Resolution { FOUND, ABSENT, UNKNOWN }

    private record MemberLookup(Resolution resolution, MemberInfo member) {
        static final MemberLookup ABSENT = new MemberLookup(Resolution.ABSENT, null);
        static final MemberLookup UNKNOWN = new MemberLookup(Resolution.UNKNOWN, null);
    }

    private static final class ClassInfo {
        int access;
        String superName;
        String[] interfaces;
        String packageName;
        final Map<String, MemberInfo> methods = new HashMap<>();
        final Map<String, MemberInfo> fields = new HashMap<>();
    }

    private final Map<String, ClassInfo> index = new HashMap<>();
    private final ClassLoader jdkProbe = ClassLoader.getPlatformClassLoader();
    /** Memoises JDK probe misses — {@code Class.forName} on absent names is not cheap in a loop. */
    private final Map<String, Kind> kindCache = new HashMap<>();

    // ---------------- indexing ----------------

    public void indexClasspath(List<Path> jars) throws IOException {
        for (Path jar : jars) {
            if (jar == null || !Files.exists(jar)) {
                continue;
            }
            if (Files.isDirectory(jar)) {
                indexDirectory(jar);
            } else {
                indexJar(jar);
            }
        }
    }

    private void indexDirectory(Path dir) throws IOException {
        try (var stream = Files.walk(dir)) {
            for (Path path : stream.filter(p -> p.toString().endsWith(".class")).toList()) {
                try (InputStream is = Files.newInputStream(path)) {
                    readInto(is, new IndexVisitor());
                }
            }
        }
    }

    private void indexJar(Path jar) throws IOException {
        try (JarFile jf = new JarFile(jar.toFile())) {
            for (var e = jf.entries(); e.hasMoreElements(); ) {
                JarEntry entry = e.nextElement();
                if (!isIndexableClassEntry(entry.getName())) {
                    continue;
                }
                try (InputStream is = jf.getInputStream(entry)) {
                    readInto(is, new IndexVisitor());
                }
            }
        }
    }

    /**
     * Multi-release jars ship the same class several times under {@code META-INF/versions/N/}.
     * Indexing those would let a variant for a different Java release overwrite the base one,
     * so only the base entries are indexed.
     */
    private static boolean isIndexableClassEntry(String name) {
        return name.endsWith(".class")
                && !name.equals("module-info.class")
                && !name.endsWith("/module-info.class")
                && !name.startsWith("META-INF/versions/");
    }

    /** ASM throws on class files newer than it understands; one bad entry must not kill the scan. */
    private void readInto(InputStream is, ClassVisitor visitor) throws IOException {
        try {
            new ClassReader(is).accept(visitor, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        } catch (IllegalArgumentException | UnsupportedOperationException unreadable) {
            Log.debug("Skipping unreadable class file: %s", unreadable.getMessage());
        }
    }

    private class IndexVisitor extends ClassVisitor {
        private ClassInfo current;

        IndexVisitor() {
            super(Opcodes.ASM9);
        }

        @Override
        public void visit(int version, int access, String name, String sig, String superName, String[] ifaces) {
            current = new ClassInfo();
            current.access = access;
            current.superName = superName;
            current.interfaces = ifaces != null ? ifaces : new String[0];
            current.packageName = packageOf(name);
            // First jar on the classpath wins, mirroring how the JVM resolves duplicates.
            index.putIfAbsent(name, current);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String desc, String sig, String[] exc) {
            if (current != null) {
                current.methods.put(name + "#" + desc, new MemberInfo(access, desc));
            }
            return null;
        }

        @Override
        public FieldVisitor visitField(int access, String name, String desc, String sig, Object val) {
            if (current != null) {
                current.fields.put(name + "#" + desc, new MemberInfo(access, desc));
            }
            return null;
        }
    }

    private static String packageOf(String internalName) {
        int idx = internalName.lastIndexOf('/');
        return idx == -1 ? "" : internalName.substring(0, idx);
    }

    /**
     * Whether two classes belong to the same nest, i.e. share a top-level enclosing class.
     * Approximated from the internal name, since {@code NestHost} is absent before Java 11.
     */
    private static boolean sameNest(String left, String right) {
        return topLevelOf(left).equals(topLevelOf(right));
    }

    private static String topLevelOf(String internalName) {
        int idx = internalName.indexOf('$');
        return idx == -1 ? internalName : internalName.substring(0, idx);
    }

    // ---------------- resolution ----------------

    private enum Kind { MISSING, CLASS, INTERFACE }

    private Kind resolveClassKind(String internalName) {
        ClassInfo ci = index.get(internalName);
        if (ci != null) {
            return (ci.access & Opcodes.ACC_INTERFACE) != 0 ? Kind.INTERFACE : Kind.CLASS;
        }
        return kindCache.computeIfAbsent(internalName, name -> {
            try {
                Class<?> c = Class.forName(name.replace('/', '.'), false, jdkProbe);
                return c.isInterface() ? Kind.INTERFACE : Kind.CLASS;
            } catch (ClassNotFoundException | LinkageError ex) {
                return Kind.MISSING;
            }
        });
    }

    /**
     * Walks the type hierarchy for a member.
     *
     * <p>Returns {@link Resolution#UNKNOWN} as soon as the walk reaches a supertype that is not in
     * the index: the member could well be declared there, and claiming otherwise would be a
     * fabricated error. Only a hierarchy that is fully visible can prove a member absent.
     */
    private MemberLookup resolveMember(String owner, String name, String desc, boolean isMethod) {
        Deque<String> queue = new ArrayDeque<>();
        queue.add(owner);
        Set<String> visited = new HashSet<>();
        boolean sawUnknownSupertype = false;

        while (!queue.isEmpty()) {
            String cls = queue.poll();
            if (!visited.add(cls)) {
                continue;
            }
            ClassInfo ci = index.get(cls);
            if (ci == null) {
                // Outside the indexed classpath (JDK or an unresolved artifact): unprovable.
                sawUnknownSupertype = true;
                continue;
            }
            MemberInfo mi = (isMethod ? ci.methods : ci.fields).get(name + "#" + desc);
            if (mi != null) {
                return new MemberLookup(Resolution.FOUND, mi);
            }
            if (ci.superName != null) {
                queue.add(ci.superName);
            }
            queue.addAll(List.of(ci.interfaces));
        }

        return sawUnknownSupertype ? MemberLookup.UNKNOWN : MemberLookup.ABSENT;
    }

    // ---------------- scanning ----------------

    public List<Finding> scanReferences(List<Path> targets) throws IOException {
        List<Finding> findings = new ArrayList<>();
        for (Path p : targets) {
            if (p == null || !Files.exists(p)) {
                continue;
            }
            if (Files.isDirectory(p)) {
                scanDirectory(p, findings);
            } else {
                scanJar(p, findings);
            }
        }
        return findings;
    }

    private void scanDirectory(Path dir, List<Finding> findings) throws IOException {
        try (var stream = Files.walk(dir)) {
            for (Path path : stream.filter(p -> p.toString().endsWith(".class")).toList()) {
                try (InputStream is = Files.newInputStream(path)) {
                    readInto(is, new ScanVisitor(findings));
                }
            }
        }
    }

    private void scanJar(Path jar, List<Finding> findings) throws IOException {
        try (JarFile jf = new JarFile(jar.toFile())) {
            for (var e = jf.entries(); e.hasMoreElements(); ) {
                JarEntry entry = e.nextElement();
                if (!isIndexableClassEntry(entry.getName())) {
                    continue;
                }
                try (InputStream is = jf.getInputStream(entry)) {
                    readInto(is, new ScanVisitor(findings));
                }
            }
        }
    }

    private class ScanVisitor extends ClassVisitor {
        private final List<Finding> findings;
        private String currentClass;

        ScanVisitor(List<Finding> findings) {
            super(Opcodes.ASM9);
            this.findings = findings;
        }

        @Override
        public void visit(int v, int access, String name, String sig, String superName, String[] ifaces) {
            currentClass = name;
            if (superName != null) {
                checkTypeUsage(superName, "extends", true, false);
            }
            if (ifaces != null) {
                for (String i : ifaces) {
                    checkTypeUsage(i, "implements", false, true);
                }
            }
        }

        private void checkTypeUsage(String internalName, String context, boolean expectClass, boolean expectInterface) {
            if (internalName == null || internalName.startsWith("[")) {
                return;
            }
            Kind kind = resolveClassKind(internalName);
            if (kind == Kind.MISSING) {
                findings.add(new Finding(ErrorType.NO_CLASS_DEF_FOUND, Severity.CRITICAL, currentClass, internalName,
                        "class not present on the new classpath (" + context + ")"));
            } else if (expectClass && kind == Kind.INTERFACE) {
                findings.add(new Finding(ErrorType.INCOMPATIBLE_CLASS_CHANGE, Severity.MEDIUM, currentClass,
                        internalName, "was a class, is now an interface — extends no longer valid"));
            } else if (expectInterface && kind == Kind.CLASS) {
                findings.add(new Finding(ErrorType.INCOMPATIBLE_CLASS_CHANGE, Severity.MEDIUM, currentClass,
                        internalName, "was an interface, is now a class — implements no longer valid"));
            }
        }

        private void checkDescriptorTypes(Type type, String context) {
            Type t = type;
            while (t.getSort() == Type.ARRAY) {
                t = t.getElementType();
            }
            if (t.getSort() == Type.OBJECT) {
                checkTypeUsage(t.getInternalName(), context, false, false);
            }
        }

        private void checkMember(String owner, String name, String desc, boolean isMethod,
                                 String context, boolean expectStatic) {
            if (owner.startsWith("[")) {
                // Array types: members resolve against Object, nothing to verify.
                return;
            }
            Kind ownerKind = resolveClassKind(owner);
            if (ownerKind == Kind.MISSING) {
                findings.add(new Finding(ErrorType.NO_CLASS_DEF_FOUND, Severity.CRITICAL, currentClass, owner,
                        "declaring class of " + (isMethod ? "method " : "field ") + name
                                + " is missing (" + context + ")"));
                return;
            }

            MemberLookup lookup = resolveMember(owner, name, desc, isMethod);
            if (lookup.resolution() == Resolution.UNKNOWN) {
                return; // Hierarchy not fully visible — cannot prove anything.
            }
            if (lookup.resolution() == Resolution.ABSENT) {
                findings.add(new Finding(isMethod ? ErrorType.NO_SUCH_METHOD : ErrorType.NO_SUCH_FIELD, Severity.HIGH,
                        currentClass, owner + "." + name + desc,
                        (isMethod ? "method" : "field") + " not found anywhere in the type hierarchy ("
                                + context + ")"));
                return;
            }

            MemberInfo mi = lookup.member();
            boolean actuallyStatic = (mi.access() & Opcodes.ACC_STATIC) != 0;
            if (actuallyStatic != expectStatic) {
                findings.add(new Finding(ErrorType.INCOMPATIBLE_CLASS_CHANGE, Severity.MEDIUM, currentClass,
                        owner + "." + name,
                        (isMethod ? "method" : "field") + " changed its static modifier (" + context + ")"));
            }

            // A class reaching into its own private members — or a nestmate's, which is how
            // javac compiles inner-class access — is perfectly legal and must never be flagged.
            if (sameNest(owner, currentClass)) {
                return;
            }

            boolean isPrivate = (mi.access() & Opcodes.ACC_PRIVATE) != 0;
            boolean isPublic = (mi.access() & Opcodes.ACC_PUBLIC) != 0;
            boolean isProtected = (mi.access() & Opcodes.ACC_PROTECTED) != 0;
            if (!isPublic && !isProtected) {
                ClassInfo ownerInfo = index.get(owner);
                boolean samePackage = ownerInfo != null && ownerInfo.packageName.equals(packageOf(currentClass));
                if (isPrivate || !samePackage) {
                    findings.add(new Finding(ErrorType.ILLEGAL_ACCESS, Severity.HIGH, currentClass,
                            owner + "." + name,
                            (isMethod ? "method" : "field") + " is now "
                                    + (isPrivate ? "private" : "package-private") + " (" + context + ")"));
                }
            }
        }

        @Override
        public FieldVisitor visitField(int access, String name, String desc, String sig, Object val) {
            checkDescriptorTypes(Type.getType(desc), "field:" + name);
            return null;
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String desc, String sig, String[] exceptions) {
            for (Type t : Type.getArgumentTypes(desc)) {
                checkDescriptorTypes(t, "param of " + name);
            }
            checkDescriptorTypes(Type.getReturnType(desc), "return of " + name);
            if (exceptions != null) {
                for (String exc : exceptions) {
                    checkTypeUsage(exc, "throws:" + name, false, false);
                }
            }

            return new MethodVisitor(Opcodes.ASM9) {
                @Override
                public void visitTypeInsn(int opcode, String type) {
                    if (!type.startsWith("[")) {
                        checkTypeUsage(type, "typeinsn(" + opName(opcode) + "):" + name, false, false);
                    }
                }

                @Override
                public void visitFieldInsn(int op, String owner, String n, String d) {
                    boolean expectStatic = op == Opcodes.GETSTATIC || op == Opcodes.PUTSTATIC;
                    checkMember(owner, n, d, false, "fieldinsn(" + opName(op) + "):" + name, expectStatic);
                }

                @Override
                public void visitMethodInsn(int op, String owner, String n, String d, boolean itf) {
                    checkMember(owner, n, d, true, "methodinsn(" + opName(op) + "):" + name,
                            op == Opcodes.INVOKESTATIC);
                }

                @Override
                public void visitTryCatchBlock(Label start, Label end, Label handler, String type) {
                    if (type != null) {
                        checkTypeUsage(type, "catch:" + name, false, false);
                    }
                }

                @Override
                public void visitMultiANewArrayInsn(String desc, int dims) {
                    checkDescriptorTypes(Type.getType(desc), "multianewarray:" + name);
                }
            };
        }

        private String opName(int op) {
            return switch (op) {
                case Opcodes.NEW -> "NEW";
                case Opcodes.ANEWARRAY -> "ANEWARRAY";
                case Opcodes.CHECKCAST -> "CHECKCAST";
                case Opcodes.INSTANCEOF -> "INSTANCEOF";
                case Opcodes.GETSTATIC -> "GETSTATIC";
                case Opcodes.PUTSTATIC -> "PUTSTATIC";
                case Opcodes.GETFIELD -> "GETFIELD";
                case Opcodes.PUTFIELD -> "PUTFIELD";
                case Opcodes.INVOKESTATIC -> "INVOKESTATIC";
                case Opcodes.INVOKEVIRTUAL -> "INVOKEVIRTUAL";
                case Opcodes.INVOKESPECIAL -> "INVOKESPECIAL";
                case Opcodes.INVOKEINTERFACE -> "INVOKEINTERFACE";
                default -> "OP_" + op;
            };
        }
    }

    public static boolean hasBreakingFinding(List<Finding> findings) {
        return findings.stream().anyMatch(f -> f.severity() == Severity.CRITICAL || f.severity() == Severity.HIGH);
    }
}
