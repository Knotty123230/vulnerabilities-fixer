package com.vulncheck;

import java.io.PrintStream;

/**
 * Minimal leveled logger for a CLI that has to be readable both in a terminal
 * and in a CI job log.
 *
 * <p>Rules of the house:
 * <ul>
 *   <li>Everything a human needs goes to {@code stdout}; diagnostics go to {@code stderr},
 *       so {@code vulnchecker ... > report.txt} stays clean.</li>
 *   <li>Colour is auto-disabled when there is no TTY, when {@code NO_COLOR} is set, or when
 *       {@code TERM=dumb} — CI logs must not be littered with escape codes.</li>
 *   <li>{@link #debug} output only appears with {@code --verbose}. Nothing else is chatty.</li>
 * </ul>
 */
public final class Log {

    public enum Level {
        /** Only the final report and errors. */
        QUIET,
        /** Progress headlines plus the report. The default. */
        NORMAL,
        /** Everything, including resolver and recipe diagnostics. */
        VERBOSE
    }

    public enum ColorMode { AUTO, ALWAYS, NEVER }

    private static final PrintStream OUT = System.out;
    private static final PrintStream ERR = System.err;

    private static Level level = Level.NORMAL;
    private static boolean color = detectColorSupport();

    private Log() {
    }

    public static void configure(Level newLevel, ColorMode colorMode) {
        level = newLevel;
        color = switch (colorMode) {
            case ALWAYS -> true;
            case NEVER -> false;
            case AUTO -> detectColorSupport();
        };
    }

    public static boolean isVerbose() {
        return level == Level.VERBOSE;
    }

    public static boolean isColorEnabled() {
        return color;
    }

    private static boolean detectColorSupport() {
        if (System.getenv("NO_COLOR") != null) {
            return false;
        }
        if ("dumb".equals(System.getenv("TERM"))) {
            return false;
        }
        return System.console() != null;
    }

    // ---------------- ANSI ----------------

    private static final String RESET = "[0m";
    private static final String BOLD = "[1m";
    private static final String DIM = "[2m";
    private static final String RED = "[31m";
    private static final String GREEN = "[32m";
    private static final String YELLOW = "[33m";
    private static final String BLUE = "[34m";
    private static final String MAGENTA = "[35m";
    private static final String CYAN = "[36m";

    public static String bold(String s) {
        return paint(BOLD, s);
    }

    public static String dim(String s) {
        return paint(DIM, s);
    }

    public static String red(String s) {
        return paint(RED, s);
    }

    public static String green(String s) {
        return paint(GREEN, s);
    }

    public static String yellow(String s) {
        return paint(YELLOW, s);
    }

    public static String blue(String s) {
        return paint(BLUE, s);
    }

    public static String magenta(String s) {
        return paint(MAGENTA, s);
    }

    public static String cyan(String s) {
        return paint(CYAN, s);
    }

    private static String paint(String code, String s) {
        return color ? code + s + RESET : s;
    }

    // ---------------- output ----------------

    /** A section headline. Suppressed by {@code --quiet}. */
    public static void section(String title) {
        if (level == Level.QUIET) {
            return;
        }
        OUT.println();
        OUT.println(bold(title));
    }

    /** A progress line. Suppressed by {@code --quiet}. */
    public static void info(String format, Object... args) {
        if (level == Level.QUIET) {
            return;
        }
        OUT.println(fmt(format, args));
    }

    /** An indented sub-step of the current section. Suppressed by {@code --quiet}. */
    public static void step(String format, Object... args) {
        if (level == Level.QUIET) {
            return;
        }
        OUT.println("  " + fmt(format, args));
    }

    /** Report output — always printed, even under {@code --quiet}. */
    public static void report(String format, Object... args) {
        OUT.println(fmt(format, args));
    }

    /** Diagnostics for {@code --verbose} only; goes to stderr so reports stay parseable. */
    public static void debug(String format, Object... args) {
        if (level != Level.VERBOSE) {
            return;
        }
        ERR.println(dim("  · " + fmt(format, args)));
    }

    public static void warn(String format, Object... args) {
        ERR.println(yellow("WARN  ") + fmt(format, args));
    }

    public static void error(String format, Object... args) {
        ERR.println(red("ERROR ") + fmt(format, args));
    }

    /**
     * Reports a failure with its cause. The stack trace is only shown with
     * {@code --verbose} — in CI a one-line cause is what people actually read.
     */
    public static void error(Throwable cause, String format, Object... args) {
        error(format, args);
        ERR.println(dim("      caused by: " + describe(cause)));
        if (level == Level.VERBOSE) {
            cause.printStackTrace(ERR);
        }
    }

    /** Flattens a cause chain into one line — nested Maven/Aether exceptions nest deeply. */
    public static String describe(Throwable cause) {
        StringBuilder sb = new StringBuilder();
        Throwable current = cause;
        int depth = 0;
        while (current != null && depth < 5) {
            if (depth > 0) {
                sb.append(" <- ");
            }
            sb.append(current.getClass().getSimpleName());
            if (current.getMessage() != null) {
                sb.append(": ").append(current.getMessage());
            }
            current = current.getCause();
            depth++;
        }
        return sb.toString();
    }

    private static String fmt(String format, Object... args) {
        return args.length == 0 ? format : String.format(format, args);
    }
}
