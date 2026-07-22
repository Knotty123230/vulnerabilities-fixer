package com.vulncheck;

import com.google.cloud.tools.opensource.classpath.LinkageChecker;
import com.google.cloud.tools.opensource.classpath.LinkageProblem;
import com.google.cloud.tools.opensource.dependencies.Bom;
import com.google.cloud.tools.opensource.dependencies.MavenRepositoryException;
import com.google.common.collect.ImmutableSet;
import org.eclipse.aether.version.InvalidVersionSpecificationException;

import java.io.IOException;
import java.nio.file.Path;

public class LinkageMavenChecker {


    public boolean hasLinkageErrors(Path fileWithDeps) throws MavenRepositoryException, InvalidVersionSpecificationException, IOException {
        var linkageChecker = LinkageChecker.create(Bom.readBom(fileWithDeps));
        ImmutableSet<LinkageProblem> linkageErrors = linkageChecker.findLinkageProblems();

        if (!linkageErrors.isEmpty()) {
            System.out.println("Linkage errors found:");
            linkageErrors.forEach(System.out::println);
            return true;
        }
        return false;
    }


}
