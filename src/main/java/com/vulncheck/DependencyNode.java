package com.vulncheck;


import java.util.ArrayList;
import java.util.List;

/**
 * {
 * "groupId": "com.vulncheck",
 * "artifactId": "vulnerabilities-fixer",
 * "version": "1.0-SNAPSHOT",
 * "type": "jar",
 * "scope": "",
 * "classifier": "",
 * "optional": "false",
 * "children": [
 * {
 * "groupId": "info.picocli",
 * "artifactId": "picocli-codegen",
 * "version": "4.7.7",
 * "type": "jar",
 * "scope": "compile",
 * "classifier": "",
 * "optional": "false",
 * "children": [
 * {
 * "groupId": "info.picocli",
 * "artifactId": "picocli",
 * "version": "4.7.7",
 * "type": "jar",
 * "scope": "compile",
 * "classifier": "",
 * "optional": "false"
 * }
 * ]
 * }
 * ]
 * }
 */
public record DependencyNode(
        String groupId,
        String artifactId,
        String version,
        String type,
        String scope,
        String classifier,
        String optional,
        List<DependencyNode> children
) {






}
