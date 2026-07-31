# vulnchecker

Scans a Maven project for vulnerable dependencies and applies **verified** version fixes to its
`pom.xml`.

The emphasis is on *verified*. Bumping a version number is easy; proving that the bump actually
removes the vulnerable artifact from the graph Maven resolves is the hard part, and it is the only
part that makes a fix real. For every candidate version the tool rewrites the POM in memory,
re-resolves the full dependency graph, and keeps the change only if the affected version is gone.

```
Dependency vulnerability report
────────────────────────────────────────────────────────────────
Project      /src/demo-service
Application  demo-app
Components   87 scanned, 4 vulnerable
Policy       same major (minor and patch upgrades)
Duration     41s

RESOLVED (2)
  ✔ org.apache.commons:commons-text 1.8 CRITICAL
      fix org.apache.commons:commons-configuration2 2.7 -> 2.9.0 (minor)
      cve CVE-2022-42889
      via org.apache.commons:commons-configuration2:2.7 -> org.apache.commons:commons-text:1.8

OUTSTANDING (1)
  ✖ org.apache.commons:commons-lang3 3.9 MEDIUM
      cve CVE-2021-1111
      note the scanner did not publish a remediated version for this advisory

────────────────────────────────────────────────────────────────
Summary  2 fixed · 1 outstanding (highest: MEDIUM)
Gate failed — outstanding findings at MEDIUM (threshold: MEDIUM)
```

## Build

```bash
mvn clean package          # produces target/vulnerabilities-fixer-1.0-SNAPSHOT.jar (executable)
mvn test -Dtest.excludedGroups=network   # unit tests only, no network
```

Requires JDK 21+. Always build with `clean`: an IDE building into the same `target/` with a
different JDK leaves class files Maven will not overwrite.

Tests tagged `network` resolve real artifacts through this machine's `settings.xml`. If the
repository is unreachable they are **skipped**, not failed — an offline machine is not a
regression. Exclude them entirely with `-Dtest.excludedGroups=network`.

## Usage

```bash
java -jar vulnchecker.jar -p /path/to/project --scan-sonatype --dry-run
```

Always start with `--dry-run`. It performs the entire analysis, including verification, and
reports exactly what it would change without touching a file.

`--scan-sonatype` is what finds vulnerabilities. The graph-based checks — `--fix-quarantined` and
`--align-families` — read the dependency tree directly and work without it:

```bash
java -jar vulnchecker.jar -p . --fix-quarantined --align-families --dry-run
```

### What runs, in order

1. **Repository firewall** (`--fix-quarantined`) — a quarantined component blocks the build, so it
   is cleared before anything else looks at the graph.
2. **Vulnerabilities** (`--scan-sonatype`) — one verified fix per component.
3. **Version skew** — always detected; aligned via BOM import with `--align-families`.

### Options that matter

| Option | Default | Purpose |
|---|---|---|
| `-p, --project DIR` | — | Maven project directory (the one containing `pom.xml`) |
| `--dry-run` | off | Analyse and report, write nothing |
| `--upgrade-scope PATCH\|MINOR\|MAJOR` | `MINOR` | How far a version may move |
| `--fail-on CRITICAL\|HIGH\|MEDIUM\|LOW\|NONE` | `HIGH` | Severity that makes the gate fail |
| `--check-linkage` | off | Also verify binary compatibility (see below) |
| `--align-families` | off | Allow importing a family BOM to fix mixed versions (see below) |
| `--fix-quarantined` | off | Pin components blocked by the repository firewall (see below) |
| `--no-check-quarantine` | — | Skip verifying that a chosen version is not quarantined |
| `--report-format MARKDOWN\|JSON` | `MARKDOWN` | Format for `--report-file` |
| `--report-file FILE` | — | Write the report to a file as well |
| `--max-candidates N` | `12` | Cap on versions tried per strategy |
| `-q/--quiet`, `-v/--verbose` | — | Report only / full resolver diagnostics |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No outstanding findings at or above `--fail-on` |
| `1` | Outstanding findings at or above the threshold — the gate failed |
| `2` | The tool could not complete the scan |

## How a fix is chosen

Maven offers several places where a version can be controlled, and they are not equally good. The
tool tries them **least-invasive first**, so the resulting diff is the one a reviewer would have
written by hand:

1. **Direct dependency** — the vulnerable artifact is declared in this POM. Just move it.
2. **Declared dependency** — bump the dependency that drags the vulnerable one in transitively.
   This is usually the right fix for a transitive CVE: it keeps the project's dependency set
   internally consistent.
3. **Imported BOM / parent POM** — when the version is governed centrally, move the governor.
4. **`dependencyManagement` pin** — last resort. Per Maven's resolution rules, the current POM's
   `dependencyManagement` beats both nearest-wins mediation and any imported BOM, so this always
   works. That is exactly why it is last: it silently diverges the project from its BOM, and the
   next BOM upgrade will quietly carry a stale pin along.

Within a strategy, candidate versions are ordered ascending and searched so that the **smallest
sufficient bump** wins — the newest candidate is verified first to see whether the strategy can
work at all, then a binary search finds the lowest version that also clears the vulnerability.
That is `log₂(n)` graph resolutions instead of `n`, and a smaller diff.

Groups that ship as a coordinated set (`ch.qos.logback`, `org.slf4j`, `com.fasterxml.jackson.*`,
`org.springframework`, `io.netty`) are upgraded with a wildcard artifact so the whole set moves
together — mixing versions inside them is a classic source of `NoSuchMethodError`.

### Mixed versions and family BOMs (`--align-families`)

Artifacts that ship as a set — `io.netty:netty-buffer` and `io.netty:netty-codec`, the Jackson
modules, gRPC — must resolve at one version. When they drift apart the build stays green and the
first call that crosses the boundary throws `NoSuchMethodError` in production. Bumping only the
declared dependency does not fix this: family members pulled in transitively stay behind.

**Detection always runs** and is reported in its own section:

```
MIXED VERSIONS (1)
  ! io.netty 4.1.100.Final, 4.1.110.Final
          netty-buffer:4.1.100.Final
          netty-codec:4.1.110.Final
          netty-common:4.1.100.Final
      fix import io.netty:netty-bom:4.1.110.Final to pin the whole family
          re-run with --align-families to apply
```

A "family" is defined by its BOM, not by groupId. Grouping by groupId alone would flag
`org.apache.commons:commons-lang3:3.12.0` alongside `commons-text:1.10.0`, which are supposed to
differ. Instead a group is only treated as lockstep when a published BOM pins all of its artifacts
to *the same* version. The BOM is found by naming convention plus a small curated table
(Jackson's BOM lives under a different groupId than its artifacts), then **verified by reading its
descriptor** — `ch.qos.logback` publishes `logback-parent`, which a convention-only guess would
wrongly adopt.

With `--align-families`, every skewed family is aligned — whether or not any vulnerability points
at it. A project with a clean security report and a drifted family is the common case, so this
runs as its own phase rather than only inside vulnerability remediation. The BOM is imported and
the now-redundant versions are stripped:

```xml
<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>io.netty</groupId><artifactId>netty-bom</artifactId>
      <version>4.1.118.Final</version><type>pom</type><scope>import</scope>
    </dependency>
  </dependencies>
</dependencyManagement>
```

Off by default, and only applied to families that have actually drifted, because the import lands
in the current POM's `dependencyManagement` — which outranks any inherited BOM. In a Spring Boot
project that silently detaches the family from the Boot BOM, and the next Boot upgrade drags a
stale pin along.

Nothing is written until re-resolving proves the family converged on a single version. Aligning a
badly split family can require a major upgrade of the laggard — `org.glassfish.jaxb` at `2.3.1`
and `4.0.9` cannot be unified without moving `jaxb-runtime` across the `javax`→`jakarta` break —
and in that case the tool reports that no BOM version worked rather than writing a POM that
compiles into a different API. Pair it with `--check-linkage` when the jump is large.

Two caveats worth knowing. A BOM does not guarantee full coverage: `netty-bom` has historically
omitted the `netty-transport-native-*` artifacts ([netty#6738](https://github.com/netty/netty/issues/6738)),
which is why alignment is confirmed by re-resolving rather than by trusting the edit. And a version
driven by a `<property>` leaves the property behind after its `<version>` is removed
([openrewrite#4350](https://github.com/openrewrite/rewrite/issues/4350)) — cosmetic, but visible in
the diff.

To gate on this in CI independently of the fixer, Maven Enforcer's
[`dependencyConvergence`](https://maven.apache.org/enforcer/enforcer-rules/dependencyConvergence.html)
and [`requireUpperBoundDeps`](https://maven.apache.org/enforcer/enforcer-rules/requireUpperBoundDeps.html)
rules cover the same ground and are usually enabled together.

### Repository firewall quarantine (`--fix-quarantined`)

Sonatype Repository Firewall quarantines a component the first time it is requested if it violates
policy, and the proxy answers with HTTP 403:

```
status code: 403, reason phrase: ---->>> REQUESTED ITEM IS QUARANTINED ---->>>
FOR DETAILS SEE ---->>> https://iq.example.com/ui/links/firewall/repositories/quarantinedComponent/... <<<----
```

That is a build-stopping problem, and the
[documented remediation](https://help.sonatype.com/en/firewall-quarantine.html) is to move to a
version without the violation — which is what this automates.

Two separate behaviours:

**Always on: never fix into a quarantined version.** `maven-metadata.xml` lists every published
version, including ones this network will refuse. Choosing a fix from metadata alone can swap a
CVE for a broken build, so before a candidate is accepted the artifact is confirmed downloadable.
Disable with `--no-check-quarantine`.

**Opt-in: `--fix-quarantined`.** Probes every resolved artifact and pins each quarantined one to
the nearest version the firewall serves. This downloads the classpath — the same work the build
would do — which is why it is not on by default.

It runs **before** everything else, and works **without a vulnerability scan**:

```bash
# No Sonatype needed — this reads the dependency graph directly
java -jar vulnchecker.jar -p . --fix-quarantined --dry-run
```

Both properties matter for a build that is already broken. A quarantined component stops
resolution, so it outranks every CVE in the report and has to be cleared before anything else can
be analysed; and a project the firewall is blocking usually cannot be scanned at all, because the
scanner has to resolve it first. Requiring `--scan-sonatype` here would have made the feature
unusable in exactly the situation it exists for.

If a quarantined POM makes the graph unresolvable outright, the failure is restated in plain terms
rather than as a stack of nested Aether exceptions:

```
ERROR The dependency graph cannot be resolved: org.jetbrains.kotlinx:kotlinx-metadata-jvm:jar:0.9.0
      is quarantined by the repository firewall (https://iq.../quarantinedComponent/...).
      Nothing can be analysed until it is released or replaced — either request a policy waiver,
      or pin an allowed version by hand and re-run.
```

```
QUARANTINED BY REPOSITORY FIREWALL (1)
  ✔ org.jetbrains.kotlinx:kotlinx-metadata-jvm:0.9.0
      fix org.jetbrains.kotlinx:kotlinx-metadata-jvm -> 0.9.1
      via io.quarkus:quarkus-core:3.32.3 -> org.jetbrains.kotlinx:kotlinx-metadata-jvm:0.9.0
      why https://iq.example.com/ui/links/firewall/repositories/quarantinedComponent/...
```

A quarantined component that could not be moved **fails the gate at any `--fail-on` level except
`NONE`** — it is not a severity judgement, nothing builds until it is resolved.

Two implementation notes that matter in practice. A plain 403 (bad credentials) is deliberately
told apart from a quarantine, because they demand opposite responses — try another version, or
stop and fix the login; only the response body distinguishes them, and Maven Resolver 2.x discards
it, so the tool re-requests the artifact directly to read it. And probing a version the firewall
has never seen is what causes it to be evaluated: harmless, since a version that quarantines on
first sight is one you must not adopt, but it does add entries to the firewall dashboard.

### Binary compatibility (`--check-linkage`)

Optional and off by default, because it needs compiled classes and downloads every JAR on the
classpath. Run `mvn compile` first.

The check is **differential**: the project's bytecode is analysed against the classpath before the
upgrade and after it, and only symbols that *stopped* resolving are reported. Real codebases are
full of references a static checker cannot satisfy — optional dependencies, `provided` scope,
reflective shims — and reporting those as errors is what makes linkage checkers get switched off.
Only byte-identical scan targets are compared, so an artifact that itself changed version is
excluded from the diff rather than generating noise.

If the check cannot run, it does not veto the fix. Blocking a security patch because a secondary
check was unavailable is the wrong default; the report says the check was skipped and why.

## CI/CD

### GitHub Actions — gate a pull request

```yaml
- name: Check dependencies
  env:
    VULNCHECKER_SONATYPE_PASSWORD: ${{ secrets.SONATYPE_PASSWORD }}
    VULNCHECKER_NEXUS_PASSWORD: ${{ secrets.NEXUS_PASSWORD }}
  run: |
    java -jar vulnchecker.jar \
      --project . --scan-sonatype --dry-run \
      --fail-on HIGH \
      --report-format markdown --report-file "$GITHUB_STEP_SUMMARY"
```

`--dry-run` keeps the pipeline read-only; the job fails when something at `HIGH` or above has no
verified fix, and the Markdown report lands in the job summary.

### Open a remediation pull request

```yaml
- run: |
    java -jar vulnchecker.jar --project . --scan-sonatype \
      --fail-on NONE --report-format markdown --report-file report.md
- uses: peter-evans/create-pull-request@v6
  with:
    branch: chore/dependency-security-fixes
    title: "chore(deps): remediate dependency vulnerabilities"
    body-path: report.md
```

`--fail-on NONE` keeps the job green so the PR is always created; the report explains what was and
was not fixed.

### Machine-readable output

```bash
java -jar vulnchecker.jar -p . --scan-sonatype --dry-run --quiet \
  --report-format json --report-file findings.json

jq -r '.findings[] | select(.outcome=="NO_WORKING_FIX") | "\(.groupId):\(.artifactId) \(.severity)"' findings.json
```

Every fact in the console report is present in the JSON — outcomes, dependency paths, candidate
versions tried, and the reason a finding is outstanding.

## Configuration

### Repositories

By default the tool reads `~/.m2/settings.xml` (and the installation-wide `conf/settings.xml`) and
honours its **mirrors, proxies, server credentials, `localRepository` and offline flag**. The rule
is: *if `mvn` can resolve it on this machine, so can the tool.* Encrypted `{...}` passwords are
decrypted via `~/.m2/settings-security.xml`.

This matters most on locked-down networks. Without it, a machine whose `settings.xml` mirrors
everything to an internal Nexus would see the tool hang or fail against
`repo.maven.apache.org` — while `mvn` built the same project fine.

Precedence:

1. `--nexus-url` — explicit override; mirrors **all** repositories through it, including those
   declared inside transitive POMs, so a locked-down network never sees a direct outbound request.
2. `~/.m2/settings.xml` — mirrors, proxies, credentials, active-profile repositories.
3. Maven Central.

Use `--ignore-maven-settings` to skip step 2 (useful for reproducing a clean-machine resolution).

### Credentials

Settings are resolved from **flags → environment → saved settings**, so a pipeline only needs
secrets in the environment.

| Environment variable | Flag |
|---|---|
| `VULNCHECKER_NEXUS_URL` / `_USERNAME` / `_PASSWORD` | `--nexus-url` / `--nexus-username` / `--nexus-password` |
| `VULNCHECKER_SONATYPE_URL` / `_APPLICATION_ID` / `_USERNAME` / `_PASSWORD` | `--sonatype-*` |

`--save-nexus-credentials` / `--save-sonatype-credentials` persist the non-secret settings to
`~/.vulnchecker` and the password to the macOS Keychain — a convenience for local use. On other
platforms the Keychain is simply skipped and the password is read from the environment.

## Limitations

- **Single module.** The tool edits one `pom.xml`. In a multi-module build, run it per module;
  components belonging to other modules are reported as *not reachable from this POM* rather than
  silently ignored.
- **Remediation data comes from the scanner.** A component with no published fix is reported as
  outstanding — the tool will not invent a version.
- **Verification proves resolution, not behaviour.** It proves the vulnerable version is gone and,
  with `--check-linkage`, that symbols still resolve. It does not run your tests. Keep the build
  running after the fix.
