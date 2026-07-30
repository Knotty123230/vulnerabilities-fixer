package com.vulncheck;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VersionPolicyTest {

    @Nested
    @DisplayName("ordering")
    class Ordering {

        @Test
        @DisplayName("compares numerically, not lexicographically")
        void comparesNumerically() {
            // The bug this replaces: string comparison puts "1.10" below "1.9".
            assertTrue(VersionPolicy.compare("1.10.0", "1.9.0") > 0);
            assertTrue(VersionPolicy.compare("3.5.9", "3.5.10") < 0);
            assertEquals(0, VersionPolicy.compare("2.0.0", "2.0.0"));
        }

        @Test
        @DisplayName("sorts qualifiers the way Maven does")
        void sortsQualifiers() {
            assertTrue(VersionPolicy.compare("1.0-alpha", "1.0") < 0);
            assertTrue(VersionPolicy.compare("1.0-SNAPSHOT", "1.0") < 0);
            assertTrue(VersionPolicy.compare("1.0-sp1", "1.0") > 0);
        }

        @Test
        void sortsAWholeList() {
            List<String> sorted = List.of("1.2.10", "1.2.9", "1.10.0", "1.2.1")
                    .stream().sorted(VersionPolicy.ascending()).toList();
            assertEquals(List.of("1.2.1", "1.2.9", "1.2.10", "1.10.0"), sorted);
        }
    }

    @Nested
    @DisplayName("pre-release detection")
    class PreReleases {

        @Test
        void rejectsPreReleases() {
            assertTrue(VersionPolicy.isPreRelease("3.0.0-M1"));
            assertTrue(VersionPolicy.isPreRelease("3.0.0-RC2"));
            assertTrue(VersionPolicy.isPreRelease("1.0-alpha3"));
            assertTrue(VersionPolicy.isPreRelease("2.1.0-SNAPSHOT"));
            assertTrue(VersionPolicy.isPreRelease("1.0.0-beta"));
        }

        @Test
        @DisplayName("keeps release qualifiers that merely look unusual")
        void keepsRealReleases() {
            // A blanket "has a dash means pre-release" rule would discard all of these.
            assertFalse(VersionPolicy.isPreRelease("32.1.3-jre"));
            assertFalse(VersionPolicy.isPreRelease("4.1.100.Final"));
            assertFalse(VersionPolicy.isPreRelease("1.2.3-sp1"));
            assertFalse(VersionPolicy.isPreRelease("3.5.14"));
        }
    }

    @Nested
    @DisplayName("upgrade scope")
    class Scope {

        private final List<String> available = List.of(
                "3.5.14", "3.5.15", "3.5.20", "3.6.0", "4.0.0", "4.0.1", "4.1.0-M1");

        @Test
        void patchStaysOnTheSameMinorLine() {
            assertEquals(List.of("3.5.15", "3.5.20"),
                    VersionPolicy.candidates(available, "3.5.14", VersionPolicy.UpgradeScope.PATCH));
        }

        @Test
        void minorStaysOnTheSameMajor() {
            assertEquals(List.of("3.5.15", "3.5.20", "3.6.0"),
                    VersionPolicy.candidates(available, "3.5.14", VersionPolicy.UpgradeScope.MINOR));
        }

        @Test
        void majorAllowsEverythingReleased() {
            assertEquals(List.of("3.5.15", "3.5.20", "3.6.0", "4.0.0", "4.0.1"),
                    VersionPolicy.candidates(available, "3.5.14", VersionPolicy.UpgradeScope.MAJOR));
        }

        @Test
        @DisplayName("returns candidates ascending so the smallest sufficient bump is tried first")
        void ascendingOrder() {
            List<String> candidates =
                    VersionPolicy.candidates(available, "3.5.14", VersionPolicy.UpgradeScope.MAJOR);
            assertEquals("3.5.15", candidates.getFirst());
            assertEquals("4.0.1", candidates.getLast());
        }
    }

    @Nested
    @DisplayName("affected-version test")
    class Affected {

        @Test
        void theKnownBadVersionIsAffected() {
            assertTrue(VersionPolicy.isStillAffected("1.4.11", "1.4.11", List.of("1.4.14")));
        }

        @Test
        void aVersionAtOrBeyondTheFixIsNot() {
            assertFalse(VersionPolicy.isStillAffected("1.4.14", "1.4.11", List.of("1.4.14")));
            assertFalse(VersionPolicy.isStillAffected("1.4.20", "1.4.11", List.of("1.4.14")));
        }

        @Test
        @DisplayName("handles backported fixes across release lines")
        void handlesBackports() {
            // Fix backported to 1.9.5 and shipped in 2.1.0. Version 2.0.3 sorts above 1.9.5
            // but predates the fix on its own line, so it is still affected.
            List<String> remediations = List.of("1.9.5", "2.1.0");
            assertTrue(VersionPolicy.isStillAffected("2.0.3", "2.0.0", remediations));
            assertFalse(VersionPolicy.isStillAffected("2.1.0", "2.0.0", remediations));
            assertFalse(VersionPolicy.isStillAffected("1.9.5", "1.9.0", remediations));
            assertFalse(VersionPolicy.isStillAffected("3.0.0", "2.0.0", remediations));
        }

        @Test
        @DisplayName("without remediation data, only the exact reported version is provably affected")
        void withoutRemediationData() {
            assertTrue(VersionPolicy.isStillAffected("1.0.0", "1.0.0", List.of()));
            assertFalse(VersionPolicy.isStillAffected("1.0.1", "1.0.0", List.of()));
        }
    }

    @Nested
    @DisplayName("severity")
    class Severity {

        @Test
        @DisplayName("bands raw CVSS scores, which is what Sonatype reports")
        void bandsCvssScores() {
            assertEquals(4, VersionPolicy.severityRank("9.8"));
            assertEquals(3, VersionPolicy.severityRank("7.5"));
            assertEquals(2, VersionPolicy.severityRank("5.3"));
            assertEquals(1, VersionPolicy.severityRank("3.1"));
            assertEquals(0, VersionPolicy.severityRank("0"));
        }

        @Test
        void acceptsNamedLevelsToo() {
            assertEquals(4, VersionPolicy.severityRank("CRITICAL"));
            assertEquals(3, VersionPolicy.severityRank("high"));
            assertEquals(2, VersionPolicy.severityRank("Moderate"));
            assertEquals(0, VersionPolicy.severityRank(null));
        }
    }

    @Nested
    class VersionParts {

        @Test
        void extractsMajorAndMinorPastQualifiers() {
            assertEquals("4.1", VersionPolicy.majorMinor("4.1.100.Final"));
            assertEquals("4", VersionPolicy.major("4.1.100.Final"));
            assertEquals("32.1", VersionPolicy.majorMinor("32.1.3-jre"));
        }

        @Test
        void describesTheKindOfJump() {
            assertTrue(VersionPolicy.describeJump("1.0.0", "1.0.1").endsWith("(patch)"));
            assertTrue(VersionPolicy.describeJump("1.0.0", "1.1.0").endsWith("(minor)"));
            assertTrue(VersionPolicy.describeJump("1.0.0", "2.0.0").endsWith("(major)"));
        }
    }
}
