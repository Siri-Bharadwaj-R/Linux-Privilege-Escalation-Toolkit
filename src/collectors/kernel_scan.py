import platform
import re


class KernelCollector:
    """
    Collects Linux kernel information and performs
    detection-only analysis using predefined
    kernel vulnerability patterns.
    """

    def __init__(self):
        """
        Predefined vulnerability reference data.

        This database is intentionally detection-only.
        It does not download or execute exploits.
        """

        self.vulnerability_patterns = [
            {
                "name": "Dirty Pipe",
                "cve": "CVE-2022-0847",
                "affected_versions": [
                    "5.8",
                    "5.9",
                    "5.10",
                    "5.11",
                    "5.12",
                    "5.13",
                    "5.14",
                    "5.15",
                ],
                "severity": "High",
                "description": (
                    "A Linux kernel vulnerability involving "
                    "improper handling of pipe buffers."
                ),
                "mitigation": (
                    "Update the Linux kernel to a patched "
                    "vendor-supported version."
                ),
            },
            {
                "name": "OverlayFS Privilege Escalation",
                "cve": "CVE-2021-3493",
                "affected_versions": [
                    "5.8",
                    "5.9",
                    "5.10",
                    "5.11",
                ],
                "severity": "High",
                "description": (
                    "An OverlayFS vulnerability that may allow "
                    "local privilege escalation on affected systems."
                ),
                "mitigation": (
                    "Apply the security updates provided by "
                    "the Linux distribution vendor."
                ),
            },
            {
                "name": "Kernel Local Privilege Escalation Risk",
                "cve": "CVE-2021-4034",
                "affected_versions": [],
                "severity": "Medium",
                "description": (
                    "A local privilege escalation risk that should "
                    "be investigated alongside system package versions."
                ),
                "mitigation": (
                    "Keep the operating system and installed "
                    "security packages fully updated."
                ),
            },
        ]

    def collect(self) -> dict:
        """
        Collect and analyze kernel information.
        """

        kernel_release = platform.release()
        kernel_version = self._extract_kernel_version(
            kernel_release
        )

        matches = self._match_vulnerabilities(
            kernel_version
        )

        outdated = self._is_potentially_outdated(
            kernel_version
        )

        return {
            "kernel_release": kernel_release,
            "kernel_version": kernel_version,
            "kernel_matches": matches,
            "match_count": len(matches),
            "potentially_outdated": outdated,
        }

    def _extract_kernel_version(
        self,
        kernel_release: str,
    ) -> str:
        """
        Extract the major.minor version from the kernel release.

        Example:
        6.6.87.2-microsoft-standard-WSL2 -> 6.6
        """

        match = re.match(
            r"(\d+\.\d+)",
            kernel_release,
        )

        if match:
            return match.group(1)

        return "unknown"

    def _match_vulnerabilities(
        self,
        kernel_version: str,
    ) -> list:
        """
        Match the detected kernel version against the
        predefined vulnerability patterns.
        """

        matches = []

        for vulnerability in self.vulnerability_patterns:

            affected_versions = vulnerability[
                "affected_versions"
            ]

            if kernel_version in affected_versions:
                matches.append(
                    {
                        "name": vulnerability["name"],
                        "cve": vulnerability["cve"],
                        "severity": vulnerability[
                            "severity"
                        ],
                        "description": vulnerability[
                            "description"
                        ],
                        "mitigation": vulnerability[
                            "mitigation"
                        ],
                    }
                )

        return matches

    def _is_potentially_outdated(
        self,
        kernel_version: str,
    ) -> bool:
        """
        Perform a simple age-based version check.

        This is only an indicator. A distribution may
        backport security patches without changing the
        major/minor kernel version.
        """

        try:
            major, minor = map(
                int,
                kernel_version.split("."),
            )

            if major < 5:
                return True

            if major == 5 and minor < 15:
                return True

            return False

        except (
            ValueError,
            AttributeError,
        ):
            return False