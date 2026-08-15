import os
import subprocess


class CapabilitiesCollector:
    """
    Collects Linux file capabilities and identifies
    potentially high-risk capability assignments.
    """

    def __init__(self):
        self.high_risk_capabilities = {
            "cap_setuid",
            "cap_setgid",
            "cap_sys_admin",
            "cap_dac_override",
            "cap_dac_read_search",
        }

    def collect(self) -> dict:
        """
        Run getcap across the filesystem and analyze
        discovered file capabilities.
        """

        capabilities = self._get_capabilities()
        risky_capabilities = self._find_risky_capabilities(
            capabilities
        )

        return {
            "capabilities": capabilities,
            "capability_count": len(capabilities),
            "risky_capabilities": risky_capabilities,
            "risky_capability_count": len(risky_capabilities),
        }

    def _get_capabilities(self) -> list:
        """
        Run getcap -r / to discover files with
        Linux capabilities.
        """

        try:
            process = subprocess.run(
                ["getcap", "-r", "/"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            capabilities = []

            for line in process.stdout.splitlines():
                line = line.strip()

                if not line:
                    continue

                parts = line.split(None, 1)

                if len(parts) != 2:
                    continue

                path, capability_data = parts

                capabilities.append(
                    {
                        "path": path,
                        "capabilities": capability_data,
                    }
                )

            return sorted(
                capabilities,
                key=lambda item: item["path"],
            )

        except FileNotFoundError:
            return []

        except subprocess.TimeoutExpired:
            return []

    def _find_risky_capabilities(
        self,
        capabilities: list,
    ) -> list:
        """
        Identify capability assignments containing
        potentially privilege-impacting capabilities.
        """

        risky = []

        for item in capabilities:
            capability_text = item["capabilities"].lower()

            detected = [
                capability
                for capability in self.high_risk_capabilities
                if capability in capability_text
            ]

            if detected:
                risky.append(
                    {
                        "path": item["path"],
                        "capabilities": item["capabilities"],
                        "risky_capabilities": sorted(
                            detected
                        ),
                    }
                )

        return risky