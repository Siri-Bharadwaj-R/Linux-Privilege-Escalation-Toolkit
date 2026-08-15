import os
import subprocess


class SudoCollector:
    """
    Collects and analyzes sudo privileges available
    to the current user.
    """

    def collect(self) -> dict:
        """
        Run sudo -l and analyze the returned sudo rules.
        """

        result = self._run_sudo_list()

        output = result["output"]

        return {
            "sudo_available": result["success"],
            "raw_output": output,
            "nopasswd_rules": self._find_nopasswd_rules(output),
            "all_access": self._detect_all_access(output),
            "risky_commands": self._find_risky_commands(output),
        }

    def _run_sudo_list(self) -> dict:
        """
        Execute sudo -n -l.

        -n prevents the scanner from hanging while waiting
        for a password.
        """

        try:
            process = subprocess.run(
                ["sudo", "-n", "-l"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            output = (
                process.stdout.strip()
                if process.stdout
                else process.stderr.strip()
            )

            return {
                "success": process.returncode == 0,
                "output": output,
            }

        except FileNotFoundError:
            return {
                "success": False,
                "output": "sudo command not found",
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "output": "sudo privilege check timed out",
            }

    def _find_nopasswd_rules(self, output: str) -> list:
        """Find sudo rules containing NOPASSWD."""

        return [
            line.strip()
            for line in output.splitlines()
            if "NOPASSWD" in line.upper()
        ]

    def _detect_all_access(self, output: str) -> bool:
        """
        Detect unrestricted sudo access such as:
        (ALL : ALL) ALL
        """

        normalized_output = " ".join(output.split())

        return "(ALL : ALL) ALL" in normalized_output

    def _find_risky_commands(self, output: str) -> list:
        """
        Identify potentially risky commands allowed through sudo.
        """

        risky_commands = [
            "awk",
            "bash",
            "busybox",
            "cp",
            "env",
            "find",
            "less",
            "more",
            "nano",
            "nmap",
            "perl",
            "python",
            "python3",
            "ruby",
            "sh",
            "tar",
            "tee",
            "vi",
            "vim",
        ]

        detected = []

        output_lower = output.lower()

        for command in risky_commands:
            if command in output_lower:
                detected.append(command)

        return sorted(set(detected))