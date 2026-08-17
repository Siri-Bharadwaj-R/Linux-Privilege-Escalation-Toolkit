from src.analysis.findings import Finding


class AnalysisEngine:
    """
    Converts raw collector output into structured
    Linux privilege escalation security findings.
    """

    def analyze(self, scan_results: dict) -> list:
        """
        Analyze results from all collectors.
        """

        findings = []

        findings.extend(
            self._analyze_suid_sgid(
                scan_results.get("suid_sgid", {})
            )
        )

        findings.extend(
            self._analyze_permissions(
                scan_results.get("permissions", {})
            )
        )

        findings.extend(
            self._analyze_sudo(
                scan_results.get("sudo", {})
            )
        )

        findings.extend(
            self._analyze_cron(
                scan_results.get("cron", {})
            )
        )

        findings.extend(
            self._analyze_services(
                scan_results.get("services", {})
            )
        )

        findings.extend(
            self._analyze_capabilities(
                scan_results.get("capabilities", {})
            )
        )

        findings.extend(
            self._analyze_kernel(
                scan_results.get("kernel", {})
            )
        )

        return [
            finding.to_dict()
            for finding in findings
        ]

    def _analyze_suid_sgid(self, data: dict) -> list:
        findings = []

        for binary in data.get("risky_binaries", []):

            target = (
                binary.get("path", "Unknown")
                if isinstance(binary, dict)
                else binary
            )

            findings.append(
                Finding(
                    title="Potentially Risky SUID/SGID Binary",
                    severity="High",
                    target=target,
                    description=(
                        "A binary with elevated SUID or SGID "
                        "permissions matches a predefined "
                        "high-risk pattern."
                    ),
                    mitigation=(
                        "Verify whether the elevated permission "
                        "is required and remove unnecessary "
                        "SUID/SGID bits."
                    ),
                    category="SUID/SGID",
                )
            )

        return findings

    def _analyze_permissions(self, data: dict) -> list:
        findings = []

        for path in data.get(
            "world_writable_files",
            []
        ):
            findings.append(
                Finding(
                    title="World-Writable File Detected",
                    severity="High",
                    target=path,
                    description=(
                        "The file is writable by any local user. "
                        "This may become a privilege escalation "
                        "risk if used by a privileged process."
                    ),
                    mitigation=(
                        "Remove unnecessary world-write "
                        "permissions and restrict access."
                    ),
                    category="Permissions",
                )
            )

        for path in data.get(
            "world_writable_directories",
            []
        ):
            findings.append(
                Finding(
                    title="World-Writable Directory Detected",
                    severity="Medium",
                    target=path,
                    description=(
                        "The directory is writable by all users. "
                        "Review whether this is intentional and "
                        "whether privileged processes use files "
                        "inside it."
                    ),
                    mitigation=(
                        "Restrict directory write permissions "
                        "where they are not required."
                    ),
                    category="Permissions",
                )
            )

        for path, details in data.get(
            "sensitive_file_permissions",
            {}
        ).items():

            if not details.get("exists"):
                continue

            if details.get("world_writable"):
                findings.append(
                    Finding(
                        title=(
                            "Sensitive System File Is "
                            "World-Writable"
                        ),
                        severity="Critical",
                        target=path,
                        description=(
                            "A sensitive system file is writable "
                            "by any user, creating a serious "
                            "privilege escalation risk."
                        ),
                        mitigation=(
                            "Immediately restore secure ownership "
                            "and permissions."
                        ),
                        category="Permissions",
                    )
                )

            elif details.get("group_writable"):
                findings.append(
                    Finding(
                        title=(
                            "Sensitive System File Is "
                            "Group-Writable"
                        ),
                        severity="High",
                        target=path,
                        description=(
                            "A sensitive system file can be "
                            "modified by members of its group. "
                            "This should be reviewed to ensure "
                            "only trusted administrators have "
                            "write access."
                        ),
                        mitigation=(
                            "Restrict group write permissions "
                            "and verify file ownership."
                        ),
                        category="Permissions",
                    )
                )

            if (
                path == "/etc/shadow"
                and details.get("world_readable")
            ):
                findings.append(
                    Finding(
                        title="Shadow File Is World-Readable",
                        severity="Critical",
                        target=path,
                        description=(
                            "The system password hash file is "
                            "readable by all users, exposing "
                            "credential hashes."
                        ),
                        mitigation=(
                            "Immediately restrict permissions so "
                            "only root and the appropriate system "
                            "group can access the file."
                        ),
                        category="Permissions",
                    )
                )

            if (
                path == "/etc/sudoers"
                and details.get("world_readable")
            ):
                findings.append(
                    Finding(
                        title="Sudoers File Is World-Readable",
                        severity="High",
                        target=path,
                        description=(
                            "The sudo configuration is readable "
                            "by all users. Review permissions and "
                            "ensure the file is protected."
                        ),
                        mitigation=(
                            "Restrict sudoers file permissions "
                            "to authorized administrators."
                        ),
                        category="Permissions",
                    )
                )

        for home in data.get(
            "home_permissions",
            []
        ):

            if home.get("world_writable"):
                findings.append(
                    Finding(
                        title=(
                            "World-Writable Home Directory "
                            "Detected"
                        ),
                        severity="High",
                        target=home.get("path", "Unknown"),
                        description=(
                            "A user's home directory is writable "
                            "by all local users, which may allow "
                            "unauthorized modification of "
                            "configuration files or executables."
                        ),
                        mitigation=(
                            "Restrict write permissions so only "
                            "the directory owner and authorized "
                            "administrators can modify it."
                        ),
                        category="Permissions",
                    )
                )

        return findings

    def _analyze_sudo(self, data: dict) -> list:
        findings = []

        if data.get("all_access"):
            findings.append(
                Finding(
                    title="Unrestricted Sudo Access",
                    severity="Critical",
                    target="sudo configuration",
                    description=(
                        "The current user appears to have "
                        "unrestricted sudo privileges."
                    ),
                    mitigation=(
                        "Apply least-privilege sudo rules and "
                        "allow only required commands."
                    ),
                    category="Sudo",
                )
            )

        for rule in data.get("nopasswd_rules", []):
            findings.append(
                Finding(
                    title="NOPASSWD Sudo Rule Detected",
                    severity="High",
                    target=rule,
                    description=(
                        "A sudo rule may allow command execution "
                        "without password authentication."
                    ),
                    mitigation=(
                        "Remove unnecessary NOPASSWD entries "
                        "and restrict allowed commands."
                    ),
                    category="Sudo",
                )
            )

        for command in data.get(
            "risky_commands",
            []
        ):
            findings.append(
                Finding(
                    title="Potentially Risky Sudo Command",
                    severity="High",
                    target=command,
                    description=(
                        "A command capable of broad system access "
                        "or command execution appears in the "
                        "sudo configuration."
                    ),
                    mitigation=(
                        "Restrict the command, use absolute "
                        "paths, and review whether sudo access "
                        "is necessary."
                    ),
                    category="Sudo",
                )
            )

        return findings

    def _analyze_cron(self, data: dict) -> list:
        findings = []

        for job in data.get("writable_jobs", []):
            findings.append(
                Finding(
                    title="Writable Scheduled Job",
                    severity="High",
                    target=job.get("path", "Unknown"),
                    description=(
                        "A system scheduled job is writable by "
                        "group members or other users."
                    ),
                    mitigation=(
                        "Ensure scheduled jobs are owned by root "
                        "and are not writable by untrusted users."
                    ),
                    category="Cron",
                )
            )

        return findings

    def _analyze_services(self, data: dict) -> list:
        findings = []

        for item in data.get(
            "writable_service_files",
            []
        ):
            findings.append(
                Finding(
                    title="Writable File Used by Service",
                    severity="Critical",
                    target=item.get("path", "Unknown"),
                    description=(
                        "A system service references a file that "
                        "is writable by non-privileged users."
                    ),
                    mitigation=(
                        "Restrict ownership and write access to "
                        "files executed or loaded by privileged "
                        "services."
                    ),
                    category="Services",
                )
            )

        for item in data.get(
            "insecure_path_services",
            []
        ):
            findings.append(
                Finding(
                    title="Potentially Insecure Service PATH",
                    severity="High",
                    target=item.get("service", "Unknown"),
                    description=(
                        "The service environment contains a PATH "
                        "configuration with potentially unsafe "
                        "locations."
                    ),
                    mitigation=(
                        "Use absolute executable paths and remove "
                        "untrusted directories from PATH."
                    ),
                    category="Services",
                )
            )

        return findings

    def _analyze_capabilities(self, data: dict) -> list:
        findings = []

        for item in data.get(
            "risky_capabilities",
            []
        ):
            findings.append(
                Finding(
                    title="High-Risk Linux Capability Detected",
                    severity="High",
                    target=item.get("path", "Unknown"),
                    description=(
                        "The file has Linux capabilities that may "
                        "allow privileged operations."
                    ),
                    mitigation=(
                        "Verify that the capability assignment is "
                        "necessary and remove unnecessary "
                        "capabilities."
                    ),
                    category="Capabilities",
                )
            )

        return findings

    def _analyze_kernel(self, data: dict) -> list:
        findings = []

        for match in data.get(
            "kernel_matches",
            []
        ):
            findings.append(
                Finding(
                    title=match.get(
                        "name",
                        "Kernel Vulnerability",
                    ),
                    severity=match.get(
                        "severity",
                        "Medium",
                    ),
                    target=match.get(
                        "cve",
                        "Unknown",
                    ),
                    description=match.get(
                        "description",
                        "Potential kernel security issue detected.",
                    ),
                    mitigation=match.get(
                        "mitigation",
                        "Update the system using vendor-provided "
                        "security patches.",
                    ),
                    category="Kernel",
                )
            )

        if data.get("potentially_outdated"):
            findings.append(
                Finding(
                    title="Potentially Outdated Kernel",
                    severity="Medium",
                    target=data.get(
                        "kernel_release",
                        "Unknown",
                    ),
                    description=(
                        "The detected kernel version may be older "
                        "than currently supported versions."
                    ),
                    mitigation=(
                        "Update the kernel using the official "
                        "Linux distribution update mechanism."
                    ),
                    category="Kernel",
                )
            )

        return findings