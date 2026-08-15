import configparser
import os
import stat
import subprocess


class ServiceCollector:
    """
    Collects and analyzes systemd service configurations.

    The collector checks for:
    - Available systemd services
    - Services configured to run as root
    - Executable paths used by services
    - Potentially writable service executables
    - PATH-related configuration risks
    """

    def collect(self) -> dict:
        services = self._get_services()

        root_services = []
        writable_service_files = []
        insecure_path_services = []

        for service in services:
            analysis = self._analyze_service(service)

            if analysis is None:
                continue

            if analysis["runs_as_root"]:
                root_services.append(analysis)

            if analysis["writable_files"]:
                writable_service_files.extend(
                    analysis["writable_files"]
                )

            if analysis["insecure_path"]:
                insecure_path_services.append(
                    {
                        "service": service,
                        "service_file": analysis["service_file"],
                        "environment": analysis["environment"],
                    }
                )

        return {
            "services": services,
            "service_count": len(services),
            "root_services": root_services,
            "writable_service_files": writable_service_files,
            "insecure_path_services": insecure_path_services,
        }

    def _get_services(self) -> list:
        """
        Get installed systemd service units.
        """

        try:
            process = subprocess.run(
                [
                    "systemctl",
                    "list-unit-files",
                    "--type=service",
                    "--no-legend",
                    "--no-pager",
                ],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )

            services = []

            for line in process.stdout.splitlines():
                parts = line.split()

                if parts and parts[0].endswith(".service"):
                    services.append(parts[0])

            return sorted(set(services))

        except (
            FileNotFoundError,
            subprocess.TimeoutExpired,
        ):
            return []

    def _analyze_service(self, service_name: str) -> dict | None:
        """
        Inspect one service using systemctl show.
        """

        try:
            process = subprocess.run(
                [
                    "systemctl",
                    "show",
                    service_name,
                    "--property=FragmentPath",
                    "--property=User",
                    "--property=ExecStart",
                    "--property=Environment",
                    "--no-pager",
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

        except (
            FileNotFoundError,
            subprocess.TimeoutExpired,
        ):
            return None

        if process.returncode != 0:
            return None

        properties = {}

        for line in process.stdout.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                properties[key] = value.strip()

        service_file = properties.get("FragmentPath", "")
        user = properties.get("User", "")
        exec_start = properties.get("ExecStart", "")
        environment = properties.get("Environment", "")

        # In systemd, an empty User= generally means root.
        runs_as_root = user == ""

        executable_paths = self._extract_executable_paths(
            exec_start
        )

        writable_files = []

        for path in executable_paths:
            if self._is_writable(path):
                writable_files.append(
                    {
                        "service": service_name,
                        "path": path,
                    }
                )

        insecure_path = self._has_insecure_path(
            environment
        )

        return {
            "service": service_name,
            "service_file": service_file,
            "user": user if user else "root",
            "runs_as_root": runs_as_root,
            "exec_start": exec_start,
            "environment": environment,
            "executable_paths": executable_paths,
            "writable_files": writable_files,
            "insecure_path": insecure_path,
        }

    def _extract_executable_paths(
        self,
        exec_start: str,
    ) -> list:
        """
        Extract absolute executable paths from ExecStart data.
        """

        paths = []

        for token in exec_start.replace(
            "{",
            " "
        ).replace(
            "}",
            " "
        ).replace(
            ";",
            " "
        ).split():

            if token.startswith("/"):
                cleaned = token.strip()

                if os.path.exists(cleaned):
                    paths.append(cleaned)

        return sorted(set(paths))

    def _is_writable(self, path: str) -> bool:
        """
        Check whether a path is writable by group or others.
        """

        try:
            file_stat = os.stat(path)

            return bool(
                file_stat.st_mode & stat.S_IWGRP
                or file_stat.st_mode & stat.S_IWOTH
            )

        except (
            FileNotFoundError,
            PermissionError,
            OSError,
        ):
            return False

    def _has_insecure_path(
        self,
        environment: str,
    ) -> bool:
        """
        Detect potentially unsafe PATH definitions.

        Flags PATH values containing:
        - .
        - Empty path components
        - /tmp
        - /var/tmp
        """

        if "PATH=" not in environment:
            return False

        path_value = environment.split(
            "PATH=",
            1,
        )[1]

        path_value = path_value.strip(
            '"'
        )

        components = path_value.split(":")

        risky_components = {
            ".",
            "/tmp",
            "/var/tmp",
            "",
        }

        return any(
            component in risky_components
            for component in components
        )