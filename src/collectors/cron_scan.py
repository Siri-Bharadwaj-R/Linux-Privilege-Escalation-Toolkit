import os
import stat
import subprocess


class CronCollector:
    """
    Collects and analyzes user and system cron jobs.

    The collector checks:
    - Current user's crontab
    - /etc/crontab
    - /etc/cron.d
    - /etc/cron.hourly
    - /etc/cron.daily
    - /etc/cron.weekly
    - /etc/cron.monthly
    - /etc/cron.yearly
    """

    def __init__(self):
        self.cron_directories = [
            "/etc/cron.d",
            "/etc/cron.hourly",
            "/etc/cron.daily",
            "/etc/cron.weekly",
            "/etc/cron.monthly",
            "/etc/cron.yearly",
        ]

    def collect(self) -> dict:
        """
        Collect cron jobs and permission information.
        """

        user_crontab = self._get_user_crontab()
        system_crontab = self._read_file("/etc/crontab")

        cron_directories = self._scan_cron_directories()

        root_executed_jobs = self._find_root_jobs(
            system_crontab,
            cron_directories,
        )

        writable_jobs = self._find_writable_jobs(
            cron_directories
        )

        return {
            "user_crontab": user_crontab,
            "system_crontab": system_crontab,
            "cron_directories": cron_directories,
            "root_executed_jobs": root_executed_jobs,
            "writable_jobs": writable_jobs,
        }

    def _get_user_crontab(self) -> dict:
        """
        Retrieve the current user's crontab without
        requiring interactive input.
        """

        try:
            process = subprocess.run(
                ["crontab", "-l"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            output = process.stdout.strip()
            error = process.stderr.strip()

            if process.returncode != 0:
                return {
                    "exists": False,
                    "entries": [],
                    "message": error or "No crontab found",
                }

            entries = [
                line.strip()
                for line in output.splitlines()
                if line.strip()
                and not line.strip().startswith("#")
            ]

            return {
                "exists": True,
                "entries": entries,
                "message": None,
            }

        except FileNotFoundError:
            return {
                "exists": False,
                "entries": [],
                "message": "crontab command not found",
            }

        except subprocess.TimeoutExpired:
            return {
                "exists": False,
                "entries": [],
                "message": "crontab command timed out",
            }

    def _read_file(self, file_path: str) -> dict:
        """
        Read a cron configuration file.
        """

        try:
            with open(
                file_path,
                "r",
                encoding="utf-8",
                errors="replace",
            ) as file:
                lines = [
                    line.strip()
                    for line in file
                    if line.strip()
                    and not line.strip().startswith("#")
                ]

            return {
                "exists": True,
                "entries": lines,
            }

        except FileNotFoundError:
            return {
                "exists": False,
                "entries": [],
            }

        except PermissionError:
            return {
                "exists": True,
                "entries": [],
                "error": "Permission denied",
            }

    def _scan_cron_directories(self) -> dict:
        """
        Enumerate files inside all system cron directories
        and record their permissions.
        """

        results = {}

        for directory in self.cron_directories:
            jobs = []

            if not os.path.exists(directory):
                results[directory] = {
                    "exists": False,
                    "jobs": [],
                }
                continue

            try:
                for entry in os.scandir(directory):
                    if not entry.is_file(
                        follow_symlinks=False
                    ):
                        continue

                    try:
                        file_stat = entry.stat(
                            follow_symlinks=False
                        )

                        jobs.append(
                            {
                                "path": entry.path,
                                "mode": stat.filemode(
                                    file_stat.st_mode
                                ),
                                "uid": file_stat.st_uid,
                                "gid": file_stat.st_gid,
                                "world_writable": bool(
                                    file_stat.st_mode
                                    & stat.S_IWOTH
                                ),
                                "group_writable": bool(
                                    file_stat.st_mode
                                    & stat.S_IWGRP
                                ),
                            }
                        )

                    except (
                        PermissionError,
                        FileNotFoundError,
                        OSError,
                    ):
                        continue

                results[directory] = {
                    "exists": True,
                    "jobs": sorted(
                        jobs,
                        key=lambda job: job["path"],
                    ),
                }

            except PermissionError:
                results[directory] = {
                    "exists": True,
                    "jobs": [],
                    "error": "Permission denied",
                }

        return results

    def _find_root_jobs(
        self,
        system_crontab: dict,
        cron_directories: dict,
    ) -> list:
        """
        Identify jobs that are explicitly configured to run
        as root, plus scripts located in system cron folders.

        Files in /etc/cron.hourly, daily, weekly, monthly,
        and yearly are system-level scheduled jobs and are
        recorded separately for reporting.
        """

        root_jobs = []

        for entry in system_crontab.get("entries", []):
            parts = entry.split()

            # System crontab format:
            # minute hour day month weekday user command
            if len(parts) >= 7 and parts[5] == "root":
                root_jobs.append(
                    {
                        "source": "/etc/crontab",
                        "entry": entry,
                        "user": "root",
                    }
                )

        for directory, data in cron_directories.items():
            for job in data.get("jobs", []):
                root_jobs.append(
                    {
                        "source": directory,
                        "entry": job["path"],
                        "user": "system",
                    }
                )

        return root_jobs

    def _find_writable_jobs(
        self,
        cron_directories: dict,
    ) -> list:
        """
        Identify cron job files writable by group or others.
        """

        writable_jobs = []

        for directory, data in cron_directories.items():
            for job in data.get("jobs", []):
                if (
                    job["world_writable"]
                    or job["group_writable"]
                ):
                    writable_jobs.append(
                        {
                            "source": directory,
                            "path": job["path"],
                            "mode": job["mode"],
                            "world_writable": (
                                job["world_writable"]
                            ),
                            "group_writable": (
                                job["group_writable"]
                            ),
                        }
                    )

        return writable_jobs