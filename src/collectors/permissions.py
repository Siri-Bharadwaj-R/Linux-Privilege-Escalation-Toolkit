import os
import stat
import pwd
import grp


class PermissionsCollector:
    """
    Scans for potentially weak file and directory permissions
    relevant to Linux privilege escalation.
    """

    def __init__(self, search_paths=None):
        self.search_paths = search_paths or [
            "/tmp",
            "/var/tmp",
            "/home",
            "/etc",
        ]

        self.sensitive_files = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/group",
            "/etc/gshadow",
            "/etc/sudoers",
        ]

    def collect(self) -> dict:
        """
        Collect permission-related security information.
        """

        world_writable_files = []
        world_writable_directories = []

        for search_path in self.search_paths:
            if not os.path.exists(search_path):
                continue

            for root, directories, files in os.walk(
                search_path,
                onerror=lambda error: None,
            ):
                # Check directories
                for directory in directories:
                    directory_path = os.path.join(
                        root,
                        directory,
                    )

                    if self._is_world_writable(
                        directory_path
                    ):
                        world_writable_directories.append(
                            directory_path
                        )

                # Check files
                for filename in files:
                    file_path = os.path.join(
                        root,
                        filename,
                    )

                    if self._is_world_writable(
                        file_path
                    ):
                        world_writable_files.append(
                            file_path
                        )

        sensitive_file_permissions = (
            self._check_sensitive_files()
        )

        home_permissions = (
            self._check_home_directories()
        )

        return {
            "world_writable_files": sorted(
                set(world_writable_files)
            ),
            "world_writable_directories": sorted(
                set(world_writable_directories)
            ),
            "world_writable_file_count": len(
                set(world_writable_files)
            ),
            "world_writable_directory_count": len(
                set(world_writable_directories)
            ),
            "sensitive_file_permissions":
                sensitive_file_permissions,
            "home_permissions": home_permissions,
        }

    def _is_world_writable(self, path: str) -> bool:
        """
        Check whether a file or directory is writable by others.
        """

        try:
            mode = os.stat(path).st_mode

            return bool(
                mode & stat.S_IWOTH
            )

        except (
            PermissionError,
            FileNotFoundError,
            OSError,
        ):
            return False

    def _check_sensitive_files(self) -> dict:
        """
        Collect detailed permission information for sensitive
        system files.
        """

        results = {}

        for file_path in self.sensitive_files:
            try:
                file_stat = os.stat(file_path)

                mode = file_stat.st_mode

                results[file_path] = {
                    "exists": True,
                    "mode": stat.filemode(mode),
                    "uid": file_stat.st_uid,
                    "gid": file_stat.st_gid,
                    "owner": self._get_username(
                        file_stat.st_uid
                    ),
                    "group": self._get_groupname(
                        file_stat.st_gid
                    ),
                    "owner_writable": bool(
                        mode & stat.S_IWUSR
                    ),
                    "group_writable": bool(
                        mode & stat.S_IWGRP
                    ),
                    "world_writable": bool(
                        mode & stat.S_IWOTH
                    ),
                    "world_readable": bool(
                        mode & stat.S_IROTH
                    ),
                }

            except FileNotFoundError:
                results[file_path] = {
                    "exists": False
                }

            except PermissionError:
                results[file_path] = {
                    "exists": True,
                    "error": "Permission denied"
                }

            except OSError as error:
                results[file_path] = {
                    "exists": True,
                    "error": str(error)
                }

        return results

    def _get_username(self, uid: int) -> str:
        """
        Convert a UID into a username.
        """

        try:
            return pwd.getpwuid(uid).pw_name

        except KeyError:
            return str(uid)

    def _get_groupname(self, gid: int) -> str:
        """
        Convert a GID into a group name.
        """

        try:
            return grp.getgrgid(gid).gr_name

        except KeyError:
            return str(gid)

    def _check_home_directories(self) -> list:
        """
        Collect permission information for directories inside
        /home.
        """

        home_permissions = []

        if not os.path.exists("/home"):
            return home_permissions

        try:
            for entry in os.scandir("/home"):
                if not entry.is_dir(
                    follow_symlinks=False
                ):
                    continue

                try:
                    directory_stat = entry.stat(
                        follow_symlinks=False
                    )

                    mode = directory_stat.st_mode

                    home_permissions.append(
                        {
                            "path": entry.path,
                            "mode": stat.filemode(
                                mode
                            ),
                            "owner": self._get_username(
                                directory_stat.st_uid
                            ),
                            "group": self._get_groupname(
                                directory_stat.st_gid
                            ),
                            "group_writable": bool(
                                mode & stat.S_IWGRP
                            ),
                            "world_writable": bool(
                                mode & stat.S_IWOTH
                            ),
                            "world_readable": bool(
                                mode & stat.S_IROTH
                            ),
                        }
                    )

                except (
                    PermissionError,
                    OSError,
                ):
                    continue

        except PermissionError:
            pass

        return sorted(
            home_permissions,
            key=lambda item: item["path"],
        )