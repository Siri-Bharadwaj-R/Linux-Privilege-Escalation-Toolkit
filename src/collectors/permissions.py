import os
import stat


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
                    directory_path = os.path.join(root, directory)

                    if self._is_world_writable(directory_path):
                        world_writable_directories.append(directory_path)

                # Check files
                for filename in files:
                    file_path = os.path.join(root, filename)

                    if self._is_world_writable(file_path):
                        world_writable_files.append(file_path)

        sensitive_file_permissions = self._check_sensitive_files()

        home_permissions = self._check_home_directories()

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
            "sensitive_file_permissions": sensitive_file_permissions,
            "home_permissions": home_permissions,
        }

    def _is_world_writable(self, path: str) -> bool:
        """
        Check whether a file or directory is writable by others.
        """

        try:
            mode = os.stat(path).st_mode
            return bool(mode & stat.S_IWOTH)

        except (PermissionError, FileNotFoundError, OSError):
            return False

    def _check_sensitive_files(self) -> dict:
        """
        Collect permission information for sensitive system files.
        """

        results = {}

        for file_path in self.sensitive_files:
            try:
                file_stat = os.stat(file_path)

                results[file_path] = {
                    "exists": True,
                    "mode": stat.filemode(file_stat.st_mode),
                    "uid": file_stat.st_uid,
                    "gid": file_stat.st_gid,
                    "world_writable": bool(
                        file_stat.st_mode & stat.S_IWOTH
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

        return results

    def _check_home_directories(self) -> list:
        """
        Collect permission information for directories inside /home.
        """

        home_permissions = []

        if not os.path.exists("/home"):
            return home_permissions

        try:
            for entry in os.scandir("/home"):
                if not entry.is_dir(follow_symlinks=False):
                    continue

                try:
                    directory_stat = entry.stat(
                        follow_symlinks=False
                    )

                    home_permissions.append(
                        {
                            "path": entry.path,
                            "mode": stat.filemode(
                                directory_stat.st_mode
                            ),
                            "world_writable": bool(
                                directory_stat.st_mode
                                & stat.S_IWOTH
                            ),
                        }
                    )

                except (PermissionError, OSError):
                    continue

        except PermissionError:
            pass

        return sorted(
            home_permissions,
            key=lambda item: item["path"]
        )