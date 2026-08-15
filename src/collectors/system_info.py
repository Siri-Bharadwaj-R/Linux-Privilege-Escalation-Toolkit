import os
import platform
import pwd
import grp


class SystemInfoCollector:
    """
    Collects basic system and user information required
    for privilege escalation analysis.
    """

    def collect(self) -> dict:
        current_user = pwd.getpwuid(os.getuid()).pw_name
        uid = os.getuid()
        gid = os.getgid()

        groups = [
            group.gr_name
            for group in grp.getgrall()
            if current_user in group.gr_mem or group.gr_gid == gid
        ]

        os_info = self._get_os_info()

        return {
            "hostname": platform.node(),
            "current_user": current_user,
            "uid": uid,
            "gid": gid,
            "groups": sorted(set(groups)),
            "is_root": uid == 0,
            "privilege_level": "ROOT" if uid == 0 else "STANDARD USER",
            "os": os_info,
            "kernel": platform.release(),
            "architecture": platform.machine(),
        }

    def _get_os_info(self) -> dict:
        """
        Reads operating system information from /etc/os-release.
        """

        os_info = {}

        try:
            with open("/etc/os-release", "r", encoding="utf-8") as file:
                for line in file:
                    line = line.strip()

                    if "=" in line:
                        key, value = line.split("=", 1)
                        os_info[key] = value.strip('"')

        except FileNotFoundError:
            os_info["error"] = "/etc/os-release not found"

        return os_info