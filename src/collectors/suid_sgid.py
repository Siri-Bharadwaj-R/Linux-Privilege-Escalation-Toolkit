import os
from src.analysis.pattern_matcher import PatternMatcher

class SuidSgidCollector:
    """
    Scans the filesystem for files with SUID and SGID permission bits.
    """

    def __init__(self, search_paths=None):
        self.search_paths = search_paths or [
            "/usr/bin",
            "/usr/sbin",
            "/bin",
            "/sbin",
        ]
        self.pattern_matcher = PatternMatcher()
    
    def collect(self) -> dict:
        """
        Collect SUID and SGID binaries from configured search paths.
        """

        suid_files = []
        sgid_files = []

        for search_path in self.search_paths:
            if not os.path.exists(search_path):
                continue

            for root, _, files in os.walk(search_path):
                for filename in files:
                    file_path = os.path.join(root, filename)

                    try:
                        mode = os.stat(file_path).st_mode

                        if mode & 0o4000:
                            suid_files.append(file_path)

                        if mode & 0o2000:
                            sgid_files.append(file_path)

                    except (PermissionError, FileNotFoundError):
                        continue
       
        risky_binaries = []

        for file_path in sorted(set(suid_files + sgid_files)):
            risk = self.pattern_matcher.check_binary(file_path)

            if risk:
                risky_binaries.append(
                    {
                        "path": file_path,
                        "binary": os.path.basename(file_path),
                        "risk": risk,
                    }
                )
                        
        return {
            "suid_files": sorted(set(suid_files)),
            "sgid_files": sorted(set(sgid_files)),
            "suid_count": len(set(suid_files)),
            "sgid_count": len(set(sgid_files)),
            "risky_binaries": risky_binaries,
        }