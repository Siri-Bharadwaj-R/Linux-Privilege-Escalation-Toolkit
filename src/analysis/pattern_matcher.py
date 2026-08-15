import json
import os
from pathlib import Path


class PatternMatcher:
    """
    Matches discovered binaries against predefined
    privilege escalation risk patterns.
    """

    def __init__(self):
        project_root = Path(__file__).resolve().parents[2]
        data_file = project_root / "data" / "risky_binaries.json"

        with open(data_file, "r", encoding="utf-8") as file:
            self.patterns = json.load(file)

    def check_binary(self, file_path: str) -> str | None:
        """
        Return the risk level of a binary if it exists
        in the predefined risk database.
        """

        binary_name = os.path.basename(file_path)

        if binary_name in self.patterns["high_risk"]:
            return "HIGH"

        if binary_name in self.patterns["medium_risk"]:
            return "MEDIUM"

        return None