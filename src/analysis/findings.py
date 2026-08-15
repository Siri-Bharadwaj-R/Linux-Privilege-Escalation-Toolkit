class Finding:
    """
    Represents a single security finding discovered
    during the privilege escalation audit.
    """

    VALID_SEVERITIES = [
        "Critical",
        "High",
        "Medium",
        "Low",
        "Info",
    ]

    def __init__(
        self,
        title: str,
        severity: str,
        target: str,
        description: str,
        mitigation: str,
        category: str,
    ):
        if severity not in self.VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity: {severity}"
            )

        self.title = title
        self.severity = severity
        self.target = target
        self.description = description
        self.mitigation = mitigation
        self.category = category

    def to_dict(self) -> dict:
        """
        Convert the finding into a dictionary so it can
        later be used by the CLI and report generator.
        """

        return {
            "title": self.title,
            "severity": self.severity,
            "target": self.target,
            "description": self.description,
            "mitigation": self.mitigation,
            "category": self.category,
        }