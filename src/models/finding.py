from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    """
    Represents a single security finding discovered during a scan.
    """

    title: str
    category: str
    severity: str
    evidence: str
    description: str
    exploitation_possible: bool
    mitigation: str

    location: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """
        Convert the finding into a dictionary for reporting.
        """

        return {
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "evidence": self.evidence,
            "description": self.description,
            "exploitation_possible": self.exploitation_possible,
            "mitigation": self.mitigation,
            "location": self.location,
            "metadata": self.metadata,
        }