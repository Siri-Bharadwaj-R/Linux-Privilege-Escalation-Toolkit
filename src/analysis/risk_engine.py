class RiskEngine:
    """
    Calculates severity statistics, an overall risk score,
    and an overall risk level from security findings.
    """

    SEVERITY_WEIGHTS = {
        "Critical": 25,
        "High": 15,
        "Medium": 8,
        "Low": 3,
        "Info": 0,
    }

    def calculate(self, findings: list) -> dict:
        """
        Calculate risk statistics from a list of findings.
        """

        severity_counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Info": 0,
        }

        total_score = 0

        for finding in findings:
            severity = finding.get(
                "severity",
                "Info",
            )

            if severity in severity_counts:
                severity_counts[severity] += 1

            total_score += self.SEVERITY_WEIGHTS.get(
                severity,
                0,
            )

        risk_score = min(total_score, 100)

        risk_level = self._determine_risk_level(
            risk_score
        )

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "severity_counts": severity_counts,
            "total_findings": len(findings),
        }

    def _determine_risk_level(
        self,
        risk_score: int,
    ) -> str:
        """
        Convert a numerical risk score into a risk level.
        """

        if risk_score >= 75:
            return "Critical"

        if risk_score >= 50:
            return "High"

        if risk_score >= 25:
            return "Medium"

        if risk_score > 0:
            return "Low"

        return "Info"