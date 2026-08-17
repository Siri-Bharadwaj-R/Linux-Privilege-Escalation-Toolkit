import json
from datetime import datetime
from pathlib import Path


class JsonReporter:
    """Generates a JSON report containing security findings."""

    def generate(self, findings):
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = reports_dir / f"security_report_{timestamp}.json"

        report_data = {
            "generated_at": datetime.now().isoformat(),
            "total_findings": len(findings),
            "findings": findings,
        }

        with open(report_path, "w", encoding="utf-8") as file:
            json.dump(
                report_data,
                file,
                indent=4,
            )

        print(f"[+] JSON report saved to: {report_path}")

        return report_path