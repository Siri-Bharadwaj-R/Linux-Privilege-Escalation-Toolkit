from datetime import datetime
from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Spacer,
    Paragraph,
)


class PdfReporter:
    """Generates a PDF report containing security findings."""

    def generate(self, findings):
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = reports_dir / f"security_report_{timestamp}.pdf"

        document = SimpleDocTemplate(
            str(report_path),
            pagesize=A4,
            rightMargin=0.7 * inch,
            leftMargin=0.7 * inch,
            topMargin=0.7 * inch,
            bottomMargin=0.7 * inch,
        )

        styles = getSampleStyleSheet()
        story = []

        story.append(
            Paragraph(
                "Linux Privilege Escalation Toolkit",
                styles["Title"],
            )
        )

        story.append(
            Paragraph(
                "Security Assessment Report",
                styles["Heading2"],
            )
        )

        story.append(Spacer(1, 20))

        story.append(
            Paragraph(
                f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                styles["Normal"],
            )
        )

        story.append(
            Paragraph(
                f"Total Findings: {len(findings)}",
                styles["Normal"],
            )
        )

        story.append(Spacer(1, 20))

        if not findings:
            story.append(
                Paragraph(
                    "No security findings were detected.",
                    styles["Normal"],
                )
            )
        else:
            for index, finding in enumerate(findings, start=1):
                title = finding.get("title", "Unknown Finding")
                severity = finding.get("severity", "Unknown")
                target = finding.get("target", "Unknown")
                description = finding.get(
                    "description",
                    "No description available.",
                )
                mitigation = finding.get("mitigation", "")

                story.append(
                    Paragraph(
                        f"{index}. {title}",
                        styles["Heading3"],
                    )
                )

                story.append(
                    Paragraph(
                        f"<b>Severity:</b> {severity}",
                        styles["Normal"],
                    )
                )

                story.append(
                    Paragraph(
                        f"<b>Target:</b> {target}",
                        styles["Normal"],
                    )
                )

                story.append(
                    Paragraph(
                        f"<b>Description:</b> {description}",
                        styles["Normal"],
                    )
                )

                if mitigation:
                    story.append(
                        Paragraph(
                            f"<b>Recommendation:</b> {mitigation}",
                            styles["Normal"],
                        )
                    )

                story.append(Spacer(1, 14))

        document.build(story)

        print(f"[+] PDF report saved to: {report_path}")

        return report_path