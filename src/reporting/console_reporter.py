class ConsoleReporter:
    """Displays security findings in the terminal."""

    def generate(self, findings):
        print("=" * 70)
        print("                    SECURITY FINDINGS")
        print("=" * 70)

        if not findings:
            print("\nNo security findings detected.")
            return

        severity_order = ["Critical", "High", "Medium", "Low"]

        for severity in severity_order:
            severity_findings = [
                finding
                for finding in findings
                if finding.get("severity") == severity
            ]

            if not severity_findings:
                continue

            print(f"\n[{severity.upper()}]")

            for index, finding in enumerate(
                severity_findings,
                start=1,
            ):
                print(f"\n{index}. {finding.get('title', 'Unknown')}")

                print(
                    f"   Severity: "
                    f"{finding.get('severity', 'Unknown')}"
                )

                print(
                    f"   Target: "
                    f"{finding.get('target', 'Unknown')}"
                )

                print(
                    f"   Description: "
                    f"{finding.get('description', 'No description')}"
                )

                mitigation = finding.get("mitigation")

                if mitigation:
                    print(
                        f"   Recommendation: "
                        f"{mitigation}"
                    )

        print("\n" + "=" * 70)