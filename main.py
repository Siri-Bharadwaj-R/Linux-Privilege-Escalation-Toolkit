from src.collectors.system_info import SystemInfoCollector
from src.collectors.suid_sgid import SuidSgidCollector
from src.collectors.permissions import PermissionsCollector
from src.collectors.cron_scan import CronCollector
from src.collectors.service_scan import ServiceCollector
from src.collectors.sudo_scan import SudoCollector
from src.collectors.capabilities import CapabilitiesCollector
from src.collectors.kernel_scan import KernelCollector

from src.analysis.engine import AnalysisEngine

from src.reporting.console_reporter import ConsoleReporter
from src.reporting.json_reporter import JsonReporter
from src.reporting.pdf_reporter import PdfReporter


def main():
    print("=" * 70)
    print("        LINUX PRIVILEGE ESCALATION TOOLKIT")
    print("=" * 70)
    print("\nStarting security assessment...\n")

    print("[*] Running security collectors...\n")

    scan_results = {}

    print("[+] Collecting system information...")
    scan_results["system_info"] = SystemInfoCollector().collect()

    print("[+] Scanning SUID/SGID binaries...")
    scan_results["suid_sgid"] = SuidSgidCollector().collect()

    print("[+] Checking file permissions...")
    scan_results["permissions"] = PermissionsCollector().collect()

    print("[+] Scanning scheduled cron jobs...")
    scan_results["cron"] = CronCollector().collect()

    print("[+] Scanning system services...")
    scan_results["services"] = ServiceCollector().collect()

    print("[+] Checking sudo configuration...")
    scan_results["sudo"] = SudoCollector().collect()

    print("[+] Scanning Linux capabilities...")
    scan_results["capabilities"] = CapabilitiesCollector().collect()

    print("[+] Checking kernel information...")
    scan_results["kernel"] = KernelCollector().collect()

    print("\n[*] Running analysis engine...\n")

    engine = AnalysisEngine()
    findings = engine.analyze(scan_results)

    print(f"[*] Analysis complete.")
    print(f"[*] Total findings generated: {len(findings)}\n")

    console_reporter = ConsoleReporter()
    json_reporter = JsonReporter()
    pdf_reporter = PdfReporter()

    print("[*] Generating console report...\n")
    console_reporter.generate(findings)

    print("\n[*] Generating JSON report...")
    json_reporter.generate(findings)

    print("[*] Generating PDF report...")
    pdf_reporter.generate(findings)

    print("\n" + "=" * 70)
    print("Security assessment completed successfully.")
    print("=" * 70)


if __name__ == "__main__":
    main()