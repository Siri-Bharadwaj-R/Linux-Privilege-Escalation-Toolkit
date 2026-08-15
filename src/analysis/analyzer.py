from src.collectors.system_info import SystemInfoCollector
from src.collectors.suid_sgid import SuidSgidCollector
from src.collectors.permissions import PermissionsCollector
from src.collectors.sudo_scan import SudoCollector
from src.collectors.cron_scan import CronCollector
from src.collectors.service_scan import ServiceCollector
from src.collectors.capabilities import CapabilitiesCollector
from src.collectors.kernel_scan import KernelCollector

from src.analysis.engine import AnalysisEngine
from src.analysis.risk_engine import RiskEngine


class Analyzer:
    """
    Main orchestration component for the Linux Privilege
    Escalation Automation Toolkit.

    Runs all collectors, analyzes the results, and calculates
    the overall security risk.
    """

    def __init__(self):
        self.analysis_engine = AnalysisEngine()
        self.risk_engine = RiskEngine()

    def run_scan(self) -> dict:
        """
        Run all security collectors and generate the final
        analysis result.
        """

        scan_results = {
            "system_info": self._run_collector(
                SystemInfoCollector()
            ),
            "suid_sgid": self._run_collector(
                SuidSgidCollector()
            ),
            "permissions": self._run_collector(
                PermissionsCollector()
            ),
            "sudo": self._run_collector(
                SudoCollector()
            ),
            "cron": self._run_collector(
                CronCollector()
            ),
            "services": self._run_collector(
                ServiceCollector()
            ),
            "capabilities": self._run_collector(
                CapabilitiesCollector()
            ),
            "kernel": self._run_collector(
                KernelCollector()
            ),
        }

        findings = self.analysis_engine.analyze(
            scan_results
        )

        risk_summary = self.risk_engine.calculate(
            findings
        )

        return {
            "system_info": scan_results["system_info"],
            "scan_results": scan_results,
            "findings": findings,
            "risk_summary": risk_summary,
        }

    def _run_collector(self, collector) -> dict:
        """
        Run a collector safely.

        If a collector fails, record the error instead of
        stopping the entire toolkit.
        """

        try:
            return collector.collect()

        except Exception as error:
            return {
                "error": str(error)
            }