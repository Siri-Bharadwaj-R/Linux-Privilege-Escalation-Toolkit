## Project Structure

```text
linux-privesc-toolkit/
├── data/
│   ├── kernel_cves.json
│   ├── risky_binaries.json
│   ├── risky_capabilities.json
│   └── vulnerability_patterns.json
│
├── reports/
│   └── .gitkeep
│
├── src/
│   ├── analysis/
│   │   ├── analyzer.py
│   │   ├── engine.py
│   │   ├── findings.py
│   │   ├── pattern_matcher.py
│   │   └── risk_engine.py
│   │
│   ├── collectors/
│   │   ├── capabilities.py
│   │   ├── cron_scan.py
│   │   ├── kernel_scan.py
│   │   ├── permissions.py
│   │   ├── service_scan.py
│   │   ├── sudo_scan.py
│   │   ├── suid_sgid.py
│   │   └── system_info.py
│   │
│   ├── models/
│   │   └── finding.py
│   │
│   ├── reporting/
│   │   ├── console_reporter.py
│   │   ├── json_reporter.py
│   │   └── pdf_reporter.py
│   │
│   └── utils/
│       ├── command_runner.py
│       ├── helpers.py
│       └── logger.py
│
├── tests/
│   ├── test_analysis_engine.py
│   ├── test_analyzer.py
│   ├── test_capabilities.py
│   ├── test_cron_scan.py
│   ├── test_findings.py
│   ├── test_kernel_scan.py
│   ├── test_permissions.py
│   ├── test_risk_engine.py
│   ├── test_service_scan.py
│   ├── test_sudo_scan.py
│   ├── test_suid_sgid.py
│   └── test_system_info.py
│
├── main.py
├── requirements.txt
└── README.md
```