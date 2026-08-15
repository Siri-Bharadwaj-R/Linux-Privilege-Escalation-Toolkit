from src.analysis.engine import AnalysisEngine


def test_analysis_engine():
    scan_results = {
        "suid_sgid": {
            "risky_binaries": [
                "/usr/bin/example"
            ]
        },
        "permissions": {
            "world_writable_files": [
                "/tmp/test_file"
            ],
            "world_writable_directories": [
                "/tmp/test_directory"
            ],
            "sensitive_file_permissions": {
                "/etc/passwd": {
                    "world_writable": False
                },
                "/etc/shadow": {
                    "world_writable": False
                },
            },
        },
        "sudo": {
            "all_access": False,
            "nopasswd_rules": [],
            "risky_commands": [],
        },
        "cron": {
            "writable_jobs": [],
        },
        "services": {
            "writable_service_files": [],
            "insecure_path_services": [],
        },
        "capabilities": {
            "risky_capabilities": [],
        },
        "kernel": {
            "kernel_matches": [],
            "potentially_outdated": False,
        },
    }

    engine = AnalysisEngine()

    findings = engine.analyze(scan_results)

    assert isinstance(findings, list)
    assert len(findings) == 3

    assert findings[0]["severity"] == "High"
    assert findings[0]["category"] == "SUID/SGID"

    assert findings[1]["category"] == "Permissions"
    assert findings[2]["category"] == "Permissions"