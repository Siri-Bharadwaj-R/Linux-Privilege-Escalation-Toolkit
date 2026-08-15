from src.analysis.findings import Finding


def test_finding_creation():
    finding = Finding(
        title="Test Finding",
        severity="High",
        target="/tmp/example",
        description="This is a test finding.",
        mitigation="Fix the permissions.",
        category="Permissions",
    )

    result = finding.to_dict()

    assert result["title"] == "Test Finding"
    assert result["severity"] == "High"
    assert result["target"] == "/tmp/example"
    assert result["category"] == "Permissions"


def test_invalid_severity():
    try:
        Finding(
            title="Invalid Finding",
            severity="EXTREME",
            target="/tmp/example",
            description="Test",
            mitigation="Test",
            category="Test",
        )

        assert False

    except ValueError:
        assert True