from src.analysis.risk_engine import RiskEngine


def test_risk_calculation():
    findings = [
        {
            "severity": "Critical",
        },
        {
            "severity": "High",
        },
        {
            "severity": "Medium",
        },
        {
            "severity": "Low",
        },
        {
            "severity": "Info",
        },
    ]

    engine = RiskEngine()

    result = engine.calculate(findings)

    assert result["risk_score"] == 51

    assert result["risk_level"] == "High"

    assert result["total_findings"] == 5

    assert result["severity_counts"]["Critical"] == 1
    assert result["severity_counts"]["High"] == 1
    assert result["severity_counts"]["Medium"] == 1
    assert result["severity_counts"]["Low"] == 1
    assert result["severity_counts"]["Info"] == 1


def test_empty_findings():
    engine = RiskEngine()

    result = engine.calculate([])

    assert result["risk_score"] == 0
    assert result["risk_level"] == "Info"
    assert result["total_findings"] == 0


def test_risk_score_cap():
    findings = [
        {
            "severity": "Critical",
        }
        for _ in range(10)
    ]

    engine = RiskEngine()

    result = engine.calculate(findings)

    assert result["risk_score"] == 100
    assert result["risk_level"] == "Critical"