from src.analysis.analyzer import Analyzer


def test_analyzer_initialization():
    analyzer = Analyzer()

    assert analyzer.analysis_engine is not None
    assert analyzer.risk_engine is not None


def test_collector_error_handling():
    class BrokenCollector:

        def collect(self):
            raise RuntimeError("Test collector failure")

    analyzer = Analyzer()

    result = analyzer._run_collector(
        BrokenCollector()
    )

    assert "error" in result
    assert result["error"] == "Test collector failure"
    
def test_full_scan_structure():
    analyzer = Analyzer()

    result = analyzer.run_scan()

    assert "system_info" in result
    assert "scan_results" in result
    assert "findings" in result
    assert "risk_summary" in result

    assert isinstance(result["scan_results"], dict)
    assert isinstance(result["findings"], list)
    assert isinstance(result["risk_summary"], dict)