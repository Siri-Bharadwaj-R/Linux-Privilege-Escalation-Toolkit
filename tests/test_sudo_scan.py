from src.collectors.sudo_scan import SudoCollector


def test_sudo_collection():
    collector = SudoCollector()

    results = collector.collect()

    assert "sudo_available" in results
    assert "raw_output" in results
    assert "nopasswd_rules" in results
    assert "all_access" in results
    assert "risky_commands" in results

    assert isinstance(results["sudo_available"], bool)
    assert isinstance(results["raw_output"], str)
    assert isinstance(results["nopasswd_rules"], list)
    assert isinstance(results["all_access"], bool)
    assert isinstance(results["risky_commands"], list)