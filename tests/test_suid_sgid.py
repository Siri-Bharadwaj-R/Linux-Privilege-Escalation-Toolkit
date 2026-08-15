from src.collectors.suid_sgid import SuidSgidCollector


def test_suid_sgid_collection():
    collector = SuidSgidCollector()

    results = collector.collect()

    assert "suid_files" in results
    assert "sgid_files" in results
    assert "suid_count" in results
    assert "sgid_count" in results
    assert "risky_binaries" in results
    assert isinstance(results["risky_binaries"], list)

    assert isinstance(results["suid_files"], list)
    assert isinstance(results["sgid_files"], list)

    assert results["suid_count"] == len(results["suid_files"])
    assert results["sgid_count"] == len(results["sgid_files"])
    