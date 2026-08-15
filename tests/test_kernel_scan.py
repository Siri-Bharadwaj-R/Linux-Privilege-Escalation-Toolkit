from src.collectors.kernel_scan import KernelCollector


def test_kernel_collection():
    collector = KernelCollector()

    results = collector.collect()

    assert "kernel_release" in results
    assert "kernel_version" in results
    assert "kernel_matches" in results
    assert "match_count" in results
    assert "potentially_outdated" in results

    assert isinstance(results["kernel_release"], str)
    assert isinstance(results["kernel_version"], str)
    assert isinstance(results["kernel_matches"], list)
    assert isinstance(results["match_count"], int)
    assert isinstance(
        results["potentially_outdated"],
        bool,
    )

    assert results["match_count"] == len(
        results["kernel_matches"]
    )