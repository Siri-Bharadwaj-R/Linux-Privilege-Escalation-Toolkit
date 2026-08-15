from src.collectors.capabilities import (
    CapabilitiesCollector,
)


def test_capabilities_collection():
    collector = CapabilitiesCollector()

    results = collector.collect()

    assert "capabilities" in results
    assert "capability_count" in results
    assert "risky_capabilities" in results
    assert "risky_capability_count" in results

    assert isinstance(results["capabilities"], list)
    assert isinstance(results["capability_count"], int)
    assert isinstance(
        results["risky_capabilities"],
        list,
    )
    assert isinstance(
        results["risky_capability_count"],
        int,
    )

    assert results["capability_count"] == len(
        results["capabilities"]
    )

    assert results["risky_capability_count"] == len(
        results["risky_capabilities"]
    )