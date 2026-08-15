from src.collectors.service_scan import ServiceCollector


def test_service_collection():
    collector = ServiceCollector()

    results = collector.collect()

    assert "services" in results
    assert "service_count" in results
    assert "root_services" in results
    assert "writable_service_files" in results
    assert "insecure_path_services" in results

    assert isinstance(results["services"], list)
    assert isinstance(results["service_count"], int)
    assert isinstance(results["root_services"], list)
    assert isinstance(
        results["writable_service_files"],
        list,
    )
    assert isinstance(
        results["insecure_path_services"],
        list,
    )

    assert results["service_count"] == len(
        results["services"]
    )