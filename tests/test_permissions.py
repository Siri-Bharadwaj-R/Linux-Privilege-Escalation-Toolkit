from src.collectors.permissions import PermissionsCollector


def test_permissions_collection():
    collector = PermissionsCollector()

    results = collector.collect()

    assert "world_writable_files" in results
    assert "world_writable_directories" in results
    assert "world_writable_file_count" in results
    assert "world_writable_directory_count" in results
    assert "sensitive_file_permissions" in results
    assert "home_permissions" in results

    assert isinstance(results["world_writable_files"], list)
    assert isinstance(
        results["world_writable_directories"],
        list
    )
    assert isinstance(
        results["sensitive_file_permissions"],
        dict
    )
    assert isinstance(results["home_permissions"], list)

    assert (
        results["world_writable_file_count"]
        == len(results["world_writable_files"])
    )

    assert (
        results["world_writable_directory_count"]
        == len(results["world_writable_directories"])
    )

    assert "/etc/passwd" in results["sensitive_file_permissions"]
    assert "/etc/shadow" in results["sensitive_file_permissions"]