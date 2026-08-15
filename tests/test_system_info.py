from src.collectors.system_info import SystemInfoCollector


def test_system_info_collection():
    collector = SystemInfoCollector()

    info = collector.collect()

    assert info["current_user"]
    assert info["uid"] >= 0
    assert info["privilege_level"] in ["ROOT", "STANDARD USER"]
    assert info["kernel"]
    assert info["architecture"]
    assert isinstance(info["groups"], list)