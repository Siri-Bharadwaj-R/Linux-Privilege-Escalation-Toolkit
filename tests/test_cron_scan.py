from src.collectors.cron_scan import CronCollector


def test_cron_collection():
    collector = CronCollector()

    results = collector.collect()

    assert "user_crontab" in results
    assert "system_crontab" in results
    assert "cron_directories" in results
    assert "root_executed_jobs" in results
    assert "writable_jobs" in results

    assert isinstance(results["user_crontab"], dict)
    assert isinstance(results["system_crontab"], dict)
    assert isinstance(results["cron_directories"], dict)
    assert isinstance(results["root_executed_jobs"], list)
    assert isinstance(results["writable_jobs"], list)

    assert "/etc/cron.d" in results["cron_directories"]
    assert "/etc/cron.daily" in results["cron_directories"]
    assert "/etc/cron.weekly" in results["cron_directories"]