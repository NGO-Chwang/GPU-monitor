import argparse
import sys
import time
from datetime import datetime

from monitor_common import (
    DASHBOARD_FILE,
    cache_compatible,
    cache_fresh,
    config_fingerprint,
    create_placeholder_dashboard,
    load_raw_cache,
    load_settings,
    load_ssh_credentials,
    load_users,
    acquire_collector_lock,
    publish_dashboard,
    save_raw_cache,
    scan_all_hosts,
)


def run_iteration(force_scan=False, last_published_fingerprint=None):
    settings = load_settings()
    user_map, aliases = load_users()
    fingerprint = config_fingerprint(settings, user_map, aliases)
    cache = load_raw_cache()

    # Any users.csv / health-threshold change republishes the interactive HTML
    # immediately from the raw cache, without an SSH scan.
    if cache_compatible(cache, settings):
        if force_scan or not cache_fresh(cache, settings):
            ssh_username, ssh_password = load_ssh_credentials(settings)
            if not ssh_password:
                if not DASHBOARD_FILE.exists():
                    create_placeholder_dashboard(settings, "placeholder_ssh_not_configured")
                print("[%s] SSH password not configured; keeping existing dashboard." % datetime.now().isoformat(timespec="seconds"))
            else:
                data = scan_all_hosts(settings, ssh_username, ssh_password, cache.get("data", {}))
                cache = save_raw_cache(data, settings)
                publish_dashboard(cache, settings, user_map, aliases)
                fingerprint = config_fingerprint(settings, user_map, aliases)
                print("[%s] Server data refreshed and dashboard published." % datetime.now().isoformat(timespec="seconds"))
                return fingerprint
        elif fingerprint != last_published_fingerprint or not DASHBOARD_FILE.exists():
            publish_dashboard(cache, settings, user_map, aliases)
            print("[%s] Dashboard rebuilt from cache (config/users changed; no SSH scan)." % datetime.now().isoformat(timespec="seconds"))
        return fingerprint

    # First run or host-list/schema change: no compatible raw cache exists.
    ssh_username, ssh_password = load_ssh_credentials(settings)
    if not ssh_password:
        create_placeholder_dashboard(settings, "placeholder_ssh_not_configured")
        print("SSH password not configured.")
        return fingerprint

    create_placeholder_dashboard(settings, "placeholder_first_scan")
    data = scan_all_hosts(settings, ssh_username, ssh_password, {})
    cache = save_raw_cache(data, settings)
    publish_dashboard(cache, settings, user_map, aliases)
    print("[%s] Initial scan completed." % datetime.now().isoformat(timespec="seconds"))
    return fingerprint


def main():
    parser = argparse.ArgumentParser(description="GPU Monitor background collector")
    parser.add_argument("--loop", action="store_true", help="Run continuously")
    parser.add_argument("--once", action="store_true", help="Run one iteration then exit")
    parser.add_argument("--force", action="store_true", help="Force an SSH refresh immediately")
    args = parser.parse_args()

    lock_file = acquire_collector_lock()
    if lock_file is None:
        print("Another collector.py instance is already running.")
        return 0

    last_fingerprint = None
    try:
        if args.once or not args.loop:
            run_iteration(force_scan=args.force, last_published_fingerprint=last_fingerprint)
            return 0

        first = True
        while True:
            try:
                last_fingerprint = run_iteration(
                    force_scan=(args.force and first),
                    last_published_fingerprint=last_fingerprint,
                )
            except Exception as e:
                print("[%s] Collector error: %s" % (datetime.now().isoformat(timespec="seconds"), e), file=sys.stderr)
            first = False
            settings = load_settings()
            time.sleep(settings.get("collector_poll_seconds", 2))
    finally:
        try:
            lock_file.close()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
