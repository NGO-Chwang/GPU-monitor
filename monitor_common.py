import csv
import hashlib
import html
import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from pathlib import Path

import altair as alt
import pandas as pd
import paramiko

try:
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None


BASE_DIR = Path(__file__).resolve().parent
CONFIG_DIR = BASE_DIR / "config"
DATA_DIR = BASE_DIR / "data"
STATIC_DIR = BASE_DIR / "static"
VENDOR_DIR = STATIC_DIR / "vendor"
CONFIG_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)
STATIC_DIR.mkdir(parents=True, exist_ok=True)
VENDOR_DIR.mkdir(parents=True, exist_ok=True)

SETTINGS_FILE = CONFIG_DIR / "settings.json"
USERS_FILE = CONFIG_DIR / "users.csv"
SECRETS_FILE = CONFIG_DIR / "secrets.json"
RAW_CACHE_FILE = DATA_DIR / "gpu_monitor_cache.json"
COLLECTOR_LOCK_FILE = DATA_DIR / ".collector.lock"
DASHBOARD_FILE = STATIC_DIR / "dashboard_cache.html"
DASHBOARD_VERSION_FILE = STATIC_DIR / "dashboard_version.json"
DASHBOARD_SPECS_FILES = {lang: STATIC_DIR / ("dashboard_specs_%s.json" % lang) for lang in ("ja", "zh", "en")}

CACHE_SCHEMA_VERSION = 4

DEFAULT_SETTINGS = {
    "hosts": [],
    "reverse_hosts": True,
    "cache_ttl_seconds": 60,
    "collector_poll_seconds": 2,
    "dashboard_check_seconds": 5,
    "scan_workers": 6,
    "ssh_timeout_seconds": 5,
    "zombie_threshold_gb": 0.1,
    "contact_username": "chwang",
    "trust_proxy_headers": False,
    "visitor_logging_enabled": True,
    "charts": {
        "plot_height": 360,
        "chart_container_height": 450,
        "cpu_bar_width": 24,
        "gpu_bar_width": 44,
        "cpu_label_angle": -28,
        "cpu_label_limit": 86,
        "lazy_render_margin_px": 900,
        "initial_render_charts": 6,
        "progressive_batch_size": 4,
        "progressive_delay_ms": 60
    },
    "gpu_health": {
        "enabled": True,
        "warning_memory_gb": 1.0,
        "critical_memory_gb": 0.2,
        "min_runtime_minutes": 10,
        "temperature_warning_c": 85,
        "zombie_is_warning": True,
    },
}


def _deep_merge(base, override):
    result = dict(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _read_json(path, default):
    try:
        with Path(path).open("r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return default


def atomic_write_json(path, payload, private=False):
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    os.replace(str(tmp), str(path))
    if private:
        try:
            os.chmod(str(path), 0o600)
        except OSError:
            pass


def atomic_write_text(path, text):
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        f.write(text)
    os.replace(str(tmp), str(path))


def load_settings():
    raw = _read_json(SETTINGS_FILE, {})
    if not isinstance(raw, dict):
        raw = {}
    settings = _deep_merge(DEFAULT_SETTINGS, raw)
    settings["cache_ttl_seconds"] = max(5, int(settings.get("cache_ttl_seconds", 60)))
    settings["collector_poll_seconds"] = max(1, int(settings.get("collector_poll_seconds", 2)))
    settings["dashboard_check_seconds"] = max(2, int(settings.get("dashboard_check_seconds", 5)))
    settings["scan_workers"] = max(1, int(settings.get("scan_workers", 6)))
    settings["ssh_timeout_seconds"] = max(1, int(settings.get("ssh_timeout_seconds", 5)))
    settings["zombie_threshold_gb"] = max(0.0, float(settings.get("zombie_threshold_gb", 0.1)))
    charts = settings.get("charts", {})
    charts["plot_height"] = max(240, int(charts.get("plot_height", 360)))
    charts["chart_container_height"] = max(charts["plot_height"] + 60, int(charts.get("chart_container_height", 450)))
    charts["cpu_bar_width"] = max(6, min(60, int(charts.get("cpu_bar_width", 24))))
    charts["gpu_bar_width"] = max(10, min(90, int(charts.get("gpu_bar_width", 44))))
    charts["cpu_label_angle"] = max(-90, min(0, int(charts.get("cpu_label_angle", -28))))
    charts["cpu_label_limit"] = max(40, int(charts.get("cpu_label_limit", 86)))
    charts["lazy_render_margin_px"] = max(0, int(charts.get("lazy_render_margin_px", 900)))
    charts["initial_render_charts"] = max(2, min(20, int(charts.get("initial_render_charts", 6))))
    charts["progressive_batch_size"] = max(1, min(12, int(charts.get("progressive_batch_size", 4))))
    charts["progressive_delay_ms"] = max(0, min(1000, int(charts.get("progressive_delay_ms", 60))))
    settings["charts"] = charts
    health = settings.get("gpu_health", {})
    health["warning_memory_gb"] = max(0.0, float(health.get("warning_memory_gb", 1.0)))
    health["critical_memory_gb"] = max(0.0, float(health.get("critical_memory_gb", 0.2)))
    health["min_runtime_minutes"] = max(0.0, float(health.get("min_runtime_minutes", 10)))
    health["temperature_warning_c"] = float(health.get("temperature_warning_c", 85))
    settings["gpu_health"] = health
    return settings


def ordered_hosts(settings):
    hosts = [str(h).strip() for h in settings.get("hosts", []) if str(h).strip()]
    if settings.get("reverse_hosts", True):
        hosts.reverse()
    return hosts


def format_username(username):
    return username[:7] + "+" if len(username) > 7 else username


def load_users():
    user_map = {}
    enabled_aliases = set()
    with USERS_FILE.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            username = (row.get("username") or "").strip()
            nickname = (row.get("nickname") or "").strip() or username
            enabled_text = (row.get("enabled") or "1").strip().lower()
            enabled = enabled_text not in {"0", "false", "no", "off"}
            if not username or not enabled:
                continue
            for alias in {username, format_username(username)}:
                user_map[alias] = nickname
                enabled_aliases.add(alias)
    return user_map, enabled_aliases


def load_ssh_credentials(settings):
    secrets = _read_json(SECRETS_FILE, {})
    if not isinstance(secrets, dict):
        secrets = {}
    username = os.getenv(
        "GPU_MONITOR_SSH_USER",
        str(secrets.get("ssh_username", settings.get("contact_username", "chwang"))),
    )
    password = os.getenv(
        "GPU_MONITOR_SSH_PASSWORD",
        str(secrets.get("ssh_password", "")),
    )
    return username, password


def config_fingerprint(settings, user_map, aliases):
    relevant = {
        "hosts": ordered_hosts(settings),
        "gpu_health": settings.get("gpu_health", {}),
        "zombie_threshold_gb": settings.get("zombie_threshold_gb"),
        "dashboard_check_seconds": settings.get("dashboard_check_seconds"),
        "charts": settings.get("charts", {}),
        "users": sorted((k, user_map.get(k, "")) for k in aliases),
    }
    raw = json.dumps(relevant, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _duration_string(seconds):
    try:
        return str(timedelta(seconds=int(seconds)))
    except Exception:
        return "Unknown"


def _to_float(value, default=None):
    try:
        text = str(value).strip()
        if text in {"", "N/A", "[N/A]", "Not Supported", "[Not Supported]"}:
            return default
        return float(text)
    except (TypeError, ValueError):
        return default


def _query_process_metadata(ssh, pids):
    if not pids:
        return {}
    pid_arg = ",".join(str(pid) for pid in sorted(set(pids), key=lambda x: int(x)))
    command = "ps -p %s -o pid=,user=,etimes=,lstart=" % pid_arg
    _, stdout, _ = ssh.exec_command(command)
    result = {}
    for line in stdout.readlines():
        try:
            pid, username, elapsed_seconds, start_time = line.strip().split(None, 3)
            seconds = int(elapsed_seconds)
            result[str(pid)] = {
                "username": username,
                "start_time": start_time,
                "duration_seconds": seconds,
                "duration": _duration_string(seconds),
            }
        except (ValueError, TypeError):
            continue
    return result


def collect_gpu_info(ssh, zombie_threshold_gb):
    command = (
        "nvidia-smi --query-gpu=index,name,uuid,memory.total,memory.used,"
        "utilization.gpu,temperature.gpu --format=csv,noheader,nounits"
    )
    _, stdout, stderr = ssh.exec_command(command)
    lines = stdout.readlines()
    if not lines:
        error_text = "".join(stderr.readlines()).strip()
        if error_text:
            raise RuntimeError(error_text)

    gpus = []
    for line in lines:
        try:
            parts = next(csv.reader([line]))
            parts = [part.strip() for part in parts]
            if len(parts) < 7:
                continue
            gpu_id = int(parts[0])
            gpus.append(
                {
                    "gpu_id": gpu_id,
                    "name": parts[1],
                    "uuid": parts[2],
                    "total_memory_gb": (_to_float(parts[3], 0.0) or 0.0) / 1024.0,
                    "used_memory_gb": (_to_float(parts[4], 0.0) or 0.0) / 1024.0,
                    "utilization_percent": _to_float(parts[5], None),
                    "temperature_c": _to_float(parts[6], None),
                    "processes": [],
                }
            )
        except Exception as e:
            print("[Warning] Failed to parse GPU summary: %s (%s)" % (line.strip(), e))

    all_pids = []
    by_gpu = {}
    for gpu in gpus:
        gpu_id = gpu["gpu_id"]
        command = (
            "nvidia-smi --query-compute-apps=pid,used_memory "
            "--format=csv,noheader,nounits --id=%s" % gpu_id
        )
        _, stdout, _ = ssh.exec_command(command)
        processes = []
        for line in stdout.readlines():
            try:
                parts = next(csv.reader([line]))
                pid = parts[0].strip()
                memory_mib = _to_float(parts[1], None)
                if not pid or memory_mib is None:
                    continue
                processes.append((pid, memory_mib / 1024.0))
                all_pids.append(pid)
            except Exception:
                continue
        by_gpu[gpu_id] = processes

    metadata = _query_process_metadata(ssh, all_pids)
    for gpu in gpus:
        accounted = 0.0
        for pid, memory_gb in by_gpu.get(gpu["gpu_id"], []):
            meta = metadata.get(str(pid), {})
            accounted += memory_gb
            gpu["processes"].append(
                {
                    "pid": str(pid),
                    "username": meta.get("username", "Unknown"),
                    "memory_gb": memory_gb,
                    "start_time": meta.get("start_time", "Unknown"),
                    "duration_seconds": meta.get("duration_seconds"),
                    "duration": meta.get("duration", "Unknown"),
                    "kind": "process",
                }
            )

        residual = max(0.0, float(gpu.get("used_memory_gb") or 0.0) - accounted)
        if residual > zombie_threshold_gb:
            gpu["processes"].append(
                {
                    "pid": "-",
                    "username": "ZombieProcess",
                    "memory_gb": residual,
                    "start_time": "-",
                    "duration_seconds": None,
                    "duration": "-",
                    "kind": "zombie",
                }
            )
    return gpus


def collect_host(host, settings, ssh_username, ssh_password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    timeout = settings["ssh_timeout_seconds"]
    try:
        ssh.connect(
            host,
            username=ssh_username,
            password=ssh_password,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
        )

        cpu_usage = {}
        _, stdout, _ = ssh.exec_command("ps aux")
        for line in stdout.readlines()[1:]:
            try:
                parts = line.split()
                if len(parts) < 6:
                    continue
                username = parts[0]
                memory_gb = float(parts[5]) / 1024.0 / 1024.0
                cpu_usage[username] = cpu_usage.get(username, 0.0) + memory_gb
            except Exception:
                continue

        gpus = collect_gpu_info(ssh, settings["zombie_threshold_gb"])
        return {
            "cpu_memory_gb": cpu_usage,
            "gpus": gpus,
            "error": None,
            "collected_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        }
    finally:
        ssh.close()


def load_raw_cache():
    cache = _read_json(RAW_CACHE_FILE, None)
    return cache if isinstance(cache, dict) else None


def cache_compatible(cache, settings):
    if not cache:
        return False
    return (
        int(cache.get("schema_version", 0)) == CACHE_SCHEMA_VERSION
        and cache.get("hosts") == ordered_hosts(settings)
        and isinstance(cache.get("data"), dict)
    )


def cache_fresh(cache, settings):
    if not cache_compatible(cache, settings):
        return False
    try:
        return (time.time() - float(cache["updated_ts"])) < settings["cache_ttl_seconds"]
    except (KeyError, TypeError, ValueError):
        return False


def scan_all_hosts(settings, ssh_username, ssh_password, previous_data=None):
    hosts = ordered_hosts(settings)
    previous_data = previous_data or {}
    results = {}
    workers = min(settings["scan_workers"], len(hosts)) if hosts else 1
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {
            executor.submit(collect_host, host, settings, ssh_username, ssh_password): host
            for host in hosts
        }
        for future in as_completed(future_map):
            host = future_map[future]
            try:
                results[host] = future.result()
            except Exception as e:
                print("[Error] Could not refresh %s: %s" % (host, e))
                if host in previous_data:
                    old = dict(previous_data[host])
                    old["refresh_error"] = str(e)
                    results[host] = old
                else:
                    results[host] = {
                        "cpu_memory_gb": {},
                        "gpus": [],
                        "error": str(e),
                        "collected_at": datetime.now().astimezone().isoformat(timespec="seconds"),
                    }
    return {host: results.get(host, {}) for host in hosts}


def save_raw_cache(data, settings):
    now = datetime.now().astimezone()
    payload = {
        "schema_version": CACHE_SCHEMA_VERSION,
        "hosts": ordered_hosts(settings),
        "updated_ts": time.time(),
        "updated_at": now.isoformat(timespec="seconds"),
        "data": data,
    }
    atomic_write_json(RAW_CACHE_FILE, payload, private=True)
    return payload



TRANSLATIONS = {
    "ja": {
        "title": "Morilab サーバー GPU モニター",
        "language": "言語",
        "server_data": "サーバーデータ: {updated}",
        "online_badge": "Vega インタラクティブ SVG",
        "status_Healthy": "正常",
        "status_Idle": "アイドル",
        "status_Warning": "警告",
        "status_Critical": "重大",
        "status_Unknown": "不明",
        "status_Starting": "起動中",
        "status_Zombie": "Zombie",
        "health_note": "GPU の健康表示はタスク使用状況のヒューリスティック判定であり、ハードウェア故障を意味しません。実行時間が {minutes} 分以上で、GPU メモリが {warning} GB 以下なら警告、{critical} GB 以下なら重大と判定します。",
        "health_ok": "✓ 長時間の低 GPU メモリ使用タスクやその他の警告は検出されていません",
        "refresh_error": "⛔ データ更新エラー",
        "panel_cpu_memory": "CPU メモリ",
        "panel_gpu_memory_health": "GPU メモリ / 健康状態",
        "empty_cpu": "CPU データを利用できません",
        "empty_gpu": "GPU データを利用できません",
        "legend_zombie": "ZombieProcess",
        "legend_warning": "低 GPU メモリ警告",
        "legend_critical": "低 GPU メモリ重大",
        "legend_total": "GPU 総メモリ",
        "axis_cpu_x": "CPU の利用状況",
        "axis_cpu_y": "メモリ使用量 (GB)",
        "axis_gpu_x": "GPU の利用状況",
        "axis_gpu_y": "GPU 使用量 (GB)",
        "legend_user": "ユーザー",
        "tooltip_pid": "PID",
        "tooltip_username": "ユーザー名",
        "tooltip_nickname": "表示名",
        "tooltip_memory_usage": "メモリ使用量 (GB)",
        "tooltip_user": "ユーザー",
        "tooltip_memory_used": "GPU メモリ使用量 (GB)",
        "tooltip_health": "状態",
        "tooltip_health_reason": "判定理由",
        "tooltip_gpu_util": "GPU 使用率 (%)",
        "tooltip_temperature": "温度 (°C)",
        "tooltip_start_time": "開始時刻",
        "tooltip_duration": "実行時間",
        "tooltip_total_memory": "総メモリ (GB)",
        "reason_normal": "正常",
        "reason_starting": "プログラムは起動・ロード観察期間中です",
        "reason_low_memory": "{minutes} 分以上実行していますが、GPU メモリ使用量は {memory} GB のみです",
        "reason_zombie": "{memory} GB の Zombie / 残留 GPU メモリを検出しました",
        "reason_temperature": "GPU 温度 {temperature}°C が警告しきい値 {threshold}°C 以上です",
        "reason_idle": "GPU に計算プロセスはありません",
        "contact": "お問い合わせ・コメント: {contact}",
        "placeholder_ssh_not_configured": "SSH パスワードが設定されていません。config/secrets.json を編集してください。",
        "placeholder_first_scan": "初回のサーバースキャンを実行しています……",
        "placeholder_wait": "収集プログラムが初回スキャンを完了すると、この画面は自動的に更新されます。",
        "loading_cache": "インタラクティブ図表キャッシュを読み込んでいます……",
        "load_failed": "図表キャッシュを読み込めませんでした。",
        "load_hint": "collector.py と Streamlit が起動していることを確認してください。",
        "chart_error": "図表の描画に失敗しました"
    },
    "zh": {
        "title": "Morilab 服务器 GPU 监控",
        "language": "语言",
        "server_data": "服务器数据: {updated}",
        "online_badge": "Vega 交互式 SVG",
        "status_Healthy": "正常",
        "status_Idle": "空闲",
        "status_Warning": "警告",
        "status_Critical": "严重",
        "status_Unknown": "未知",
        "status_Starting": "启动中",
        "status_Zombie": "Zombie",
        "health_note": "GPU 健康提示是任务使用状态的启发式判断，不代表硬件故障。运行时间达到 {minutes} 分钟且 GPU 显存不超过 {warning} GB 时为警告，不超过 {critical} GB 时为严重。",
        "health_ok": "✓ 未发现长时间低显存任务或其他警告",
        "refresh_error": "⛔ 数据刷新异常",
        "panel_cpu_memory": "CPU 内存",
        "panel_gpu_memory_health": "GPU 显存 / 健康状态",
        "empty_cpu": "CPU 数据不可用",
        "empty_gpu": "GPU 数据不可用",
        "legend_zombie": "ZombieProcess",
        "legend_warning": "低显存 Warning",
        "legend_critical": "低显存 Critical",
        "legend_total": "GPU 总显存",
        "axis_cpu_x": "CPU 利用情况",
        "axis_cpu_y": "内存使用量 (GB)",
        "axis_gpu_x": "GPU 利用情况",
        "axis_gpu_y": "GPU 使用量 (GB)",
        "legend_user": "用户",
        "tooltip_pid": "PID",
        "tooltip_username": "用户名",
        "tooltip_nickname": "显示名",
        "tooltip_memory_usage": "内存使用量 (GB)",
        "tooltip_user": "用户",
        "tooltip_memory_used": "GPU 显存使用量 (GB)",
        "tooltip_health": "状态",
        "tooltip_health_reason": "判断原因",
        "tooltip_gpu_util": "GPU 利用率 (%)",
        "tooltip_temperature": "温度 (°C)",
        "tooltip_start_time": "开始时间",
        "tooltip_duration": "运行时间",
        "tooltip_total_memory": "总显存 (GB)",
        "reason_normal": "正常",
        "reason_starting": "程序仍处于启动/加载观察期",
        "reason_low_memory": "运行超过 {minutes} 分钟但仅占用 {memory} GB GPU 显存",
        "reason_zombie": "检测到 {memory} GB Zombie / 残留显存",
        "reason_temperature": "GPU 温度 {temperature}°C，高于警告阈值 {threshold}°C",
        "reason_idle": "GPU 当前无计算进程",
        "contact": "问题和意见请联系: {contact}",
        "placeholder_ssh_not_configured": "SSH 密码尚未配置。请编辑 config/secrets.json。",
        "placeholder_first_scan": "正在进行第一次服务器扫描……",
        "placeholder_wait": "采集程序完成第一次扫描后，这里会自动更新。",
        "loading_cache": "正在读取交互式图表缓存……",
        "load_failed": "无法读取图表缓存。",
        "load_hint": "请确认 collector.py 与 Streamlit 正在运行。",
        "chart_error": "图表渲染失败"
    },
    "en": {
        "title": "Morilab Server GPU Monitor",
        "language": "Language",
        "server_data": "Server data: {updated}",
        "online_badge": "Vega interactive SVG",
        "status_Healthy": "Healthy",
        "status_Idle": "Idle",
        "status_Warning": "Warning",
        "status_Critical": "Critical",
        "status_Unknown": "Unknown",
        "status_Starting": "Starting",
        "status_Zombie": "Zombie",
        "health_note": "GPU health is a heuristic for workload behavior, not a hardware-failure diagnosis. A process running for at least {minutes} minutes is Warning at ≤ {warning} GB GPU memory and Critical at ≤ {critical} GB.",
        "health_ok": "✓ No long-running low-memory GPU tasks or other warnings detected",
        "refresh_error": "⛔ Data refresh error",
        "panel_cpu_memory": "CPU Memory",
        "panel_gpu_memory_health": "GPU Memory / Health",
        "empty_cpu": "CPU data unavailable",
        "empty_gpu": "GPU data unavailable",
        "legend_zombie": "ZombieProcess",
        "legend_warning": "Low-memory Warning",
        "legend_critical": "Low-memory Critical",
        "legend_total": "GPU total memory",
        "axis_cpu_x": "CPU utilization",
        "axis_cpu_y": "Memory usage (GB)",
        "axis_gpu_x": "GPU utilization",
        "axis_gpu_y": "GPU memory usage (GB)",
        "legend_user": "User",
        "tooltip_pid": "PID",
        "tooltip_username": "Username",
        "tooltip_nickname": "Display name",
        "tooltip_memory_usage": "Memory usage (GB)",
        "tooltip_user": "User",
        "tooltip_memory_used": "GPU memory used (GB)",
        "tooltip_health": "Health",
        "tooltip_health_reason": "Reason",
        "tooltip_gpu_util": "GPU utilization (%)",
        "tooltip_temperature": "Temperature (°C)",
        "tooltip_start_time": "Start time",
        "tooltip_duration": "Duration",
        "tooltip_total_memory": "Total memory (GB)",
        "reason_normal": "Normal",
        "reason_starting": "The process is still within the startup/loading observation period",
        "reason_low_memory": "Running for more than {minutes} minutes while using only {memory} GB of GPU memory",
        "reason_zombie": "Detected {memory} GB of Zombie / residual GPU memory",
        "reason_temperature": "GPU temperature {temperature}°C is at or above the warning threshold of {threshold}°C",
        "reason_idle": "No compute process is currently using this GPU",
        "contact": "Questions and comments: {contact}",
        "placeholder_ssh_not_configured": "SSH password is not configured. Edit config/secrets.json.",
        "placeholder_first_scan": "Running the first server scan…",
        "placeholder_wait": "This view will update automatically after the collector completes the first scan.",
        "loading_cache": "Loading the interactive chart cache…",
        "load_failed": "Could not load the chart cache.",
        "load_hint": "Make sure collector.py and Streamlit are running.",
        "chart_error": "Chart rendering failed"
    },
}


def _tr(key, lang="ja", **params):
    text = TRANSLATIONS.get(lang, TRANSLATIONS["ja"]).get(key, key)
    for name, value in params.items():
        text = text.replace("{%s}" % name, str(value))
    return text


def _i18n_params_attr(params):
    return html.escape(json.dumps(params or {}, ensure_ascii=False), quote=True)


def _i18n_span(key, params=None, cls=None, tag="span"):
    attrs = ['data-i18n-key="%s"' % html.escape(key, quote=True)]
    if params:
        attrs.append('data-i18n-params="%s"' % _i18n_params_attr(params))
    if cls:
        attrs.append('class="%s"' % html.escape(cls, quote=True))
    initial = _tr(key, "ja", **(params or {}))
    return '<%s %s>%s</%s>' % (tag, " ".join(attrs), html.escape(initial), tag)


def _health_rank(status):
    return {"Unknown": 5, "Critical": 4, "Warning": 3, "Healthy": 2, "Idle": 1}.get(status, 0)


def evaluate_gpu_health(gpu, user_map, settings):
    cfg = settings.get("gpu_health", {})
    enabled = bool(cfg.get("enabled", True))
    warning_gb = float(cfg.get("warning_memory_gb", 1.0))
    critical_gb = float(cfg.get("critical_memory_gb", 0.2))
    min_seconds = float(cfg.get("min_runtime_minutes", 10)) * 60.0
    temp_warning = float(cfg.get("temperature_warning_c", 85))
    zombie_is_warning = bool(cfg.get("zombie_is_warning", True))

    alerts = []
    process_health = {}

    for proc in gpu.get("processes", []):
        pid = str(proc.get("pid", ""))
        if proc.get("kind") == "zombie":
            params = {"memory": "%.2f" % float(proc.get("memory_gb") or 0.0)}
            process_health[pid + "#zombie"] = ("Zombie", "reason_zombie", params)
            if zombie_is_warning:
                alerts.append({
                    "severity": "Warning",
                    "type": "zombie",
                    "gpu_id": gpu.get("gpu_id"),
                    "user": "ZombieProcess",
                    "pid": "-",
                    "reason_key": "reason_zombie",
                    "reason_params": params,
                })
            continue

        health = "Healthy"
        reason_key = "reason_normal"
        reason_params = {}
        if enabled:
            duration_seconds = proc.get("duration_seconds")
            memory_gb = float(proc.get("memory_gb") or 0.0)
            if duration_seconds is not None and float(duration_seconds) >= min_seconds:
                params = {"minutes": "%.0f" % (min_seconds / 60.0), "memory": "%.2f" % memory_gb}
                if memory_gb <= critical_gb:
                    health, reason_key, reason_params = "Critical", "reason_low_memory", params
                elif memory_gb <= warning_gb:
                    health, reason_key, reason_params = "Warning", "reason_low_memory", params
            elif duration_seconds is not None and float(duration_seconds) < min_seconds:
                health, reason_key = "Starting", "reason_starting"

        process_health[pid] = (health, reason_key, reason_params)
        if health in {"Warning", "Critical"}:
            raw_user = proc.get("username", "Unknown")
            alerts.append({
                "severity": health,
                "type": "low_memory",
                "gpu_id": gpu.get("gpu_id"),
                "user": user_map.get(raw_user, raw_user),
                "username": raw_user,
                "pid": pid,
                "reason_key": reason_key,
                "reason_params": reason_params,
            })

    temperature = gpu.get("temperature_c")
    if enabled and temperature is not None and float(temperature) >= temp_warning:
        alerts.append({
            "severity": "Warning",
            "type": "temperature",
            "gpu_id": gpu.get("gpu_id"),
            "user": "-",
            "pid": "-",
            "reason_key": "reason_temperature",
            "reason_params": {
                "temperature": "%.0f" % float(temperature),
                "threshold": "%.0f" % temp_warning,
            },
        })

    status = "Idle" if not gpu.get("processes") else "Healthy"
    for alert in alerts:
        if _health_rank(alert["severity"]) > _health_rank(status):
            status = alert["severity"]
    return status, alerts, process_health


def _cpu_chart(host_data, user_map, aliases, lang, settings=None):
    rows = []
    usage = host_data.get("cpu_memory_gb", {}) if isinstance(host_data, dict) else {}
    for username, memory_gb in usage.items():
        if username not in aliases:
            continue
        rows.append({
            "Username": username,
            "Nickname": user_map.get(username, username),
            "Memory Usage (GB)": float(memory_gb),
        })
    if not rows:
        return None
    settings = settings or DEFAULT_SETTINGS
    chart_cfg = settings.get("charts", {})
    df = pd.DataFrame(rows)
    max_usage = df["Memory Usage (GB)"].max()
    df["Color"] = df["Memory Usage (GB)"].apply(
        lambda x: "blue" if x < 1 else ("red" if x == max_usage else "gray")
    )
    # Keep the plot area a fixed height and move the X-axis title outside Vega.
    # This prevents long user labels from pushing the CPU title lower than GPU.
    x_axis = alt.Axis(
        title=None,
        labelAngle=int(chart_cfg.get("cpu_label_angle", -28)),
        labelLimit=int(chart_cfg.get("cpu_label_limit", 86)),
        labelPadding=6,
        labelOverlap="greedy",
    )
    return (
        alt.Chart(df)
        .mark_bar(size=int(chart_cfg.get("cpu_bar_width", 24)))
        .encode(
            x=alt.X("Nickname:N", axis=x_axis),
            y=alt.Y("Memory Usage (GB):Q", title=_tr("axis_cpu_y", lang)),
            color=alt.Color("Color:N", scale=None, legend=None),
            tooltip=[
                alt.Tooltip("Username:N", title=_tr("tooltip_username", lang)),
                alt.Tooltip("Nickname:N", title=_tr("tooltip_nickname", lang)),
                alt.Tooltip("Memory Usage (GB):Q", title=_tr("tooltip_memory_usage", lang), format=".2f"),
            ],
        )
        .properties(width=560, height=int(chart_cfg.get("plot_height", 360)))
        .configure_axis(labelFontSize=13, titleFontSize=18)
    )


def _gpu_chart(host_data, user_map, settings, lang):
    process_rows = []
    total_rows = []
    all_alerts = []
    gpu_statuses = []
    chart_cfg = settings.get("charts", {})

    for gpu in host_data.get("gpus", []):
        gpu_label = "GPU %s" % gpu.get("gpu_id")
        status, alerts, process_health = evaluate_gpu_health(gpu, user_map, settings)
        gpu_statuses.append({
            "gpu_id": gpu.get("gpu_id"),
            "status": status,
            "temperature_c": gpu.get("temperature_c"),
            "utilization_percent": gpu.get("utilization_percent"),
            "name": gpu.get("name", ""),
        })
        all_alerts.extend(alerts)
        total_rows.append({
            "GPUID": gpu_label,
            "Total Memory (GB)": float(gpu.get("total_memory_gb") or 0.0),
        })

        if gpu.get("processes"):
            for proc in gpu["processes"]:
                raw_user = proc.get("username", "Unknown")
                kind = proc.get("kind", "process")
                user = "ZombieProcess" if kind == "zombie" else user_map.get(raw_user, raw_user)
                key = str(proc.get("pid", "")) + ("#zombie" if kind == "zombie" else "")
                health, reason_key, reason_params = process_health.get(key, ("Healthy", "reason_normal", {}))
                process_rows.append({
                    "GPUID": gpu_label,
                    "PID": str(proc.get("pid", "")),
                    "User": user,
                    "Username": raw_user,
                    "Memory Used (GB)": float(proc.get("memory_gb") or 0.0),
                    "Start Time": str(proc.get("start_time", "-")),
                    "Duration": str(proc.get("duration", "-")),
                    "Kind": kind,
                    "HealthCode": health,
                    "Health": _tr("status_%s" % health, lang),
                    "Health Reason": _tr(reason_key, lang, **reason_params),
                    "GPU Utilization (%)": gpu.get("utilization_percent"),
                    "Temperature (C)": gpu.get("temperature_c"),
                })
        else:
            process_rows.append({
                "GPUID": gpu_label,
                "PID": "None",
                "User": "NoUser",
                "Username": "NoUser",
                "Memory Used (GB)": 0.0,
                "Start Time": "-",
                "Duration": "-",
                "Kind": "idle",
                "HealthCode": "Idle",
                "Health": _tr("status_Idle", lang),
                "Health Reason": _tr("reason_idle", lang),
                "GPU Utilization (%)": gpu.get("utilization_percent"),
                "Temperature (C)": gpu.get("temperature_c"),
            })

    if not total_rows:
        return None, all_alerts, gpu_statuses

    df = pd.DataFrame(process_rows)
    df_total = pd.DataFrame(total_rows)
    gpu_bar_width = int(chart_cfg.get("gpu_bar_width", 44))
    bars = alt.Chart(df).mark_bar(size=gpu_bar_width).encode(
        x=alt.X(
            "GPUID:N",
            axis=alt.Axis(title=None, labelAngle=0, labelLimit=80, labelPadding=6),
        ),
        y=alt.Y("Memory Used (GB):Q", title=_tr("axis_gpu_y", lang), stack="zero"),
        color=alt.condition(
            alt.datum.Kind == "zombie",
            alt.value("purple"),
            alt.Color("User:N", legend=alt.Legend(title=_tr("legend_user", lang))),
        ),
        stroke=alt.condition(
            "datum.HealthCode === 'Warning' || datum.HealthCode === 'Critical'",
            alt.value("#f59e0b"),
            alt.value("transparent"),
        ),
        strokeWidth=alt.condition(
            "datum.HealthCode === 'Warning' || datum.HealthCode === 'Critical'",
            alt.value(3),
            alt.value(0),
        ),
        tooltip=[
            alt.Tooltip("PID:N", title=_tr("tooltip_pid", lang)),
            alt.Tooltip("Username:N", title=_tr("tooltip_username", lang)),
            alt.Tooltip("User:N", title=_tr("tooltip_user", lang)),
            alt.Tooltip("Memory Used (GB):Q", title=_tr("tooltip_memory_used", lang), format=".2f"),
            alt.Tooltip("Health:N", title=_tr("tooltip_health", lang)),
            alt.Tooltip("Health Reason:N", title=_tr("tooltip_health_reason", lang)),
            alt.Tooltip("GPU Utilization (%):Q", title=_tr("tooltip_gpu_util", lang), format=".0f"),
            alt.Tooltip("Temperature (C):Q", title=_tr("tooltip_temperature", lang), format=".0f"),
            alt.Tooltip("Start Time:N", title=_tr("tooltip_start_time", lang)),
            alt.Tooltip("Duration:N", title=_tr("tooltip_duration", lang)),
        ],
    )
    total_marks = (
        alt.Chart(df_total)
        .mark_tick(color="red", thickness=3, size=max(30, gpu_bar_width + 6))
        .encode(
            x=alt.X("GPUID:N", axis=None),
            y=alt.Y("Total Memory (GB):Q"),
            tooltip=[alt.Tooltip("Total Memory (GB):Q", title=_tr("tooltip_total_memory", lang), format=".1f")],
        )
    )
    chart = (
        (bars + total_marks)
        .properties(width=560, height=int(chart_cfg.get("plot_height", 360)))
        .configure_axis(labelFontSize=13, titleFontSize=18)
    )
    return chart, all_alerts, gpu_statuses

def _extract_vega_scripts():
    dummy = alt.Chart(pd.DataFrame({"x": [1], "y": [1]})).mark_point().encode(x="x:Q", y="y:Q")
    try:
        sample = dummy.to_html()
        urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', sample)
        vega = next((u for u in urls if "vega@" in u and "vega-lite" not in u and "vega-embed" not in u), None)
        vl = next((u for u in urls if "vega-lite" in u), None)
        embed = next((u for u in urls if "vega-embed" in u), None)
        if vega and vl and embed:
            return vega, vl, embed
    except Exception:
        pass
    return (
        "https://cdn.jsdelivr.net/npm/vega@5",
        "https://cdn.jsdelivr.net/npm/vega-lite@5",
        "https://cdn.jsdelivr.net/npm/vega-embed@6",
    )


_VEGA_SCRIPT_URLS_CACHE = None


def get_vega_script_urls():
    """Return Vega browser dependencies matching the installed Altair version."""
    global _VEGA_SCRIPT_URLS_CACHE
    if _VEGA_SCRIPT_URLS_CACHE is None:
        _VEGA_SCRIPT_URLS_CACHE = _extract_vega_scripts()
    return _VEGA_SCRIPT_URLS_CACHE


def _overall_status(gpu_statuses, host_error=None):
    if host_error or not gpu_statuses:
        return "Unknown"
    return max((x.get("status", "Unknown") for x in gpu_statuses), key=_health_rank)


def _alert_html(alert):
    severity = alert.get("severity", "Warning")
    cls = "critical" if severity == "Critical" else "warning"
    user = html.escape(str(alert.get("user", "-")))
    pid = html.escape(str(alert.get("pid", "-")))
    gpu_id = html.escape(str(alert.get("gpu_id", "?")))
    reason = _i18n_span(alert.get("reason_key", "reason_normal"), alert.get("reason_params", {}))
    return '<div class="health-alert %s"><strong>%s GPU %s</strong> · %s · PID %s — %s</div>' % (
        cls, "⛔" if severity == "Critical" else "⚠", gpu_id, user, pid, reason
    )


def build_dashboard_html(cache, settings, user_map, aliases):
    hosts = ordered_hosts(settings)
    specs_by_lang = {"ja": {}, "zh": {}, "en": {}}
    host_sections = []
    global_counts = {"Healthy": 0, "Idle": 0, "Warning": 0, "Critical": 0, "Unknown": 0}

    for idx, host in enumerate(hosts):
        host_data = cache.get("data", {}).get(host, {})
        host_error = host_data.get("error") or host_data.get("refresh_error")

        # Japanese pass also supplies language-independent alerts/statuses.
        cpu_ja = _cpu_chart(host_data, user_map, aliases, "ja", settings)
        gpu_ja, alerts, gpu_statuses = _gpu_chart(host_data, user_map, settings, "ja")
        overall = _overall_status(gpu_statuses, host_error)
        global_counts[overall] = global_counts.get(overall, 0) + 1

        cpu_id = "cpu_%d" % idx
        gpu_id = "gpu_%d" % idx
        if cpu_ja is not None:
            specs_by_lang["ja"][cpu_id] = cpu_ja.to_dict()
        if gpu_ja is not None:
            specs_by_lang["ja"][gpu_id] = gpu_ja.to_dict()

        for lang in ("zh", "en"):
            cpu_chart = _cpu_chart(host_data, user_map, aliases, lang, settings)
            gpu_chart, _, _ = _gpu_chart(host_data, user_map, settings, lang)
            if cpu_chart is not None:
                specs_by_lang[lang][cpu_id] = cpu_chart.to_dict()
            if gpu_chart is not None:
                specs_by_lang[lang][gpu_id] = gpu_chart.to_dict()

        alert_block = "".join(_alert_html(a) for a in alerts)
        if host_error:
            alert_block = '<div class="health-alert critical"><strong>%s</strong> — %s</div>' % (
                _i18n_span("refresh_error"), html.escape(str(host_error))
            ) + alert_block
        if not alert_block:
            alert_block = '<div class="health-ok">%s</div>' % _i18n_span("health_ok")

        gpu_badges = []
        for s in gpu_statuses:
            badge_status = s.get("status", "Unknown")
            temp = s.get("temperature_c")
            util = s.get("utilization_percent")
            details = []
            if util is not None:
                details.append("%.0f%%" % float(util))
            if temp is not None:
                details.append("%.0f°C" % float(temp))
            suffix = " " + "/".join(details) if details else ""
            gpu_badges.append(
                '<span class="gpu-badge %s">GPU %s %s%s</span>' % (
                    badge_status.lower(),
                    html.escape(str(s.get("gpu_id", "?"))),
                    _i18n_span("status_%s" % badge_status),
                    html.escape(suffix),
                )
            )

        host_sections.append(
            '''<section class="host-section">
<div class="host-title-row"><div class="host-title">{host}</div><span class="status-badge {status_cls}">{status_text}</span></div>
<div class="gpu-badges">{gpu_badges}</div>
<div class="health-alerts">{alerts}</div>
<div class="chart-grid">
  <div class="chart-panel"><div class="panel-title">{cpu_title}</div><div id="{cpu_id}" class="chart-target" data-has-chart="{cpu_has_chart}">{cpu_fallback}</div><div class="axis-title">{cpu_axis_title}</div></div>
  <div class="chart-panel"><div class="panel-title">{gpu_title}</div><div id="{gpu_id}" class="chart-target" data-has-chart="{gpu_has_chart}">{gpu_fallback}</div><div class="axis-title">{gpu_axis_title}</div></div>
</div>
</section>'''.format(
                host=html.escape(host),
                status_cls=overall.lower(),
                status_text=_i18n_span("status_%s" % overall),
                gpu_badges="".join(gpu_badges),
                alerts=alert_block,
                cpu_title=_i18n_span("panel_cpu_memory"),
                gpu_title=_i18n_span("panel_gpu_memory_health"),
                cpu_id=cpu_id,
                gpu_id=gpu_id,
                cpu_has_chart="1" if cpu_ja is not None else "0",
                gpu_has_chart="1" if gpu_ja is not None else "0",
                cpu_axis_title=_i18n_span("axis_cpu_x"),
                gpu_axis_title=_i18n_span("axis_gpu_x"),
                cpu_fallback="" if cpu_ja is not None else _i18n_span("empty_cpu"),
                gpu_fallback="" if gpu_ja is not None else _i18n_span("empty_gpu"),
            )
        )

    version = "%d" % time.time_ns()
    health_cfg = settings.get("gpu_health", {})
    health_params = {
        "minutes": "%.0f" % float(health_cfg.get("min_runtime_minutes", 10)),
        "warning": "%.2f" % float(health_cfg.get("warning_memory_gb", 1.0)),
        "critical": "%.2f" % float(health_cfg.get("critical_memory_gb", 0.2)),
    }
    counts_html = " · ".join(
        "%s %d" % (_i18n_span("status_%s" % key), global_counts.get(key, 0))
        for key in ("Healthy", "Idle", "Warning", "Critical", "Unknown")
    )
    translations_json = json.dumps(TRANSLATIONS, ensure_ascii=False).replace("</", "<\\/")
    contact = settings.get("contact_username", "chwang")
    chart_cfg = settings.get("charts", {})
    # Vega must execute inside the same iframe/document as the charts.  Calling a
    # vegaEmbed function from the parent iframe renders the SVG but makes HTML
    # tooltips belong to the parent document, so their coordinates drift for
    # charts further down the page.  Deferred scripts download in parallel while
    # still executing in dependency order inside this dashboard document.
    vega_url, vega_lite_url, vega_embed_url = get_vega_script_urls()

    page = r'''<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<link rel="preconnect" href="https://cdn.jsdelivr.net" crossorigin>
<script defer crossorigin="anonymous" src="{vega_url}"></script>
<script defer crossorigin="anonymous" src="{vega_lite_url}"></script>
<script defer crossorigin="anonymous" src="{vega_embed_url}"></script>
<style>
:root{{color-scheme:light}}*{{box-sizing:border-box}}body{{margin:0;padding:0 4px;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#1f2937;background:white}}
.page-title{{font-size:25px;font-weight:700;margin:5px 0 8px}}.summary{{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;padding:8px 2px 14px;border-bottom:1px solid #e5e7eb;margin-bottom:10px}}
.summary strong{{font-size:15px}}.summary .muted{{color:#6b7280;font-size:13px;margin-top:4px;max-width:760px}}.online-badge{{display:inline-block;margin-left:8px;border:1px solid #bfdbfe;background:#eff6ff;color:#1d4ed8;border-radius:999px;padding:2px 7px;font-size:11px}}
.legend-row{{display:flex;flex-wrap:wrap;gap:8px 14px;align-items:center;padding:0 2px 8px;font-size:12px;color:#4b5563}}.legend-line{{display:inline-block;width:18px;border-top:3px solid red;vertical-align:middle;margin-right:5px}}.legend-box{{display:inline-block;width:12px;height:12px;vertical-align:middle;margin-right:5px;border-radius:2px}}
.host-section{{padding:14px 0 22px;border-bottom:1px solid #d1d5db}}.host-title-row{{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:6px}}.host-title{{font-size:32px;font-weight:650}}
.status-badge,.gpu-badge{{display:inline-block;border-radius:999px;padding:4px 9px;font-size:12px;font-weight:650;border:1px solid #d1d5db}}.healthy{{background:#ecfdf5;color:#065f46;border-color:#a7f3d0}}.idle{{background:#f3f4f6;color:#4b5563}}.warning{{background:#fff7ed;color:#9a3412;border-color:#fdba74}}.critical{{background:#fef2f2;color:#991b1b;border-color:#fca5a5}}.unknown{{background:#f3f4f6;color:#374151}}
.gpu-badges{{display:flex;flex-wrap:wrap;gap:6px;margin:6px 0 8px}}.health-alerts{{margin:6px 0 10px}}.health-alert{{border-left:5px solid #f59e0b;background:#fff7ed;padding:8px 10px;margin:5px 0;font-size:14px}}.health-alert.critical{{border-left-color:#dc2626;background:#fef2f2;color:#7f1d1d}}.health-ok{{color:#047857;font-size:13px;margin:6px 0 10px}}
.chart-grid{{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:18px;align-items:start}}.chart-panel{{min-width:0}}.panel-title{{font-size:14px;font-weight:650;color:#4b5563;margin-bottom:4px}}.chart-target{{height:{chart_container_height}px;min-height:{chart_container_height}px;width:100%;overflow:hidden}}.axis-title{{height:28px;line-height:22px;text-align:center;font-size:18px;font-weight:500;color:#333;padding-top:2px}}.vega-embed{{width:100%}}.vega-embed>div{{width:100%}}.chart-error{{color:#b91c1c;padding:12px}}
.contact{{padding:14px 2px;color:#6b7280;font-size:12px}}@media(max-width:900px){{.chart-grid{{grid-template-columns:1fr}}.host-title{{font-size:26px}}.summary{{flex-direction:column}}}}
</style></head><body>
<h1 class="page-title" data-i18n-key="title">{title}</h1>
<div class="summary"><div><strong data-i18n-key="server_data" data-i18n-params="{server_params}">{server_data}</strong><span class="online-badge" data-i18n-key="online_badge">{online_badge}</span><div class="muted">{counts}</div></div><div class="muted" data-i18n-key="health_note" data-i18n-params="{health_params_attr}">{health_note}</div></div>
<div class="legend-row"><span><span class="legend-box" style="background:purple"></span><span data-i18n-key="legend_zombie">{legend_zombie}</span></span><span><span class="legend-box" style="background:#fff7ed;border:2px solid #f59e0b"></span><span data-i18n-key="legend_warning">{legend_warning}</span></span><span><span class="legend-box" style="background:#fef2f2;border:2px solid #dc2626"></span><span data-i18n-key="legend_critical">{legend_critical}</span></span><span><span class="legend-line"></span><span data-i18n-key="legend_total">{legend_total}</span></span></div>
{sections}
<div class="contact" data-i18n-key="contact" data-i18n-params="{contact_params}">{contact_text}</div>
<script>
const DASHBOARD_VERSION={version_json};
const I18N={translations_json};
const LAZY_MARGIN={lazy_margin};
const INITIAL_RENDER_CHARTS={initial_render_charts};
const PROGRESSIVE_BATCH_SIZE={progressive_batch_size};
const PROGRESSIVE_DELAY_MS={progressive_delay_ms};
let currentLanguage='ja';
let initialized=false;
let firstLanguageApplied=false;
let startupRenderStarted=false;
let specsCache={{}};
let specsPromiseCache={{}};
let observer=null;
let visibleTargets=new Set();
let renderToken=0;
let languageReceived=false;

function tr(k,p={{}}){{let s=(I18N[currentLanguage]&&I18N[currentLanguage][k])||(I18N.ja&&I18N.ja[k])||k;Object.entries(p||{{}}).forEach(([a,b])=>{{s=s.split('{{'+a+'}}').join(String(b))}});return s;}}
function paramsOf(el){{try{{return JSON.parse(el.dataset.i18nParams||'{{}}')}}catch(e){{return {{}}}}}}
function translateDOM(){{document.documentElement.lang=currentLanguage==='zh'?'zh-CN':currentLanguage==='en'?'en':'ja';document.title=tr('title');document.querySelectorAll('[data-i18n-key]').forEach(el=>{{el.textContent=tr(el.dataset.i18nKey,paramsOf(el));}});}}
function sendHeight(){{const h=Math.max(document.body.scrollHeight,document.documentElement.scrollHeight)+12;try{{window.parent.postMessage({{type:'morilab-dashboard-height',height:h}},'*')}}catch(e){{}}}}
async function fetchSpecs(lang){{
  if(specsCache[lang])return specsCache[lang];
  // Several charts are requested together on first paint. Share one in-flight
  // JSON request instead of downloading the same (potentially large) language
  // spec once per chart.
  if(specsPromiseCache[lang])return specsPromiseCache[lang];
  specsPromiseCache[lang]=(async()=>{{
    const name='dashboard_specs_'+lang+'.json?v='+encodeURIComponent(String(DASHBOARD_VERSION));
    const paths=['/app/static/'+name,'app/static/'+name];let last=null;
    for(const p of paths){{try{{const r=await fetch(p,{{cache:'force-cache'}});if(!r.ok)throw new Error('HTTP '+r.status);const data=await r.json();specsCache[lang]=data||{{}};return specsCache[lang];}}catch(e){{last=e}}}}
    throw last||new Error('spec fetch failed');
  }})();
  try{{return await specsPromiseCache[lang];}}
  finally{{delete specsPromiseCache[lang];}}
}}
async function waitForVegaEmbed(timeoutMs=25000){{
  const start=Date.now();
  while(Date.now()-start<timeoutMs){{
    // IMPORTANT: use the Vega instance from this dashboard iframe.  This keeps
    // Vega Tooltip in the same document and preserves correct pointer coordinates
    // for charts far down the page.
    if(typeof window.vegaEmbed==='function')return window.vegaEmbed;
    await new Promise(r=>setTimeout(r,50));
  }}
  throw new Error('Vega libraries are not ready after '+Math.round(timeoutMs/1000)+' s');
}}
async function renderTarget(el,force=false,token=renderToken){{
  if(!el||el.dataset.hasChart!=='1')return;
  if(!force&&el.dataset.renderLang===currentLanguage&&el.childElementCount>0)return;
  const lang=currentLanguage;
  try{{
    const specs=await fetchSpecs(lang);if(token!==renderToken||lang!==currentLanguage)return;
    const spec=specs[el.id];if(!spec)return;
    el.innerHTML='';
    const embedFn=await waitForVegaEmbed();
    await embedFn(el,spec,{{actions:false,renderer:'svg'}});
    if(token!==renderToken||lang!==currentLanguage)return;
    el.dataset.renderLang=lang;
  }}catch(err){{el.innerHTML='<div class="chart-error">'+tr('chart_error')+': '+String(err)+'</div>';}}
  initialized=true;sendHeight();
}}
function allChartTargets(){{return [...document.querySelectorAll('.chart-target[data-has-chart="1"]')];}}
let progressiveQueue=[];
let progressiveScheduled=false;

function rebuildProgressiveQueue(){{
  progressiveQueue=allChartTargets().filter(el=>!(el.dataset.renderLang===currentLanguage&&el.childElementCount>0));
}}
function renderInitial(force=false){{
  const token=renderToken;
  const targets=allChartTargets();
  // Always make the top of the page useful first. This is intentionally based on
  // DOM order rather than IntersectionObserver because the nested iframe expands
  // to the whole dashboard and can otherwise make every chart appear "visible".
  targets.slice(0,INITIAL_RENDER_CHARTS).forEach(el=>renderTarget(el,force,token));
}}
function scheduleProgressive(){{
  if(progressiveScheduled||!progressiveQueue.length)return;
  progressiveScheduled=true;
  const runBatch=(deadline)=>{{
    progressiveScheduled=false;
    const token=renderToken;
    let count=0;
    while(progressiveQueue.length&&count<PROGRESSIVE_BATCH_SIZE){{
      if(deadline&&count>0&&deadline.timeRemaining&&deadline.timeRemaining()<4)break;
      const el=progressiveQueue.shift();
      renderTarget(el,false,token);
      count++;
    }}
    if(progressiveQueue.length){{
      if('requestIdleCallback' in window){{
        window.requestIdleCallback(runBatch,{{timeout:700}});
        progressiveScheduled=true;
      }}else{{
        progressiveScheduled=true;
        setTimeout(()=>runBatch(null),PROGRESSIVE_DELAY_MS);
      }}
    }}
  }};
  if('requestIdleCallback' in window){{
    window.requestIdleCallback(runBatch,{{timeout:500}});
  }}else{{
    setTimeout(()=>runBatch(null),PROGRESSIVE_DELAY_MS);
  }}
}}
function prioritizeUnrendered(){{
  // If the user interacts/returns while background rendering is still running,
  // keep the first charts prioritized and let the rest continue incrementally.
  renderInitial(false);
  rebuildProgressiveQueue();
  scheduleProgressive();
}}
function setupLazyRendering(){{
  renderInitial(false);
  rebuildProgressiveQueue();
  // Remove the charts already requested by renderInitial from the queue.
  progressiveQueue=progressiveQueue.slice(INITIAL_RENDER_CHARTS);
  scheduleProgressive();
}}
async function applyLanguage(lang){{
  const nextLanguage=['ja','zh','en'].includes(lang)?lang:'ja';
  languageReceived=true;

  // First language selection happens before any Vega chart is rendered.  This
  // prevents the old cold-start path from drawing Japanese charts first and then
  // immediately drawing the same charts again when the parent sends "ja".
  if(!firstLanguageApplied){{
    firstLanguageApplied=true;
    currentLanguage=nextLanguage;
    translateDOM();
    await fetchSpecs(currentLanguage).catch(()=>{{}});
    if(!startupRenderStarted){{
      startupRenderStarted=true;
      setupLazyRendering();
    }}
    sendHeight();
    return;
  }}

  // The parent can legitimately send the currently selected language more than
  // once during iframe lifecycle events.  A same-language message must be a no-op;
  // forcing a re-render here used to duplicate dozens of Vega renders at startup.
  if(nextLanguage===currentLanguage){{
    translateDOM();
    sendHeight();
    return;
  }}

  currentLanguage=nextLanguage;
  translateDOM();
  renderToken++;
  await fetchSpecs(currentLanguage).catch(()=>{{}});
  // Real language change: re-render charts that already exist, then progressively
  // fill the rest using the newly selected language spec.
  const token=renderToken;
  allChartTargets().filter(el=>el.childElementCount>0).forEach(el=>renderTarget(el,true,token));
  renderInitial(true);
  rebuildProgressiveQueue();
  progressiveQueue=progressiveQueue.filter(el=>el.childElementCount===0||el.dataset.renderLang!==currentLanguage);
  scheduleProgressive();
  sendHeight();
}}
function requestLanguage(){{try{{window.parent.postMessage({{type:'morilab-dashboard-ready',version:String(DASHBOARD_VERSION)}},'*')}}catch(e){{}}}}
window.addEventListener('message',e=>{{const d=e.data||{{}};if(d.type==='morilab-set-language'){{applyLanguage(d.lang);}}}});
document.addEventListener('visibilitychange',()=>{{if(!document.hidden&&startupRenderStarted){{prioritizeUnrendered();sendHeight();}}}});
window.addEventListener('pageshow',()=>{{if(startupRenderStarted){{prioritizeUnrendered();sendHeight();}}}});
if(window.ResizeObserver)new ResizeObserver(sendHeight).observe(document.body);
translateDOM();requestLanguage();setTimeout(()=>{{if(!firstLanguageApplied)applyLanguage('ja');}},500);
</script></body></html>'''.format(
        title=html.escape(_tr("title")),
        server_params=_i18n_params_attr({"updated": str(cache.get("updated_at", "Unknown"))}),
        server_data=html.escape(_tr("server_data", updated=str(cache.get("updated_at", "Unknown")))),
        online_badge=html.escape(_tr("online_badge")),
        counts=counts_html,
        health_params_attr=_i18n_params_attr(health_params),
        health_note=html.escape(_tr("health_note", **health_params)),
        legend_zombie=html.escape(_tr("legend_zombie")),
        legend_warning=html.escape(_tr("legend_warning")),
        legend_critical=html.escape(_tr("legend_critical")),
        legend_total=html.escape(_tr("legend_total")),
        sections="".join(host_sections),
        contact_params=_i18n_params_attr({"contact": contact}),
        contact_text=html.escape(_tr("contact", contact=contact)),
        version_json=json.dumps(version),
        translations_json=translations_json,
        chart_container_height=int(chart_cfg.get("chart_container_height", 450)),
        lazy_margin=int(chart_cfg.get("lazy_render_margin_px", 900)),
        initial_render_charts=int(chart_cfg.get("initial_render_charts", 6)),
        progressive_batch_size=int(chart_cfg.get("progressive_batch_size", 4)),
        progressive_delay_ms=int(chart_cfg.get("progressive_delay_ms", 60)),
        vega_url=html.escape(vega_url, quote=True),
        vega_lite_url=html.escape(vega_lite_url, quote=True),
        vega_embed_url=html.escape(vega_embed_url, quote=True),
    )
    return page, version, global_counts, specs_by_lang


def publish_dashboard(cache, settings, user_map, aliases):
    page, version, counts, specs_by_lang = build_dashboard_html(cache, settings, user_map, aliases)
    # Specs are separate JSON files. The browser only downloads the currently
    # selected language, and can cache it using the versioned URL.
    for lang, spec_payload in specs_by_lang.items():
        atomic_write_json(DASHBOARD_SPECS_FILES[lang], spec_payload)
    atomic_write_text(DASHBOARD_FILE, page)
    atomic_write_json(DASHBOARD_VERSION_FILE, {
        "version": version,
        "server_data_updated_at": cache.get("updated_at"),
        "published_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "counts": counts,
    })
    return version


def create_placeholder_dashboard(settings, message_key):
    if message_key not in TRANSLATIONS["ja"]:
        message_key = "placeholder_first_scan"
    version = "%d" % time.time_ns()
    translations_json = json.dumps(TRANSLATIONS, ensure_ascii=False).replace("</", "<\\/")
    page = r'''<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:0;padding:20px;color:#374151}}.box{{border:1px solid #d1d5db;border-radius:10px;padding:18px;background:#f9fafb}}</style></head><body><div class="box"><strong>GPU Monitor</strong><p data-i18n-key="{message_key}">{message}</p><p data-i18n-key="placeholder_wait">{wait}</p></div><script>const I18N={translations_json};let L='ja';function t(k){{return(I18N[L]&&I18N[L][k])||(I18N.ja&&I18N.ja[k])||k}}function a(v){{L=['ja','zh','en'].includes(v)?v:'ja';document.querySelectorAll('[data-i18n-key]').forEach(e=>e.textContent=t(e.dataset.i18nKey));try{{parent.postMessage({{type:'morilab-dashboard-height',height:document.body.scrollHeight+20}},'*')}}catch(e){{}}}}addEventListener('message',e=>{{if((e.data||{{}}).type==='morilab-set-language')a(e.data.lang)}});try{{parent.postMessage({{type:'morilab-dashboard-ready',version:{version_json}}},'*')}}catch(e){{}}setTimeout(()=>a('ja'),120);</script></body></html>'''.format(
        message_key=html.escape(message_key, quote=True),
        message=html.escape(_tr(message_key)),
        wait=html.escape(_tr("placeholder_wait")),
        translations_json=translations_json,
        version_json=json.dumps(version),
    )
    atomic_write_text(DASHBOARD_FILE, page)
    atomic_write_json(DASHBOARD_VERSION_FILE, {
        "version": version,
        "published_at": datetime.now().astimezone().isoformat(timespec="seconds"),
    })


def acquire_collector_lock():
    lock_file = COLLECTOR_LOCK_FILE.open("a+", encoding="utf-8")
    if fcntl is not None:
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, OSError):
            lock_file.close()
            return None
    return lock_file
