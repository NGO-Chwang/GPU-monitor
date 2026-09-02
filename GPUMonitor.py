import csv
import json
import os
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

import streamlit as st
import streamlit.components.v1 as components

try:
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None

from monitor_common import CONFIG_DIR, DATA_DIR, TRANSLATIONS, get_vega_script_urls, load_settings


st.set_page_config(layout="wide", page_title="Morilab GPU Monitor")

VISITOR_LOG_FILE = DATA_DIR / "visitor_log.csv"
VISITOR_STATS_FILE = DATA_DIR / "visitor_stats.json"
VISITOR_LOCK_FILE = DATA_DIR / ".visitor_stats.lock"
_thread_visitor_lock = threading.Lock()


@contextmanager
def file_lock(lock_path):
    lock_path = Path(lock_path)
    with lock_path.open("a+", encoding="utf-8") as lock_file:
        if fcntl is not None:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _safe_context_attr(name, default=""):
    try:
        context = getattr(st, "context", None)
        if context is None:
            return default
        value = getattr(context, name, default)
        return default if value is None else str(value)
    except Exception:
        return default


def _normalize_ip(value):
    if value is None:
        return ""
    value = str(value).strip()
    if not value or value.lower() in {"none", "unknown"}:
        return ""
    # IPv4-mapped IPv6 is common on dual-stack hosts. Store the readable IPv4.
    if value.startswith("::ffff:") and value.count(":") == 3:
        value = value[7:]
    return value


def _get_ip_from_streamlit_session():
    """Best-effort fallback for Streamlit versions before st.context.ip_address.

    Streamlit 1.39 exposes request headers through st.context but does not expose
    the peer IP. The WebSocket handler still has Tornado's request.remote_ip, so
    we obtain the SessionClient for this script session and read it. This uses a
    Streamlit internal compatibility path and therefore fails closed to "" if a
    future version changes the implementation.
    """
    try:
        try:
            from streamlit.runtime.scriptrunner import get_script_run_ctx
        except ImportError:
            from streamlit.runtime.scriptrunner.script_run_context import get_script_run_ctx

        ctx = get_script_run_ctx(suppress_warning=True)
        if ctx is None:
            return ""

        from streamlit.runtime.runtime import Runtime

        runtime = Runtime.instance()
        client = None

        # Prefer Runtime.get_client when the installed Streamlit provides it.
        getter = getattr(runtime, "get_client", None)
        if callable(getter):
            client = getter(ctx.session_id)

        # Compatibility with older Streamlit runtimes.
        if client is None:
            session_mgr = getattr(runtime, "_session_mgr", None)
            if session_mgr is not None:
                get_info = getattr(session_mgr, "get_active_session_info", None)
                if callable(get_info):
                    info = get_info(ctx.session_id)
                    client = getattr(info, "client", None) if info is not None else None

        if client is None:
            return ""

        # BrowserWebSocketHandler is the normal SessionClient. Tornado stores the
        # connected peer on handler.request.remote_ip. Keep a few conservative
        # attribute fallbacks because Streamlit has renamed internals over time.
        candidates = [
            getattr(client, "request", None),
            getattr(client, "_request", None),
        ]
        websocket = getattr(client, "_ws", None) or getattr(client, "ws_connection", None)
        if websocket is not None:
            candidates.append(getattr(websocket, "request", None))

        for request in candidates:
            ip = _normalize_ip(getattr(request, "remote_ip", "") if request is not None else "")
            if ip:
                return ip
    except Exception:
        pass
    return ""


def _header_value(headers, *names):
    for name in names:
        value = headers.get(name)
        if value:
            return str(value).strip()
    return ""


def get_client_info(settings):
    headers = {}
    try:
        context = getattr(st, "context", None)
        if context is not None:
            headers = dict(context.headers)
    except Exception:
        headers = {}

    # If a trusted reverse proxy is in front of Streamlit, the original client
    # address should come from the proxy headers. Never trust these by default.
    ip = ""
    if settings.get("trust_proxy_headers", False):
        forwarded_for = _header_value(headers, "X-Forwarded-For", "x-forwarded-for")
        if forwarded_for:
            ip = _normalize_ip(forwarded_for.split(",")[0])
        if not ip:
            ip = _normalize_ip(_header_value(
                headers,
                "X-Real-IP", "x-real-ip",
                "CF-Connecting-IP", "cf-connecting-ip",
                "True-Client-IP", "true-client-ip",
            ))

    # Newer Streamlit versions provide this official API. It does not exist in
    # 1.39.1, so _safe_context_attr simply returns an empty string there.
    if not ip:
        ip = _normalize_ip(_safe_context_attr("ip_address", ""))

    # Streamlit 1.39 compatibility: read Tornado's WebSocket peer address.
    if not ip:
        ip = _get_ip_from_streamlit_session()

    return {
        "ip": ip or "unknown",
        "user_agent": _header_value(headers, "User-Agent", "user-agent"),
        # locale/timezone/url were added to st.context after 1.39. Accept-Language
        # remains useful on 1.39; timezone and URL will stay blank on that version.
        "locale": _safe_context_attr("locale", _header_value(headers, "Accept-Language", "accept-language")),
        "timezone": _safe_context_attr("timezone", ""),
        "url": _safe_context_attr("url", ""),
    }


def log_visitor_once(settings):
    if not settings.get("visitor_logging_enabled", True):
        return
    if st.session_state.get("_visitor_logged", False):
        return

    now = datetime.now().astimezone()
    info = get_client_info(settings)
    row = {"timestamp": now.isoformat(timespec="seconds"), "date": now.date().isoformat(), **info}

    with _thread_visitor_lock:
        with file_lock(VISITOR_LOCK_FILE):
            exists = VISITOR_LOG_FILE.exists()
            with VISITOR_LOG_FILE.open("a", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=["timestamp", "date", "ip", "user_agent", "locale", "timezone", "url"],
                )
                if not exists:
                    writer.writeheader()
                writer.writerow(row)
            try:
                os.chmod(str(VISITOR_LOG_FILE), 0o600)
            except OSError:
                pass

            try:
                with VISITOR_STATS_FILE.open("r", encoding="utf-8") as f:
                    stats = json.load(f)
            except Exception:
                stats = {}
            day = stats.setdefault(row["date"], {
                "total_sessions": 0,
                "unique_ips": 0,
                "ips": {},
                "first_visit": row["timestamp"],
                "last_visit": row["timestamp"],
            })
            day["total_sessions"] += 1
            day["ips"][row["ip"]] = day["ips"].get(row["ip"], 0) + 1
            day["unique_ips"] = len([ip_addr for ip_addr in day["ips"] if ip_addr != "unknown"])
            day["last_visit"] = row["timestamp"]
            tmp = VISITOR_STATS_FILE.with_name(VISITOR_STATS_FILE.name + ".tmp")
            with tmp.open("w", encoding="utf-8") as f:
                json.dump(stats, f, ensure_ascii=False, indent=2)
            os.replace(str(tmp), str(VISITOR_STATS_FILE))
            try:
                os.chmod(str(VISITOR_STATS_FILE), 0o600)
            except OSError:
                pass

    st.session_state["_visitor_logged"] = True


settings = load_settings()
log_visitor_once(settings)

# This outer loader stays alive. It never uses document.write() to replace itself.
# Cached dashboard HTML is placed in a child iframe through srcdoc. When a browser
# tab returns from the background, the loader force-reloads the cached dashboard,
# which also forces Vega to rebuild the SVG charts and their tooltips.
loader_i18n = {
    lang: {k: values[k] for k in ("language", "loading_cache", "load_failed", "load_hint")}
    for lang, values in TRANSLATIONS.items()
}
loader_i18n_json = json.dumps(loader_i18n, ensure_ascii=False).replace("</", "<\\/")
check_ms = int(settings.get("dashboard_check_seconds", 5)) * 1000
vega_urls_json = json.dumps(list(get_vega_script_urls()), ensure_ascii=False).replace("</", "<\\/")

loader_html = r'''
<link rel="preconnect" href="https://cdn.jsdelivr.net" crossorigin>
<link rel="dns-prefetch" href="//cdn.jsdelivr.net">
<style>
*{box-sizing:border-box}body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:white;color:#1f2937}
.toolbar{display:flex;justify-content:flex-end;align-items:center;gap:8px;padding:0 4px 7px;color:#4b5563;font-size:13px}
.toolbar select{border:1px solid #d1d5db;border-radius:7px;padding:5px 8px;background:white;color:#1f2937}
#loading{padding:18px 8px;color:#4b5563}#dashboard-frame{display:block;width:100%;border:0;min-height:500px;background:white}
</style>
<div class="toolbar"><span id="lang-label">言語</span><select id="language-select"><option value="ja">日本語</option><option value="zh">中文</option><option value="en">English</option></select></div>
<div id="loading">インタラクティブ図表キャッシュを読み込んでいます……</div>
<iframe id="dashboard-frame" title="Morilab GPU Monitor"></iframe>
<script>
const I18N=__I18N__;
const CHECK_MS=__CHECK_MS__;
const VEGA_URLS=__VEGA_URLS__;
const LANG_KEY='morilab_gpu_monitor_language';
function preloadScripts(urls){
  urls.forEach(src=>{try{const l=document.createElement('link');l.rel='preload';l.as='script';l.href=src;l.crossOrigin='anonymous';document.head.appendChild(l);}catch(e){}});
}
// Only PRELOAD Vega here.  The libraries execute inside dashboard-frame itself.
// That is required for Vega Tooltip: tooltip HTML and chart SVG must share the
// same document, otherwise lower-page tooltip coordinates are incorrect.
preloadScripts(VEGA_URLS);
const frame=document.getElementById('dashboard-frame');
const loading=document.getElementById('loading');
const select=document.getElementById('language-select');
let lang='ja';
let currentVersion=null;
let cachedHtml='';
let hiddenAt=0;
let updateRunning=false;

function t(k){return(I18N[lang]&&I18N[lang][k])||(I18N.ja&&I18N.ja[k])||k}
function readLang(){
  try{const v=localStorage.getItem(LANG_KEY);if(['ja','zh','en'].includes(v))return v}catch(e){}
  try{const v=window.parent.localStorage.getItem(LANG_KEY);if(['ja','zh','en'].includes(v))return v}catch(e){}
  try{const m=document.cookie.match(/(?:^|; )morilab_gpu_monitor_language=([^;]+)/);if(m){const v=decodeURIComponent(m[1]);if(['ja','zh','en'].includes(v))return v}}catch(e){}
  return 'ja';
}
function saveLang(v){
  try{localStorage.setItem(LANG_KEY,v)}catch(e){}
  try{window.parent.localStorage.setItem(LANG_KEY,v)}catch(e){}
  try{document.cookie='morilab_gpu_monitor_language='+encodeURIComponent(v)+'; Max-Age=31536000; Path=/; SameSite=Lax'}catch(e){}
}
function applyOuterLanguage(v){
  lang=['ja','zh','en'].includes(v)?v:'ja';select.value=lang;document.getElementById('lang-label').textContent=t('language');loading.textContent=t('loading_cache');
  try{frame.contentWindow.postMessage({type:'morilab-set-language',lang},'*')}catch(e){}
}
async function fetchStatic(name,asText=false,version=null,noStore=false){
  const suffix=version!=null?'?v='+encodeURIComponent(String(version)):(noStore?'?_='+Date.now():'');
  const paths=['app/static/'+name+suffix,'/app/static/'+name+suffix];let last=null;
  for(const p of paths){try{const r=await fetch(p,{cache:noStore?'no-store':'force-cache'});if(!r.ok)throw new Error('HTTP '+r.status);return asText?await r.text():await r.json()}catch(e){last=e}}
  throw last||new Error('fetch failed');
}
function publishHtml(html){
  cachedHtml=html;loading.style.display='none';frame.style.display='block';frame.srcdoc=html;
}
async function refreshDashboard(force=false){
  if(updateRunning)return;updateRunning=true;
  try{
    const v=await fetchStatic('dashboard_version.json',false,null,true);
    const newVersion=v&&v.version!=null?String(v.version):'';
    if(force||!cachedHtml||newVersion!==currentVersion){
      const html=await fetchStatic('dashboard_cache.html',true,newVersion,false);currentVersion=newVersion;publishHtml(html);
    }else{
      try{frame.contentWindow.postMessage({type:'morilab-set-language',lang},'*')}catch(e){}
    }
  }catch(e){
    if(!cachedHtml){loading.innerHTML='<b style="color:#b91c1c">'+t('load_failed')+'</b><br>'+t('load_hint')+'<br>'+String(e||'');}
  }finally{updateRunning=false}
}
window.addEventListener('message',e=>{
  const d=e.data||{};
  if(d.type==='morilab-dashboard-ready'){
    try{frame.contentWindow.postMessage({type:'morilab-set-language',lang},'*')}catch(err){}
  }else if(d.type==='morilab-dashboard-height'){
    const h=Math.max(500,Math.min(Number(d.height)||500,50000));frame.style.height=h+'px';
    try{window.parent.postMessage({isStreamlitMessage:true,type:'streamlit:setFrameHeight',height:h+55},'*')}catch(err){}
  }
});
select.addEventListener('change',e=>{saveLang(e.target.value);applyOuterLanguage(e.target.value)});
document.addEventListener('visibilitychange',()=>{
  if(document.hidden){hiddenAt=Date.now();return}
  const away=hiddenAt?Date.now()-hiddenAt:0;hiddenAt=0;
  // Force rebuilding the child iframe after returning from another tab. This
  // avoids stale/discarded SVGs and does not wait for the background timer.
  refreshDashboard(away>3000);
});
window.addEventListener('pageshow',e=>{if(e.persisted)refreshDashboard(true)});
lang=readLang();applyOuterLanguage(lang);refreshDashboard(true);
setInterval(()=>{if(!document.hidden)refreshDashboard(false)},CHECK_MS);
</script>
'''.replace('__I18N__', loader_i18n_json).replace('__CHECK_MS__', str(check_ms)).replace('__VEGA_URLS__', vega_urls_json)

components.html(loader_html, height=1600, scrolling=True)
