"""
bsod_core.py
General Windows error checker (incl. BSOD) with:
- Event log scanning (BSOD + broader System/Application errors & warnings)
- Human-readable descriptions for stop codes and key event IDs
- Storage reliability, SMART, GPU, Windows Updates, system snapshot
- Optional timeline chart (uses matplotlib if available)
- Live monitor hooks
- Health tools (SFC/DISM/CHKDSK/MDSCHED)
- Persistent settings (settings.json)

Branding:
  APP_NAME        = "Windows Error Checker"
  DEV_SIGNATURE   = "H.Knight"
  APP_VERSION     = "0.9.1"
"""

import ctypes
import csv
import json
import os
import re
import subprocess
import sys
import threading
import importlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from textwrap import shorten

# ----------------------------
# Branding
# ----------------------------
APP_NAME = "Windows Error Checker"
DEV_SIGNATURE = "H.Knight"
APP_VERSION = "0.9.1"

# ----------------------------
# Settings & paths
# ----------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
SETTINGS_FILE = SCRIPT_DIR / "settings.json"

DEFAULT_SETTINGS = {
    "report_dir": str((SCRIPT_DIR / "ErrorChecker_Report").resolve()),
    "lookback_days": 30,
    "window_min": 15,      # correlation window for BSOD ± minutes
    "poll_seconds": 10     # live monitor polling
}

# Globals that UI reads
REPORT_DIR = Path(DEFAULT_SETTINGS["report_dir"])
REPORT_MD = REPORT_DIR / "ErrorChecker_Report.md"

def _load_settings():
    global REPORT_DIR, REPORT_MD
    if SETTINGS_FILE.exists():
        try:
            s = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
            settings = {**DEFAULT_SETTINGS, **s}
        except Exception:
            settings = DEFAULT_SETTINGS.copy()
    else:
        settings = DEFAULT_SETTINGS.copy()
        SETTINGS_FILE.write_text(json.dumps(settings, indent=2), encoding="utf-8")
    REPORT_DIR = Path(settings["report_dir"]).resolve()
    REPORT_MD = REPORT_DIR / "ErrorChecker_Report.md"
    return settings

def _save_settings(settings: dict):
    SETTINGS_FILE.write_text(json.dumps(settings, indent=2), encoding="utf-8")

SETTINGS = _load_settings()

def set_report_dir(path: Path):
    """Called by UI to relocate outputs; persists in settings.json."""
    global SETTINGS, REPORT_DIR, REPORT_MD
    REPORT_DIR = Path(path).resolve()
    REPORT_MD = REPORT_DIR / "ErrorChecker_Report.md"
    SETTINGS["report_dir"] = str(REPORT_DIR)
    _save_settings(SETTINGS)

def set_lookback_days(days: int):
    SETTINGS["lookback_days"] = max(1, int(days))
    _save_settings(SETTINGS)

def set_window_min(minutes: int):
    SETTINGS["window_min"] = max(1, int(minutes))
    _save_settings(SETTINGS)

# ----------------------------
# Config for analysis
# ----------------------------
MAX_EVENTS_PER_CATEGORY = 1000

# Event queries (LogName, ProviderName, Id list or None)
BSOD_AND_SUSPECT_QUERIES = [
    ("System", None, [1001]),  # BugCheck / WER
    ("System", "Microsoft-Windows-Kernel-Power", [41]),
    ("System", "Microsoft-Windows-WHEA-Logger", None),
    ("System", "disk", [7, 51, 153, 154]),
    ("System", "storahci", [129, 153, 154]),
    ("System", "nvme", [129, 153, 154]),
    ("System", "volmgr", [161]),
    ("System", "Ntfs", [55, 57]),
    ("System", "Display", [4101]),
    ("Setup", None, None),
]

BUGCHECK_RE = re.compile(r"bugcheck was:\s*(0x[0-9a-fA-F]+)\s*\(([^)]*)\)", re.IGNORECASE)
DUMP_RE     = re.compile(r"dump (?:was )?saved in:\s*(.+?\.dmp)", re.IGNORECASE)

BUGCHECK_INFO = {
    "0x0000000a": ("IRQL_NOT_LESS_OR_EQUAL",
                   "Kernel-mode code touched invalid memory at high IRQL. Often RAM/driver issues, unstable OC."),
    "0x0000001e": ("KMODE_EXCEPTION_NOT_HANDLED",
                   "Unhandled kernel exception. Typically buggy/old drivers or kernel extensions."),
    "0x00000050": ("PAGE_FAULT_IN_NONPAGED_AREA",
                   "Invalid memory reference in nonpaged region. RAM, disk corruption, or drivers."),
    "0x0000003b": ("SYSTEM_SERVICE_EXCEPTION",
                   "Exception in a system service. Often GPU/display, antivirus hooks, or drivers."),
    "0x0000007e": ("SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
                   "Unhandled system thread exception. Drivers or low-level software."),
    "0x0000009f": ("DRIVER_POWER_STATE_FAILURE",
                   "Driver didn’t handle power transition. Sleep/hibernate/USB/Wi-Fi drivers common."),
    "0x00000116": ("VIDEO_TDR_FAILURE",
                   "GPU Timeout Detection & Recovery. GPU driver/hardware/overheating/PSU."),
    "0x00000124": ("WHEA_UNCORRECTABLE_ERROR",
                   "Uncorrectable hardware error (CPU/VRM/RAM/PCIe). Often thermals/OC/hardware."),
}

EVENT_INFO = {
    ("Microsoft-Windows-Kernel-Power", 41): "System rebooted without clean shutdown (power loss, crash, hang).",
    ("Microsoft-Windows-WHEA-Logger", 1):  "WHEA: Machine Check Exception reported by CPU.",
    ("Microsoft-Windows-WHEA-Logger", 17): "WHEA: Corrected hardware error (cache/memory/PCIe).",
    ("Microsoft-Windows-WHEA-Logger", 18): "WHEA: Uncorrected hardware error — strong hardware suspect.",
    ("disk", 7):   "Disk: bad block detected — backup and run vendor diagnostics.",
    ("disk", 51):  "Disk: paging/IO error — cabling/driver/disk path issue.",
    ("disk", 153): "Storport: IO retries — storage is timing out (cable/port/driver).",
    ("disk", 154): "Storport: IO operation failed — serious storage fault or driver/firmware.",
    ("storahci", 129): "AHCI reset — device not responding. Cable/port/firmware.",
    ("nvme", 129):     "NVMe reset — controller timeout. Firmware/driver/thermals.",
    ("volmgr", 161):   "VolMgr: dump file creation failed — storage path unavailable at crash.",
    ("Ntfs", 55):      "NTFS: file system corruption detected.",
    ("Ntfs", 57):      "NTFS: delayed write failed — device not ready.",
    ("Display", 4101): "Display driver stopped responding and recovered (TDR).",
}

# ----------------------------
# Helpers
# ----------------------------
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def run_powershell(ps_script):
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
        capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    if completed.returncode != 0:
        raise RuntimeError(f"PowerShell error: {completed.stderr.strip()}")
    return completed.stdout

def _parse_ps_datetime(obj):
    """
    PowerShell ConvertTo-Json for DateTime often yields { 'value': '/Date(…)/', 'DateTime': 'Monday, ...' }.
    Prefer the '/Date(ms)/' numeric component.
    """
    if isinstance(obj, str):
        m = re.search(r"/Date\((\d+)\)/", obj)
        if m:
            ms = int(m.group(1))
            return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
        try:
            return datetime.fromisoformat(obj.replace("Z", "+00:00"))
        except Exception:
            return None
    if isinstance(obj, dict):
        v = obj.get("value") or ""
        m = re.search(r"/Date\((\d+)\)/", v)
        if m:
            ms = int(m.group(1))
            return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    return None

def get_events(log_name, provider_name=None, ids=None, start_time=None, max_count=MAX_EVENTS_PER_CATEGORY):
    time_filter = f"StartTime = (Get-Date '{start_time.isoformat()}')" if start_time else ""
    provider_filter = f"ProviderName = '{provider_name}'" if provider_name else ""
    id_filter = ""
    if ids:
        id_list = ",".join(str(i) for i in ids)
        id_filter = f"Id = @({id_list})"
    filter_parts = [p for p in [f"LogName = '{log_name}'", provider_filter, id_filter, time_filter] if p]
    fh = "@{" + "; ".join(filter_parts) + "}"
    ps = rf"""
$evts = Get-WinEvent -FilterHashtable {fh} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message |
  Sort-Object TimeCreated
$evts | Select-Object `
  @{{n='TimeCreatedUtc';e={{ $_.TimeCreated.ToUniversalTime() }}}},
  Id, ProviderName, LevelDisplayName, Message |
  ConvertTo-Json -Depth 4
"""
    raw = run_powershell(ps).strip()
    if not raw:
        return []
    data = json.loads(raw)
    if isinstance(data, dict):
        data = [data]

    norm = []
    for e in (data or [])[-max_count:]:
        t = _parse_ps_datetime(e.get("TimeCreatedUtc"))
        local_iso = ""
        naive_utc = None
        if t:
            local_iso = t.astimezone().strftime("%a, %d %b %Y %I:%M:%S %p %Z")
            naive_utc = t.replace(tzinfo=None)
        e["TimeDisplayLocal"] = local_iso
        e["_utc_naive"] = naive_utc
        norm.append(e)
    return norm

def parse_bugcheck_info(message):
    if not message:
        return None, None, None
    m = BUGCHECK_RE.search(message)
    code, params, dump_path = None, None, None
    if m:
        code = m.group(1).lower()
        params = [p.strip() for p in m.group(2).split(",")] if m.group(2) else []
    d = DUMP_RE.search(message)
    if d:
        dump_path = d.group(1).strip().strip('"')
    return code, params, dump_path

def normalize_code(code: str) -> str:
    try:
        if code is None: return ""
        c = code.lower()
        n = int(c, 16) if c.startswith("0x") else int(c, 16)
        return f"0x{n:08x}"
    except Exception:
        return (code or "").lower()

def bugcheck_description(code: str):
    c = normalize_code(code or "")
    name, desc = BUGCHECK_INFO.get(c, ("Unknown stop code", "No built-in description. Use WinDbg and driver checks."))
    return c, name, desc

def event_description(provider: str, event_id: int):
    return EVENT_INFO.get((provider, event_id), "")

def shorttext(s, n=150):
    return shorten(s or "", width=n, placeholder="…")

# Optional timeline plotting (dynamic import to avoid static warnings)
def _maybe_plot_timeline(bugchecks, out_png: Path):
    try:
        plt = importlib.import_module("matplotlib.pyplot")  # dynamic import
    except Exception:
        return None
    if not bugchecks:
        return None
    counts = {}
    for b in bugchecks:
        try:
            dt = datetime.strptime(b["TimeLocal"], "%a, %d %b %Y %I:%M:%S %p %Z").date()
        except Exception:
            continue
        counts[dt] = counts.get(dt, 0) + 1
    if not counts:
        return None
    days = sorted(counts.keys())
    vals = [counts[d] for d in days]
    plt.figure()
    plt.plot(days, vals, marker="o")  # no explicit colors/styles
    plt.title("BSOD count by day")
    plt.xlabel("Date")
    plt.ylabel("Count")
    plt.tight_layout()
    out_png.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(str(out_png))
    plt.close()
    return out_png

# ----------------------------
# System inventory helpers
# ----------------------------
def list_minidumps():
    paths = []
    for base in [Path(r"C:\Windows\Minidump"), Path(r"C:\Windows")]:
        if base.exists():
            for p in base.glob("*.dmp"):
                try:
                    ts = p.stat().st_mtime
                    paths.append((p, datetime.fromtimestamp(ts, tz=timezone.utc)))
                except Exception:
                    pass
    paths.sort(key=lambda t: t[1])
    return [str(p) for p, _ in paths]

def smart_status_quick():
    ps = r"""
Get-WmiObject Win32_DiskDrive | Select-Object Model, InterfaceType, SerialNumber, Status |
ConvertTo-Json -Depth 2
"""
    try:
        raw = run_powershell(ps).strip()
        if not raw: return []
        data = json.loads(raw)
        return data if isinstance(data, list) else [data]
    except Exception:
        return []

def storage_reliability():
    ps = r"""
$pd = Get-PhysicalDisk -ErrorAction SilentlyContinue
if ($pd) {
  $pd | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue |
    Select-Object DeviceId, Wear, Temperature, ReadErrorsTotal, WriteErrorsTotal, ReadRetriesTotal, WriteRetriesTotal |
    ConvertTo-Json -Depth 3
}
"""
    try:
        raw = run_powershell(ps).strip()
        if not raw: return []
        d = json.loads(raw)
        return d if isinstance(d, list) else [d]
    except Exception:
        return []

def gpu_info():
    ps = r"""
Get-WmiObject Win32_VideoController |
  Select-Object Name, DriverVersion, DriverDate |
  ConvertTo-Json -Depth 2
"""
    try:
        raw = run_powershell(ps).strip()
        if not raw: return []
        d = json.loads(raw)
        return d if isinstance(d, list) else [d]
    except Exception:
        return []

def system_snapshot():
    ps = r"""
$cpu = Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, MaxClockSpeed
$bios = Get-CimInstance Win32_BIOS | Select-Object SMBIOSBIOSVersion, ReleaseDate
$board = Get-CimInstance Win32_BaseBoard | Select-Object Product, Manufacturer
$mem = Get-CimInstance Win32_PhysicalMemory | Select-Object Manufacturer, Speed, Capacity
$os = Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture
$scheme = (powercfg /GETACTIVESCHEME) 2>$null
[PsCustomObject]@{
  CPU = $cpu
  BIOS = $bios
  BaseBoard = $board
  Memory = $mem
  OS = $os
  PowerPlan = $scheme
} | ConvertTo-Json -Depth 5
"""
    try:
        raw = run_powershell(ps).strip()
        return json.loads(raw) if raw else {}
    except Exception:
        return {}

def hotfixes():
    ps = r"""
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10 |
  ConvertTo-Json -Depth 3
"""
    try:
        raw = run_powershell(ps).strip()
        if not raw: return []
        d = json.loads(raw)
        return d if isinstance(d, list) else [d]
    except Exception:
        return []

# ----------------------------
# Health checks & WinDbg
# ----------------------------
def _run_shell_capture(cmdline: str, out_file: Path):
    """Run a console command and capture output to file (UTF-8)."""
    try:
        proc = subprocess.run(cmdline, shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
        out_file.write_text(proc.stdout + "\n\nSTDERR:\n" + proc.stderr, encoding="utf-8")
        return out_file
    except Exception as e:
        out_file.write_text(f"Error: {e}", encoding="utf-8")
        return out_file

def run_sfc():
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    return _run_shell_capture("sfc /scannow", REPORT_DIR / "SFC_Scan.txt")

def run_dism():
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    return _run_shell_capture("DISM /Online /Cleanup-Image /RestoreHealth", REPORT_DIR / "DISM_RestoreHealth.txt")

def run_chkdsk_scan():
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    return _run_shell_capture("chkdsk /scan", REPORT_DIR / "CHKDSK_Scan.txt")

def launch_memory_test():
    subprocess.Popen(["mdsched.exe"], shell=True)

def analyze_minidumps_with_windbg():
    dumps = list_minidumps()
    if not dumps:
        return None, "No .dmp files found."
    candidates = [
        Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "WindowsApps" / "WinDbgX.exe",
        Path("C:/Program Files (x86)/Windows Kits/10/Debuggers/x64/windbgx.exe"),
    ]
    exe = next((c for c in candidates if c.exists()), None)
    if not exe:
        return None, "WinDbg (Preview) not found. Install from Microsoft Store."
    cmd = f'"{exe}" -z "{dumps[-1]}" -c "!analyze -v; .ecxr; kv; lm; qd"'
    log = REPORT_DIR / "Minidump_Analysis.txt"
    log.write_text(f"Invoked:\n{cmd}\n\nNote: WinDbg opens a window. Save the log to file from WinDbg.", encoding="utf-8")
    try:
        subprocess.Popen(cmd, shell=True)
        return str(log), None
    except Exception as e:
        return None, str(e)

# ----------------------------
# Error scanning (beyond BSOD)
# ----------------------------
def scan_recent_errors_and_warnings(start_time: datetime):
    """
    Returns:
      { "recent": [...], "top_counts": [...] }
    Scans System + Application for Level Critical/Error/Warning within lookback.
    """
    ps = rf"""
$start = Get-Date '{start_time.isoformat()}'
$levels = @({1},{2},{3})  # Critical, Error, Warning
$logs = @('System','Application')
$evts = foreach ($log in $logs) {{
  Get-WinEvent -FilterHashtable @{{LogName=$log; StartTime=$start}} -ErrorAction SilentlyContinue |
    Where-Object {{ $_.Level -in $levels }} |
    Select-Object TimeCreated, LogName, Id, ProviderName, Level, LevelDisplayName, Message
}}
$recent = $evts | Sort-Object TimeCreated -Descending | Select-Object -First 200
$top = $evts | Group-Object ProviderName, Id, Level | Sort-Object Count -Descending | Select-Object -First 50
[PsCustomObject]@{{
  recent = $recent | Select-Object `
    @{{n='TimeCreatedUtc';e={{ $_.TimeCreated.ToUniversalTime() }}}},
    LogName, ProviderName, Id, Level, LevelDisplayName, Message
  top = $top | ForEach-Object {{
    $k = $_.Name -split ', '
    [PsCustomObject]@{{ ProviderName=$k[0]; Id=[int]$k[1]; Level=[int]$k[2]; Count=$_.Count }}
  }}
}} | ConvertTo-Json -Depth 5
"""
    try:
        raw = run_powershell(ps).strip()
        if not raw:
            return {"recent": [], "top_counts": []}
        data = json.loads(raw)
        recent = data.get("recent") or []
        norm_recent = []
        for e in recent:
            t = _parse_ps_datetime(e.get("TimeCreatedUtc"))
            disp = t.astimezone().strftime("%a, %d %b %Y %I:%M:%S %p %Z") if t else ""
            norm_recent.append({
                "Time": disp,
                "Log": e.get("LogName"),
                "Provider": e.get("ProviderName"),
                "Id": e.get("Id"),
                "Level": e.get("Level"),
                "LevelName": e.get("LevelDisplayName"),
                "Message": shorttext(e.get("Message"), 220)
            })
        top = data.get("top") or []
        top_counts = [(t.get("ProviderName"), int(t.get("Id") or 0), int(t.get("Count") or 0), int(t.get("Level") or 0)) for t in top]
        return {"recent": norm_recent, "top_counts": top_counts}
    except Exception:
        return {"recent": [], "top_counts": []}

# ----------------------------
# Live monitor (polls)
# ----------------------------
def _poll_new_events(since_dt: datetime):
    ps = rf"""
$evts = Get-WinEvent -FilterHashtable @{{LogName='System'; StartTime=(Get-Date '{since_dt.isoformat()}')}} |
  Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message |
  Sort-Object TimeCreated |
  Select-Object `
    @{{n='TimeCreatedUtc';e={{ $_.TimeCreated.ToUniversalTime() }}}},
    Id, ProviderName, LevelDisplayName, Message |
  ConvertTo-Json -Depth 4
"""
    try:
        raw = run_powershell(ps).strip()
        if not raw:
            return []
        d = json.loads(raw)
        arr = d if isinstance(d, list) else [d]
        out = []
        for e in arr:
            t = _parse_ps_datetime(e.get("TimeCreatedUtc"))
            if t:
                e["_utc_naive"] = t.replace(tzinfo=None)
                e["TimeDisplayLocal"] = t.astimezone().strftime("%a, %d %b %Y %I:%M:%S %p %Z")
            out.append(e)
        return out
    except Exception:
        return []

def start_live_monitor(callback_line):
    stop_event = threading.Event()
    interesting_providers = set(p for _, p, _ in BSOD_AND_SUSPECT_QUERIES if p) | {"disk", "nvme", "storahci", "Ntfs", "volmgr", "Display"}
    start_from = datetime.now(timezone.utc) - timedelta(seconds=SETTINGS.get("poll_seconds", 10))

    def loop():
        nonlocal start_from
        while not stop_event.is_set():
            evs = _poll_new_events(start_from)
            start_from = datetime.now(timezone.utc)
            for e in evs:
                pid = int(e.get("Id") or 0)
                prov = (e.get("ProviderName") or "")
                msg = e.get("Message") or ""
                if pid == 1001 or prov in interesting_providers:
                    desc = event_description(prov, pid)
                    line = f"{e.get('TimeDisplayLocal')} — {prov} (Event {pid})"
                    if desc:
                        line += f" — {desc}"
                    line += f"\n  {shorttext(msg, 240)}\n"
                    try:
                        callback_line(line)
                    except Exception:
                        pass
            stop_event.wait(SETTINGS.get("poll_seconds", 10))

    th = threading.Thread(target=loop, daemon=True)
    th.start()
    return th, stop_event

# ----------------------------
# Main analysis entry
# ----------------------------
def run_analysis():
    """Runs analysis, writes report/CSVs, returns summary dict for UI."""
    lookback_days = SETTINGS["lookback_days"]
    window_min = SETTINGS["window_min"]

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    start = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    admin = is_admin()

    # BSOD & suspects set
    all_events = {}
    for (log, provider, ids) in BSOD_AND_SUSPECT_QUERIES:
        key = f"{log}|{provider or '*'}|{','.join(map(str, ids)) if ids else '*'}"
        evts = get_events(log, provider, ids, start_time=start)
        all_events[key] = evts

    # BugChecks
    bugchecks, bsod_times = [], []
    for evts in all_events.values():
        for e in evts:
            msg = e.get("Message") or ""
            if e.get("Id") == 1001 and ("bugcheck" in msg.lower() or "bluescreen" in msg.lower()):
                code, params, dump_path = parse_bugcheck_info(msg)
                c_norm, c_name, c_desc = bugcheck_description(code)
                bugchecks.append({
                    "TimeLocal": e.get("TimeDisplayLocal") or "",
                    "Code": c_norm,
                    "Name": c_name,
                    "Desc": c_desc,
                    "Parameters": params or [],
                    "DumpPath": dump_path or "",
                    "RawMessage": shorttext(msg, 300),
                })
                if e.get("_utc_naive"):
                    bsod_times.append(e.get("_utc_naive"))

    # Suspects near BSODs
    window = timedelta(minutes=window_min)
    flat = [e for v in all_events.values() for e in v]
    suspect_counts = {}
    for e in flat:
        if e.get("Id") == 1001:  # skip the bugcheck itself
            continue
        et = e.get("_utc_naive")
        if not et:
            continue
        if any(abs(et - bt) <= window for bt in bsod_times):
            key = ((e.get("ProviderName") or "Unknown"), int(e.get("Id") or 0))
            suspect_counts[key] = suspect_counts.get(key, 0) + 1
    top_suspects = sorted([(prov, eid, cnt) for (prov, eid), cnt in suspect_counts.items()],
                          key=lambda x: x[2], reverse=True)

    # Broader errors/warnings (System + Application)
    errscan = scan_recent_errors_and_warnings(start_time=start)

    # Inventory
    dumps = list_minidumps()
    smart = smart_status_quick()
    reliab = storage_reliability()
    gpus = gpu_info()
    sysinfo = system_snapshot()
    updates = hotfixes()

    # Optional chart
    chart_file = REPORT_DIR / "bsod_timeline.png"
    _maybe_plot_timeline(bugchecks, chart_file)

    # Write Markdown summary (branding included)
    with REPORT_MD.open("w", encoding="utf-8") as f:
        f.write(f"# {APP_NAME} Report\n\n")
        f.write(f"- Tool: {APP_NAME} v{APP_VERSION} — by {DEV_SIGNATURE}\n")
        f.write(f"- Generated: {datetime.now(timezone.utc).astimezone().strftime('%a, %d %b %Y %I:%M:%S %p %Z')}\n")
        f.write(f"- Lookback: last {lookback_days} days; BSOD correlation window ±{window_min} min\n")
        f.write(f"- Admin: {admin}\n")
        f.write(f"- Output folder: `{REPORT_DIR}`\n\n")

        f.write("## BugChecks (Blue Screens)\n")
        if not bugchecks:
            f.write("_No BugCheck events found._\n\n")
        for b in bugchecks:
            f.write(f"- **{b['TimeLocal']}** — `{b['Code']}` **{b['Name']}**\n")
            f.write(f"  - {b['Desc']}\n")
            if b["Parameters"]:
                f.write(f"  - Parameters: {', '.join(b['Parameters'])}\n")
            if b["DumpPath"]:
                f.write(f"  - Dump: `{b['DumpPath']}`\n")
            f.write(f"  - Note: {b['RawMessage']}\n")
        f.write("\n")

        f.write("## Top suspects near BSODs\n")
        if not top_suspects:
            f.write("_No correlated events found near BSOD times._\n\n")
        for prov, eid, cnt in top_suspects[:30]:
            desc = event_description(prov, eid)
            if desc:
                f.write(f"- **{prov}** (Event {eid}) — {cnt} — {desc}\n")
            else:
                f.write(f"- **{prov}** (Event {eid}) — {cnt}\n")
        f.write("\n")

        if chart_file.exists():
            f.write(f"## Timeline\nSaved chart: `{chart_file}` (BSOD count by day)\n\n")

        f.write("## Recent Errors & Warnings (System + Application)\n")
        if errscan["recent"]:
            for e in errscan["recent"]:
                f.write(f"- [{e['Log']}] {e['Time']} — {e['Provider']} (Event {e['Id']}, {e['LevelName']})\n")
                f.write(f"  - {e['Message']}\n")
        else:
            f.write("_No recent items found._\n")
        f.write("\n")

        f.write("## Top recurrent errors/warnings\n")
        if errscan["top_counts"]:
            for prov, eid, cnt, lvl in errscan["top_counts"]:
                f.write(f"- {prov} (Event {eid}, Level {lvl}) ×{cnt}\n")
        else:
            f.write("_No recurrent patterns._\n")
        f.write("\n")

        f.write("## Minidumps\n")
        if dumps:
            for p in dumps[-50:]:
                f.write(f"- `{p}`\n")
        else:
            f.write("_No .dmp files found in default locations._")
        f.write("\n\n")

        f.write("## Storage Reliability Counters\n")
        if reliab:
            for r in reliab:
                f.write(f"- Dev {r.get('DeviceId')} — Wear:{r.get('Wear')} Temp:{r.get('Temperature')}°C "
                        f"ReadErr:{r.get('ReadErrorsTotal')} WriteErr:{r.get('WriteErrorsTotal')}\n")
        else:
            f.write("_Not available._\n")
        f.write("\n")

        f.write("## SMART (quick status)\n")
        if smart:
            for d in smart:
                f.write(f"- {d.get('Model')} ({d.get('InterfaceType')}) — Serial:{d.get('SerialNumber')} — Status:**{d.get('Status')}**\n")
        else:
            f.write("_Not available._\n")
        f.write("\n")

        f.write("## GPU\n")
        if gpus:
            for g in gpus:
                f.write(f"- {g.get('Name')} — Driver {g.get('DriverVersion')} ({g.get('DriverDate')})\n")
        else:
            f.write("_Not available._\n")
        f.write("\n")

        f.write("## System Snapshot\n")
        f.write(json.dumps(sysinfo, indent=2))
        f.write("\n\n")

        f.write("## Recent Windows Updates\n")
        if updates:
            for u in updates:
                f.write(f"- {u.get('HotFixID')} — {u.get('Description')} — {u.get('InstalledOn')}\n")
        else:
            f.write("_No data._\n")

    # CSVs
    csv_bsod = REPORT_DIR / "bugchecks.csv"
    with csv_bsod.open("w", newline="", encoding="utf-8") as fcsv:
        w = csv.writer(fcsv)
        w.writerow(["TimeLocal", "Code", "Name", "Description", "Parameters", "DumpPath"])
        for b in bugchecks:
            w.writerow([b["TimeLocal"], b["Code"], b["Name"], b["Desc"], ";".join(b["Parameters"]), b["DumpPath"]])

    csv_sus = REPORT_DIR / "suspects.csv"
    with csv_sus.open("w", newline="", encoding="utf-8") as fcsv:
        w = csv.writer(fcsv)
        w.writerow(["ProviderName", "EventId", "Count", "Meaning"])
        for prov, eid, cnt in top_suspects:
            w.writerow([prov, eid, cnt, event_description(prov, eid)])

    # Return for UI
    summary = {
        "admin": admin,
        "report_path": str(REPORT_MD),
        "report_dir": str(REPORT_DIR),
        "bugchecks": bugchecks,
        "suspects": top_suspects,
        "errors_recent": errscan["recent"],
        "errors_top": errscan["top_counts"],
        "chart_path": str(chart_file) if chart_file.exists() else "",
        "dumps": dumps,
        "storage_reliability": reliab,
        "smart": smart,
        "gpu": gpus,
        "system": sysinfo,
        "updates": updates,
        "settings": SETTINGS,
        "branding": {"app": APP_NAME, "version": APP_VERSION, "by": DEV_SIGNATURE},
    }
    return summary

# CLI
if __name__ == "__main__":
    s = run_analysis()
    print("Report:", s["report_path"])
    print("BugChecks:", len(s["bugchecks"]))
