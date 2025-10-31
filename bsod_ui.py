"""
bsod_ui.py
Modern ttk GUI for the Error Checker with:
- Tabs: Summary, Errors, BugChecks, Suspects, Driver Updates, System Info, Live Monitor
- Progress bar, Info/About dialog
- Copy/Save Summary
- Change/Open report folder
- Admin banner + 'Run Elevated' helper
- Health tools (System Info tab): SFC, DISM, CHKDSK, Memory Diagnostic
- Driver Updates: refresh, open info link, install selected (Admin)
- Persistent settings (settings.json): report folder, lookback days, window minutes

Branding (from bsod_core): uses APP_NAME, DEV_SIGNATURE, APP_VERSION
Logo/Icon:
  Put one of these next to the .py files:
    - app.ico  (preferred on Windows)
    - logo.png (used in header + window iconphoto)
"""

import tkinter as tk
from tkinter import messagebox, filedialog
from tkinter import ttk
from tkinter import scrolledtext
import os
import sys
from pathlib import Path
import threading
import webbrowser

import bsod_core
import driver_updates as dups


# --------------------- helpers ---------------------
def set_text(widget: scrolledtext.ScrolledText, text: str):
    widget.config(state="normal")
    widget.delete("1.0", "end")
    widget.insert("1.0", text)
    widget.config(state="disabled")

def copy_to_clipboard(text: str):
    root.clipboard_clear()
    root.clipboard_append(text)
    root.update()

def info_text():
    return (
        "What am I seeing?\n"
        "• Errors tab: Recent and most frequent errors/warnings (System + Application).\n"
        "• BugChecks: BSOD stop codes with friendly names/descriptions and dump paths.\n"
        "• Suspects: Events that tend to cluster near BSOD times.\n"
        "• Driver Updates: Lists Windows Update–available driver updates; install or open info link.\n"
        "\n"
        "Stop code quick hints:\n"
        "  0x00000050 PAGE_FAULT_IN_NONPAGED_AREA → RAM/driver/disk.\n"
        "  0x0000001E KMODE_EXCEPTION_NOT_HANDLED → buggy driver/kernel extension.\n"
        "  0x0000003B SYSTEM_SERVICE_EXCEPTION → often GPU/display/AV.\n"
        "  0x00000116 VIDEO_TDR_FAILURE → GPU/driver/thermals/PSU.\n"
        "  0x00000124 WHEA_UNCORRECTABLE_ERROR → hardware (CPU/VRM/RAM/PCIe).\n"
    )

def about_text():
    b = bsod_core.APP_NAME if hasattr(bsod_core, "APP_NAME") else "Windows Error Checker"
    v = bsod_core.APP_VERSION if hasattr(bsod_core, "APP_VERSION") else "0"
    d = bsod_core.DEV_SIGNATURE if hasattr(bsod_core, "DEV_SIGNATURE") else "H.Knight"
    return f"{b} v{v}\nBuilt by {d}\n\nThis tool scans Windows event logs, hardware counters and updates to help diagnose crashes and errors."

def severity_for_event(provider: str, eid: int) -> str:
    if provider == "Microsoft-Windows-WHEA-Logger" and eid in (1, 18):
        return "sev_critical"
    if provider in {"disk", "nvme"} and eid in (153, 154):
        return "sev_high"
    if provider == "volmgr" and eid == 161:
        return "sev_high"
    if provider == "Ntfs" and eid in (55, 57):
        return "sev_high"
    if provider == "Display" and eid == 4101:
        return "sev_medium"
    if provider == "Microsoft-Windows-Kernel-Power" and eid == 41:
        return "sev_medium"
    return "sev_low"

def fill_tree(tree: ttk.Treeview, rows, columns, tags_func=None):
    tree.delete(*tree.get_children())
    for r in rows:
        vals = [r.get(col, "") if isinstance(r, dict) else r[i] for i, col in enumerate(columns)]
        tag = ()
        if tags_func:
            try:
                tag = (tags_func(r),)
            except Exception:
                tag = ()
        tree.insert("", "end", values=vals, tags=tag)

def tree_sortable(tree: ttk.Treeview):
    def sort_by(col, reverse):
        data = [(tree.set(k, col), k) for k in tree.get_children("")]
        try:
            data.sort(key=lambda t: float(t[0]))
        except Exception:
            data.sort(key=lambda t: t[0])
        if reverse:
            data.reverse()
        for i, (_, k) in enumerate(data):
            tree.move(k, "", i)
        tree.heading(col, command=lambda: sort_by(col, not reverse))
    for col in tree["columns"]:
        tree.heading(col, command=lambda c=col: sort_by(c, False))

# --------------------- actions ---------------------
def run_analysis():
    progress.start(8)
    btn_run.config(state="disabled")
    set_text(summary_box, "Running analysis, please wait…\n")
    def task():
        try:
            summary = bsod_core.run_analysis()
            render_all(summary)
        except Exception as e:
            set_text(summary_box, f"Error: {e}")
        finally:
            progress.stop()
            btn_run.config(state="normal")
    threading.Thread(target=task, daemon=True).start()

def render_all(summary):
    # Summary
    lines = []
    lines.append(f"Report saved to:\n  {summary['report_path']}\n")
    lines.append(f"Admin rights: {summary['admin']}")
    settings = summary.get("settings", {})
    lines.append(f"Lookback: {settings.get('lookback_days')} days, window ±{settings.get('window_min')} min\n")

    lines.append(f"BugChecks found: {len(summary['bugchecks'])}")
    for b in summary["bugchecks"][:10]:
        lines.append(f"• {b['TimeLocal']} — {b['Code']} {b['Name']}\n  {b['Desc']}")
        if b["DumpPath"]:
            lines.append(f"  dump: {b['DumpPath']}")
        if b["Parameters"]:
            lines.append(f"  params: {', '.join(b['Parameters'])}")
    if len(summary["bugchecks"]) > 10:
        lines.append(f"…and {len(summary['bugchecks'])-10} more (see report).")
    lines.append("")
    if summary.get("chart_path"):
        lines.append(f"Timeline chart: {summary['chart_path']}")
    set_text(summary_box, "\n".join(lines))

    # Errors tab
    fill_tree(errors_recent_tree, summary.get("errors_recent", []),
              ["Time", "Log", "Provider", "Id", "LevelName", "Message"])
    tree_sortable(errors_recent_tree)

    top_rows = []
    for prov, eid, cnt, lvl in summary.get("errors_top", []):
        top_rows.append({"Provider": prov, "EventId": eid, "Count": cnt, "Level": lvl})
    fill_tree(errors_top_tree, top_rows, ["Provider", "EventId", "Count", "Level"],
              tags_func=lambda r: severity_for_event(r["Provider"], int(r["EventId"])))
    tree_sortable(errors_top_tree)

    # BugChecks
    bug_rows = []
    for b in summary["bugchecks"]:
        bug_rows.append({"Time": b["TimeLocal"], "Code": b["Code"], "Name": b["Name"],
                         "Dump": b["DumpPath"], "Params": ";".join(b["Parameters"])})
    fill_tree(bugs_tree, bug_rows, ["Time", "Code", "Name", "Dump", "Params"])
    tree_sortable(bugs_tree)

    # Suspects
    sus_rows = []
    for prov, eid, cnt in summary["suspects"]:
        sus_rows.append({"Provider": prov, "EventId": eid, "Count": cnt,
                         "Meaning": bsod_core.event_description(prov, eid)})
    fill_tree(sus_tree, sus_rows, ["Provider", "EventId", "Count", "Meaning"],
              tags_func=lambda r: severity_for_event(r["Provider"], int(r["EventId"])))
    tree_sortable(sus_tree)

    # System info text
    sys_lines = []
    sys_lines.append("=== GPU ===")
    for g in summary.get("gpu", []):
        sys_lines.append(f"- {g.get('Name')} — Driver {g.get('DriverVersion')} ({g.get('DriverDate')})")
    sys_lines.append("\n=== Storage Reliability ===")
    reliab = summary.get("storage_reliability", [])
    if reliab:
        for r in reliab:
            sys_lines.append(f"- Dev {r.get('DeviceId')} Wear:{r.get('Wear')} Temp:{r.get('Temperature')}°C "
                             f"ReadErr:{r.get('ReadErrorsTotal')} WriteErr:{r.get('WriteErrorsTotal')}")
    else:
        sys_lines.append("- Not available.")
    sys_lines.append("\n=== SMART Quick Status ===")
    smart = summary.get("smart", [])
    if smart:
        for d in smart:
            sys_lines.append(f"- {d.get('Model')} ({d.get('InterfaceType')}) Serial:{d.get('SerialNumber')} Status:{d.get('Status')}")
    else:
        sys_lines.append("- Not available.")
    sys_lines.append("\n=== Windows Updates (recent) ===")
    for u in summary.get("updates", []):
        sys_lines.append(f"- {u.get('HotFixID')} — {u.get('Description')} — {u.get('InstalledOn')}")
    sys_lines.append("\n=== System Snapshot ===")
    sys_lines.append(json_pretty(summary.get("system", {})))
    set_text(sysinfo_box, "\n".join(sys_lines))

def json_pretty(obj):
    try:
        import json
        return json.dumps(obj, indent=2)
    except Exception:
        return str(obj)

def open_report_folder():
    try:
        os.startfile(str(Path(bsod_core.REPORT_DIR)))
    except Exception:
        messagebox.showerror("Error", f"Cannot open: {bsod_core.REPORT_DIR}")

def change_report_folder():
    current = Path(bsod_core.REPORT_DIR)
    new_dir = filedialog.askdirectory(initialdir=current, title="Select report folder")
    if new_dir:
        bsod_core.set_report_dir(Path(new_dir))
        report_folder_var.set(f"Report folder: {bsod_core.REPORT_DIR}")
        set_text(summary_box, f"Report folder changed to:\n  {bsod_core.REPORT_DIR}")

def save_summary_to_file():
    p = Path(bsod_core.REPORT_DIR) / "Summary_Copy.txt"
    p.write_text(summary_box.get("1.0", "end"), encoding="utf-8")
    messagebox.showinfo("Saved", f"Saved to:\n{p}")

def copy_summary():
    copy_to_clipboard(summary_box.get("1.0", "end"))

def show_info():
    messagebox.showinfo("About the Analysis", info_text())

def show_about():
    messagebox.showinfo("About", about_text())

def run_elevated():
    py = Path(sys.executable) if hasattr(sys, "executable") else "python"
    script = Path(__file__).resolve()
    ps = f'Start-Process "{py}" -ArgumentList \'"{script}"\' -Verb RunAs'
    try:
        bsod_core.run_powershell(ps)
    except Exception as e:
        messagebox.showerror("Error", f"Could not relaunch elevated.\n\n{e}")

def run_sfc():
    progress.start(8)
    def task():
        out = bsod_core.run_sfc()
        progress.stop()
        messagebox.showinfo("SFC", f"Completed.\n\nLog: {out}")
    threading.Thread(target=task, daemon=True).start()

def run_dism():
    progress.start(8)
    def task():
        out = bsod_core.run_dism()
        progress.stop()
        messagebox.showinfo("DISM", f"Completed.\n\nLog: {out}")
    threading.Thread(target=task, daemon=True).start()

def run_chkdsk():
    progress.start(8)
    def task():
        out = bsod_core.run_chkdsk_scan()
        progress.stop()
        messagebox.showinfo("CHKDSK", f"Completed.\n\nLog: {out}")
    threading.Thread(target=task, daemon=True).start()

def run_mdsched():
    try:
        bsod_core.launch_memory_test()
        messagebox.showinfo("Windows Memory Diagnostic", "Scheduled / launched. Windows may prompt to reboot.")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# ---- Driver Updates tab actions ----
driver_updates_cache = []

def drivers_refresh():
    global driver_updates_cache
    progress.start(8)
    btn_drivers_refresh.config(state="disabled")
    def task():
        try:
            ups = dups.list_driver_updates()
        except Exception as e:
            ups = []
            messagebox.showerror("Driver Updates", f"Error while searching:\n{e}")
        finally:
            driver_updates_cache = ups or []
            rows = []
            for u in driver_updates_cache:
                rows.append({
                    "Title": u.get("Title"),
                    "Manufacturer": u.get("DriverManufacturer"),
                    "Model": u.get("DriverModel"),
                    "Class": u.get("DriverClass"),
                    "Version": u.get("DriverVersion"),
                    "Date": u.get("DriverVerDate"),
                    "UpdateID": u.get("IdentityUpdateID"),
                    "Revision": u.get("IdentityRevisionNumber"),
                    "InfoURL": (u.get("MoreInfoUrls") or [""])[0]
                })
            fill_tree(drivers_tree, rows, ["Title", "Manufacturer", "Model", "Class", "Version", "Date", "UpdateID", "Revision", "InfoURL"])
            tree_sortable(drivers_tree)
            progress.stop()
            btn_drivers_refresh.config(state="normal")
    threading.Thread(target=task, daemon=True).start()

def drivers_open_link():
    sel = drivers_tree.selection()
    if not sel:
        messagebox.showinfo("Driver Updates", "Select a driver update first.")
        return
    info_url = drivers_tree.set(sel[0], "InfoURL")
    if info_url:
        webbrowser.open(info_url)
    else:
        messagebox.showinfo("Driver Updates", "No info URL provided by Windows Update.")

def drivers_install_selected():
    if not bsod_core.is_admin():
        messagebox.showwarning("Driver Updates", "Installation requires Administrator.\nUse the 'Run Elevated' button.")
        return
    sel = drivers_tree.selection()
    if not sel:
        messagebox.showinfo("Driver Updates", "Select a driver update first.")
        return
    upd_id = drivers_tree.set(sel[0], "UpdateID")
    rev = drivers_tree.set(sel[0], "Revision")
    if not upd_id:
        messagebox.showinfo("Driver Updates", "Could not determine UpdateID.")
        return
    if messagebox.askyesno("Confirm Install", "Install the selected driver update now?"):
        progress.start(8)
        def task():
            try:
                res = dups.install_driver_update(upd_id, int(rev) if rev else None)
                messagebox.showinfo("Driver Install", f"Result: {res.get('status')}  RebootRequired: {res.get('reboot')}")
            except Exception as e:
                messagebox.showerror("Driver Install", f"Failed: {e}")
            finally:
                progress.stop()
        threading.Thread(target=task, daemon=True).start()

# Live monitor
monitor_stop = None
def monitor_toggle():
    global monitor_stop
    if monitor_stop is None:
        live_btn.config(text="Stop Monitor")
        set_text(live_box, "Monitoring System log… (polling every 10s)\n")
        def cb(line: str):
            live_box.config(state="normal")
            live_box.insert("end", line + "\n")
            live_box.see("end")
            live_box.config(state="disabled")
        _, stop_event = bsod_core.start_live_monitor(cb)
        monitor_stop = stop_event
    else:
        monitor_stop.set()
        monitor_stop = None
        live_btn.config(text="Start Monitor")

# Settings change handlers
def on_lookback_change(val):
    try: bsod_core.set_lookback_days(int(val))
    except Exception: pass

def on_window_change(val):
    try: bsod_core.set_window_min(int(val))
    except Exception: pass


# --------------------- UI ---------------------
root = tk.Tk()

# Title with signature
app_title = getattr(bsod_core, "APP_NAME", "Windows Error Checker")
app_ver = getattr(bsod_core, "APP_VERSION", "0")
app_by = getattr(bsod_core, "DEV_SIGNATURE", "H.Knight")
root.title(f"{app_title} v{app_ver} — by {app_by}")

root.geometry("1120x780")
root.minsize(980, 620)

# Try to set icon and header logo
SCRIPT_DIR = Path(__file__).resolve().parent
logo_img = None
ico = SCRIPT_DIR / "app.ico"
png = SCRIPT_DIR / "logo.png"
try:
    if ico.exists():
        root.iconbitmap(default=str(ico))
    elif png.exists():
        logo_img = tk.PhotoImage(file=str(png))
        root.iconphoto(True, logo_img)
except Exception:
    pass

style = ttk.Style(root)
try: style.theme_use("clam")
except Exception: pass
style.configure("TButton", padding=8)
style.configure("Header.TFrame", background="#f6f7fb")
style.configure("Title.TLabel", font=("Segoe UI", 12, "bold"))
style.configure("Folder.TLabel", font=("Segoe UI", 9))
style.configure("Warn.TLabel", foreground="#9c6f00")

# top header bar
header = ttk.Frame(root, style="Header.TFrame")
header.pack(side="top", fill="x")

# (optional) small logo at left if logo.png present
if png.exists():
    try:
        logo_small = tk.PhotoImage(file=str(png))
        # keep a ref to avoid GC
        header._logo_small = logo_small
        tk.Label(header, image=logo_small, bg="#f6f7fb").pack(side="left", padx=(8, 4), pady=6)
    except Exception:
        pass

btn_run = ttk.Button(header, text="Run Scan", command=run_analysis)
btn_run.pack(side="left", padx=(8, 6), pady=10)

ttk.Button(header, text="Open Report Folder", command=open_report_folder).pack(side="left", padx=6, pady=10)
ttk.Button(header, text="Change Report Folder", command=change_report_folder).pack(side="left", padx=6, pady=10)

ttk.Button(header, text="Info", command=show_info).pack(side="right", padx=10, pady=10)
ttk.Button(header, text="About", command=show_about).pack(side="right", padx=(4, 10), pady=10)

# admin banner
if not bsod_core.is_admin():
    warn = ttk.Label(root, text="Not running as Administrator — some logs/dumps and driver installs may be unavailable.",
                     style="Warn.TLabel")
    warn.pack(side="top", fill="x", padx=12)
    ttk.Button(root, text="Run Elevated", command=run_elevated).pack(side="top", anchor="w", padx=12)

# progress bar
progress = ttk.Progressbar(root, mode="indeterminate")
progress.pack(side="top", fill="x")

# settings row
settings_frame = ttk.Frame(root)
settings_frame.pack(side="top", fill="x", padx=12, pady=6)
ttk.Label(settings_frame, text="Lookback (days):").pack(side="left")
lookback = tk.Spinbox(settings_frame, from_=1, to=365, width=6,
                      command=lambda: on_lookback_change(lookback.get()))
lookback.delete(0, "end"); lookback.insert(0, str(bsod_core.SETTINGS["lookback_days"]))
lookback.pack(side="left", padx=(4, 12))
ttk.Label(settings_frame, text="BSOD window (±min):").pack(side="left")
winspin = tk.Spinbox(settings_frame, from_=1, to=120, width=6,
                     command=lambda: on_window_change(winspin.get()))
winspin.delete(0, "end"); winspin.insert(0, str(bsod_core.SETTINGS["window_min"]))
winspin.pack(side="left", padx=(4, 12))

report_folder_var = tk.StringVar(value=f"Report folder: {bsod_core.REPORT_DIR}")
ttk.Label(root, textvariable=report_folder_var, style="Folder.TLabel", anchor="w").pack(side="top", fill="x", padx=12)

# notebook
nb = ttk.Notebook(root)
nb.pack(fill="both", expand=True, padx=12, pady=8)

# Summary
summary_tab = ttk.Frame(nb); nb.add(summary_tab, text="Summary")
summary_box = scrolledtext.ScrolledText(summary_tab, wrap="word", font=("Consolas", 10), padx=10, pady=10)
summary_box.pack(fill="both", expand=True); summary_box.config(state="disabled")
summary_btns = ttk.Frame(summary_tab); summary_btns.pack(fill="x", pady=(6, 0))
ttk.Button(summary_btns, text="Copy Summary", command=copy_summary).pack(side="left", padx=4)
ttk.Button(summary_btns, text="Save Summary", command=save_summary_to_file).pack(side="left", padx=4)

# Errors tab
errors_tab = ttk.Frame(nb); nb.add(errors_tab, text="Errors")
ttk.Label(errors_tab, text="Recent Errors & Warnings (System + Application)", style="Title.TLabel").pack(anchor="w", padx=4, pady=(4,0))
errors_recent_tree = ttk.Treeview(errors_tab, columns=("Time","Log","Provider","Id","LevelName","Message"), show="headings")
for c,w in [("Time",190),("Log",90),("Provider",220),("Id",70),("LevelName",100),("Message",520)]:
    errors_recent_tree.heading(c, text=c); errors_recent_tree.column(c, width=w, anchor="w")
errors_recent_tree.pack(fill="both", expand=True, padx=2, pady=4)
ttk.Label(errors_tab, text="Top recurrent issues", style="Title.TLabel").pack(anchor="w", padx=4, pady=(6,0))
errors_top_tree = ttk.Treeview(errors_tab, columns=("Provider","EventId","Count","Level"), show="headings")
for c,w in [("Provider",260),("EventId",80),("Count",80),("Level",80)]:
    errors_top_tree.heading(c, text=c); errors_top_tree.column(c, width=w, anchor="w")
# severity colors
errors_top_tree.tag_configure("sev_critical", background="#ffe5e5")
errors_top_tree.tag_configure("sev_high", background="#fff2cc")
errors_top_tree.tag_configure("sev_medium", background="#e6f0ff")
errors_top_tree.tag_configure("sev_low", background="#f7f7f7")
errors_top_tree.pack(fill="both", expand=True, padx=2, pady=(2,6))

# BugChecks tab
bugs_tab = ttk.Frame(nb); nb.add(bugs_tab, text="BugChecks")
bugs_cols = ("Time","Code","Name","Dump","Params")
bugs_tree = ttk.Treeview(bugs_tab, columns=bugs_cols, show="headings")
for c in bugs_cols:
    bugs_tree.heading(c, text=c)
    bugs_tree.column(c, width=160 if c in ("Time","Dump") else 130, anchor="w")
bugs_tree.pack(fill="both", expand=True)

# Suspects tab
sus_tab = ttk.Frame(nb); nb.add(sus_tab, text="Suspects (near BSOD)")
sus_cols = ("Provider","EventId","Count","Meaning")
sus_tree = ttk.Treeview(sus_tab, columns=sus_cols, show="headings")
for c in sus_cols:
    sus_tree.heading(c, text=c)
    sus_tree.column(c, width=150 if c!="Meaning" else 420, anchor="w")
sus_tree.tag_configure("sev_critical", background="#ffe5e5")
sus_tree.tag_configure("sev_high", background="#fff2cc")
sus_tree.tag_configure("sev_medium", background="#e6f0ff")
sus_tree.tag_configure("sev_low", background="#f7f7f7")
sus_tree.pack(fill="both", expand=True)

# Driver Updates tab
drivers_tab = ttk.Frame(nb); nb.add(drivers_tab, text="Driver Updates")
drivers_cols = ("Title","Manufacturer","Model","Class","Version","Date","UpdateID","Revision","InfoURL")
drivers_tree = ttk.Treeview(drivers_tab, columns=drivers_cols, show="headings")
for c,w in [("Title",380),("Manufacturer",160),("Model",220),("Class",120),("Version",120),("Date",140),
            ("UpdateID",0),("Revision",0),("InfoURL",0)]:
    drivers_tree.heading(c, text=c)
    drivers_tree.column(c, width=w, anchor="w", stretch=(c not in {"UpdateID","Revision","InfoURL"}))
drivers_tree.pack(fill="both", expand=True)
drv_btns = ttk.Frame(drivers_tab); drv_btns.pack(fill="x", pady=6)
btn_drivers_refresh = ttk.Button(drv_btns, text="Refresh", command=drivers_refresh); btn_drivers_refresh.pack(side="left", padx=4)
ttk.Button(drv_btns, text="Open Info Link", command=drivers_open_link).pack(side="left", padx=4)
ttk.Button(drv_btns, text="Install Selected (Admin)", command=drivers_install_selected).pack(side="left", padx=12)

# System Info tab
sys_tab = ttk.Frame(nb); nb.add(sys_tab, text="System Info")
sysinfo_box = scrolledtext.ScrolledText(sys_tab, wrap="word", font=("Consolas", 10), padx=10, pady=10)
sysinfo_box.pack(fill="both", expand=True); sysinfo_box.config(state="disabled")
tools = ttk.Frame(sys_tab); tools.pack(fill="x", pady=(6,0))
ttk.Button(tools, text="Run SFC", command=run_sfc).pack(side="left", padx=4)
ttk.Button(tools, text="Run DISM", command=run_dism).pack(side="left", padx=4)
ttk.Button(tools, text="Run CHKDSK (online)", command=run_chkdsk).pack(side="left", padx=4)
ttk.Button(tools, text="Windows Memory Diagnostic", command=run_mdsched).pack(side="left", padx=12)

# Live Monitor tab
live_tab = ttk.Frame(nb); nb.add(live_tab, text="Live Monitor")
live_box = scrolledtext.ScrolledText(live_tab, wrap="word", font=("Consolas", 10), padx=10, pady=10)
live_box.pack(fill="both", expand=True); live_box.config(state="disabled")
live_btn = ttk.Button(live_tab, text="Start Monitor", command=monitor_toggle); live_btn.pack(pady=6)

# footer / signature
footer = ttk.Label(root, text=f"{app_title} v{app_ver} — © 2025 {app_by}", anchor="w", relief="sunken")
footer.pack(side="bottom", fill="x")

# initial hint
set_text(summary_box, "Press “Run Scan” to begin.\n\nTip: Run as Administrator for full access (logs, minidumps, driver install).")

root.mainloop()
