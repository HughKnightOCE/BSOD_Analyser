"""
driver_updates.py
Finds and installs driver updates via the Windows Update COM API.
No external modules required; uses PowerShell + COM.
"""

import json
import subprocess
from pathlib import Path
from typing import List, Dict, Optional

def _run_ps(ps: str) -> str:
    c = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
        capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    if c.returncode != 0:
        raise RuntimeError(c.stderr.strip() or "PowerShell error")
    return c.stdout

def list_driver_updates() -> List[Dict]:
    """
    Returns list of driver updates available from Windows Update:
    [{ Title, DriverManufacturer, DriverModel, DriverClass, DriverVersion, DriverVerDate,
       IdentityUpdateID, IdentityRevisionNumber, MoreInfoUrls:[...] }, ...]
    """
    ps = r"""
$Session  = New-Object -ComObject Microsoft.Update.Session
$Searcher = $Session.CreateUpdateSearcher()
$Result   = $Searcher.Search("IsInstalled=0 and Type='Driver' and IsHidden=0")
$updates = @()
for ($i=0; $i -lt $Result.Updates.Count; $i++) {
  $u = $Result.Updates.Item($i)
  $updates += [pscustomobject]@{
    Title = $u.Title
    DriverManufacturer = $u.DriverManufacturer
    DriverModel = $u.DriverModel
    DriverClass = $u.DriverClass
    DriverVersion = $u.DriverVersion
    DriverVerDate = $u.DriverVerDate
    IdentityUpdateID = $u.Identity.UpdateID
    IdentityRevisionNumber = $u.Identity.RevisionNumber
    MoreInfoUrls = $u.MoreInfoUrls
  }
}
$updates | ConvertTo-Json -Depth 6
"""
    out = _run_ps(ps).strip()
    if not out:
        return []
    data = json.loads(out)
    return data if isinstance(data, list) else [data]

def install_driver_update(update_id: str, revision_number: Optional[int] = None) -> Dict:
    """
    Installs the specified driver update by UpdateID (and optional revision).
    Returns dict: {status, reboot, hresult, updateID, revision}
    """
    rev = "null" if revision_number is None else str(int(revision_number))
    ps = rf"""
$UpdateId = '{update_id}'
$Rev = {rev}
$Session  = New-Object -ComObject Microsoft.Update.Session
$Searcher = $Session.CreateUpdateSearcher()
$Result   = $Searcher.Search("IsInstalled=0 and Type='Driver'")
$match = $null
for ($i=0; $i -lt $Result.Updates.Count; $i++) {{
  $u = $Result.Updates.Item($i)
  if ($u.Identity.UpdateID -eq $UpdateId -and ($Rev -eq $null -or $u.Identity.RevisionNumber -eq [int]$Rev)) {{
    $match = $u; break
  }}
}}
if ($null -eq $match) {{
  [pscustomobject]@{{ status="NOTFOUND" }} | ConvertTo-Json
  exit
}}
$coll = New-Object -ComObject Microsoft.Update.UpdateColl
[void]$coll.Add($match)
$installer = $Session.CreateUpdateInstaller()
$installer.Updates = $coll
$res = $installer.Install()
[pscustomobject]@{{
  status = $res.ResultCode.ToString()
  reboot = $res.RebootRequired
  hresult = $res.HResult
  updateID = $match.Identity.UpdateID
  revision = $match.Identity.RevisionNumber
}} | ConvertTo-Json
"""
    out = _run_ps(ps).strip()
    return json.loads(out) if out else {"status": "ERROR"}
