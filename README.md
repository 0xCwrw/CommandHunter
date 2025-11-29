# CommandHunter
This script processes command history artifacts from Windows and MacOS - it can do any UNIX (idc nerds) command parsing as long as .history and .session files are present, it relies on .session files for temporal context. Set platform as MacOS because enabled by default there :).

Quick triage of MacOS history/session files and PowerShell script-block logs (4104). Quick triage of MacOS history/session files and PowerShell script-block logs (4104). It adds temporal context to .history files via the associated .session file. Allows for quick parsing of PowerShell transcription logs, grouping by ID.

  Windows:
  - Scans recursively for .evtx files (but try to just have them in one folder :)).
  - Filters for Event ID 4104 (PowerShell Script Block Logging).
  - Extracts metadata (Time, PID, Computer, ScriptBlock ID, Fragmentation details) and Script Text.
  - Groups output by ScriptBlock ID and orders chronologically.

  MacOS (UNIX sessions):
  - Scans recursively for .history, .historynew, and .session files.
  - Matches .session files with their corresponding .history files.
  - Extracts Epoch timestamps from .session files and converts to UTC.
  - Sorts sessions chronologically.
  - Appends orphaned .history files at the end.

## Usage:
> N.B. All output is automatically written to current working directory+commandhunter-timestamp-output.txt

**Target platform: Windows (PowerShell Scrip-block logs | 4104)**
```powershell
.\ForensicAnalyzer.ps1 -TargetDirectory "Z:\Path\To\WindowsPowerShellOperationalLogs" -Platform Windows
```

**Target platform: MacOS (any unix with .history + .session files)**
```powershell
.\ForensicAnalyzer.ps1 -TargetDirectory "C:\Evidence\MacDump" -Platform MacOS
```
