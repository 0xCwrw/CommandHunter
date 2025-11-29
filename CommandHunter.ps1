<#
    Author: Cwrw
    Date: 2025-11-29
    .SYNOPSIS
        Quick triage of MacOS history/session files and PowerShell script-block logs (4104). Provides temporal context to .zsh history files via the associated session file. Also quick and easy parsing of PowerShell transcription logs, grouping and concatenating by ID.

    .DESCRIPTION
        This script processes command history artifacts from Windows and MacOS - it can do any UNIX (idc nerds) command parsing as long as .history and .session files are present, it relies on .session files for temporal context. Set platform as MacOS because enabled by default there :).
    
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

    .PARAMETER TargetDirectory
        The root directory to scan for artifacts.
        
    .PARAMETER Platform
        The target platform type ("Windows" or "MacOS").

    .EXAMPLE
        .\ForensicAnalyzer.ps1 -TargetDirectory "C:\Evidence\MacDump" -Platform MacOS
    .EXAMPLE
        .\ForensicAnalyzer.ps1 -TargetDirectory "Z:\Path\To\WindowsPowerShellOperationalLogs" -Platform Windows
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [ValidateScript({Test-Path $_ -PathType Container})]
    [string]$TargetDirectory,

    [Parameter(Mandatory=$true, Position=1)]
    [ValidateSet("Windows", "MacOS")]
    [string]$Platform
)

# LOGGING SETUP
# ---------------------------------------------------------------------------

$TimeStamp = Get-Date -Format "yyyyMMdd-HHmmss"
$LogFile   = "commandhunter-$TimeStamp-output.txt"
$LogPath   = Join-Path -Path $PWD -ChildPath $LogFile

try {
    Write-Host "Initializing Log: $LogPath" -ForegroundColor DarkGray
    # Start-Transcript captures all output (stdout/stderr) to the file
    Start-Transcript -Path $LogPath -Force -ErrorAction SilentlyContinue
}
catch {
    Write-Warning "Could not start transcript logging. Output will only appear in console."
}

# Triage Functions:
# ---------------------------------------------------------------------------

function Convert-EpochToUtc {
    param([long]$Epoch)
    try {
        return [DateTimeOffset]::FromUnixTimeSeconds($Epoch).UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss")
    }
    catch {
        return "INVALID_DATE"
    }
}

function Analyze-MacOS {
    Write-Host "[*] Starting MacOS (*nix) Artifact Analysis..." -ForegroundColor Cyan
    Write-Host "[*] Target: $TargetDirectory" -ForegroundColor Gray

    # Find all relevant files
    $files = Get-ChildItem -Path $TargetDirectory -Recurse -Include "*.history", "*.historynew", "*.session" -File

    if (-not $files) {
        Write-Warning "No .history, .historynew, or .session files found in target directory."
        return
    }

    # Group files by their BaseName (assuming session and history share a name, e.g., 'long-ah-id-1.session' and 'long-ah-id-1.history')
    $groupedFiles = $files | Group-Object BaseName

    $processedSessions = @()
    $orphanedHistory = @()

    foreach ($group in $groupedFiles) {
        $sessionFile = $group.Group | Where-Object { $_.Extension -eq ".session" } | Select-Object -First 1
        $historyFile = $group.Group | Where-Object { $_.Extension -in ".history", ".historynew" } | Select-Object -First 1

        if ($sessionFile) {
            # Extract content to find timestamp
            $rawContent = Get-Content -Path $sessionFile.FullName -Raw -ErrorAction SilentlyContinue
            $timestamp = $null
            $dateStr = "Unknown"
            $sortableDate = 0

            if ($rawContent -match "(\d{10})") {
                $epochTime = $matches[1]
                $sortableDate = [long]$epochTime
                $dateStr = Convert-EpochToUtc -Epoch $epochTime
            }

            # Get History Content
            $histContent = "N/A"
            if ($historyFile) {
                $histContent = Get-Content -Path $historyFile.FullName -Raw -ErrorAction SilentlyContinue
            }

            $processedSessions += [PSCustomObject]@{
                SortDate      = $sortableDate
                TimestampUTC  = $dateStr
                SessionFile   = $sessionFile.Name
                HistoryFile   = if ($historyFile) { $historyFile.Name } else { "MISSING" }
                Content       = $histContent
            }
        }
        elseif ($historyFile) {
            # This is an orphan history file (no accompanying session file)
            $orphanedHistory += [PSCustomObject]@{
                HistoryFile = $historyFile.Name
                Content     = Get-Content -Path $historyFile.FullName -Raw -ErrorAction SilentlyContinue
                Path        = $historyFile.FullName
            }
        }
    }

    # 1. Output Sorted Paired Sessions
    Write-Host "`n=== RECONSTRUCTED SESSIONS (Chronological UTC) ===" -ForegroundColor Green
    
    $sortedSessions = $processedSessions | Sort-Object SortDate

    foreach ($sess in $sortedSessions) {
        Write-Host "------------------------------------------------"
        Write-Host "Session Time (UTC) : $($sess.TimestampUTC)" -ForegroundColor Yellow
        Write-Host "Source Session File: $($sess.SessionFile)"
        Write-Host "Source History File: $($sess.HistoryFile)"
        Write-Host "--- Command History ---" -ForegroundColor Cyan
        Write-Host $sess.Content
        Write-Host ""
    }

    # 2. Output Orphaned History
    if ($orphanedHistory.Count -gt 0) {
        Write-Host "`n=== ORPHANED HISTORY FILES (No Session Data) ===" -ForegroundColor Magenta
        Write-Host "N.B: These files lacked a corresponding .session file for time correlation.`n"
        
        foreach ($orph in $orphanedHistory) {
            Write-Host "------------------------------------------------"
            Write-Host "File: $($orph.HistoryFile)" -ForegroundColor Yellow
            Write-Host "Path: $($orph.Path)"
            Write-Host "--- Content ---" -ForegroundColor Cyan
            Write-Host $orph.Content
            Write-Host ""
        }
    }
}

function Analyze-Windows {
    Write-Host "[*] Starting Windows Artifact Analysis..." -ForegroundColor Cyan
    Write-Host "[*] Target: $TargetDirectory" -ForegroundColor Gray
    Write-Host "[*] Searching for Event Log files and filtering for Event ID 4104..." -ForegroundColor Gray

    # Find EVTX files
    $evtxFiles = Get-ChildItem -Path $TargetDirectory -Recurse -Filter "*.evtx"

    if (-not $evtxFiles) {
        Write-Warning "No .evtx files found in target directory."
        return
    }

    $allScriptBlocks = @()

    foreach ($file in $evtxFiles) {
        try {
            # Efficiently filter for 4104 using XPath
            $events = Get-WinEvent -Path $file.FullName -FilterXPath "*[System[(EventID=4104)]]" -ErrorAction Stop

            foreach ($evt in $events) {
                # Convert to XML for reliable property extraction
                $xml = [xml]$evt.ToXml()
                $eventData = $xml.Event.EventData.Data

                # Extract specific fields using XML node names
                $sbId = ($eventData | Where-Object { $_.Name -eq "ScriptBlockId" }).'#text'
                $msgNum = ($eventData | Where-Object { $_.Name -eq "MessageNumber" }).'#text'
                $msgTot = ($eventData | Where-Object { $_.Name -eq "MessageTotal" }).'#text'
                $sbText = ($eventData | Where-Object { $_.Name -eq "ScriptBlockText" }).'#text'

                # Fallback for older PS versions if XML names differ, or ensure defaults
                if (-not $msgNum) { $msgNum = 1 }
                if (-not $msgTot) { $msgTot = 1 }

                $allScriptBlocks += [PSCustomObject]@{
                    TimeCreated      = $evt.TimeCreated.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
                    ProcessID        = $evt.ProcessId
                    ComputerName     = $evt.MachineName
                    User             = if ($evt.UserId) { $evt.UserId.ToString() } else { "N/A" }
                    ScriptBlockID    = $sbId
                    MessageNumber    = [int]$msgNum
                    MessageTotal     = [int]$msgTot
                    ScriptText       = $sbText
                    SourceFile       = $file.Name
                }
            }
        }
        catch {
            # Common error: File is in use or corrupt, log and continue
            Write-Verbose "Could not process file $($file.Name): $_"
        }
    }

    if ($allScriptBlocks.Count -eq 0) {
        Write-Warning "No Event ID 4104 records found."
        return
    }

    # Group by ScriptBlock ID
    $groupedBlocks = $allScriptBlocks | Group-Object ScriptBlockID

    Write-Host "`n=== POWERSHELL SCRIPT BLOCK ANALYSIS (ID 4104) ===" -ForegroundColor Green
    
    # Sort groups by the TimeCreated of the FIRST block in the group
    $sortedGroups = $groupedBlocks | Sort-Object @{Expression={$_.Group[0].TimeCreated}}

    foreach ($group in $sortedGroups) {
        $sbId = $group.Name
        
        # Sort fragments within the group (1 of 3, 2 of 3, etc.)
        $fragments = $group.Group | Sort-Object MessageNumber
        
        # Meta info from the first fragment
        $meta = $fragments[0]

        Write-Host "------------------------------------------------"
        Write-Host "ScriptBlock ID : $sbId" -ForegroundColor Yellow
        Write-Host "Time (UTC)     : $($meta.TimeCreated)"
        Write-Host "Computer       : $($meta.ComputerName)"
        Write-Host "User (SID)     : $($meta.User)"
        Write-Host "Process ID     : $($meta.ProcessID)"
        Write-Host "Fragments      : $($fragments.Count) found / $($meta.MessageTotal) expected"
        Write-Host "--- Script Content ---" -ForegroundColor Cyan

        foreach ($frag in $fragments) {
            # Print text, handle potential nulls
            if ($frag.ScriptText) {
                Write-Host $frag.ScriptText
            }
        }
        Write-Host ""
    }
}

# Main
# ---------------------------------------------------------------------------
try {
    if ($Platform -like "Windows") {
        Analyze-Windows
    }
    elseif ($Platform -like "MacOs") {
        Analyze-MacOS
    }
}
catch {
    Write-Error "An unexpected error occurred during execution: $_"
}
finally {
    # Stop logging regardless of success/failure
    Stop-Transcript -ErrorAction SilentlyContinue
}
