$AgentsAvBin = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\Bin'))
# GEDR Detection Job
# Converted from GEDR C# job - FULL IMPLEMENTATION

param([hashtable]$ModuleConfig)

$ModuleName = "CredentialHardening"
$script:LastRun = [DateTime]::MinValue
$script:TickInterval = 3600
$script:SelfPid = $PID

# Helper function for deduplication
function Test-ShouldReport {
    param([string]$Key)
    
    if ($null -eq $script:ReportedItems) {
        $script:ReportedItems = @{}
    }
    
    if ($script:ReportedItems.ContainsKey($Key)) {
        return $false
    }
    
    $script:ReportedItems[$Key] = [DateTime]::UtcNow
    return $true
}

# Helper function for logging
function Write-Detection {
    param(
        [string]$Message,
        [string]$Level = "THREAT",
        [string]$LogFile = "credentialhardening_detections.log"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [$ModuleName] $Message"
    
    # Write to console
    switch ($Level) {
        "THREAT" { Write-Host $logEntry -ForegroundColor Red }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "INFO" { Write-Host $logEntry -ForegroundColor Cyan }
        default { Write-Host $logEntry }
    }
    
    # Write to log file
    $logPath = Join-Path $env:LOCALAPPDATA "GEDR\Logs"
    if (-not (Test-Path $logPath)) { New-Item -ItemType Directory -Path $logPath -Force | Out-Null }
    Add-Content -Path (Join-Path $logPath $LogFile) -Value $logEntry -ErrorAction SilentlyContinue
}

# Helper function for threat response
function Invoke-ThreatResponse {
    param(
        [int]$ProcessId,
        [string]$ProcessName,
        [string]$Reason
    )
    
    Write-Detection "Threat response triggered for $ProcessName (PID: $ProcessId) - $Reason"
    
    # Don't kill critical system processes
    $criticalProcesses = @("System", "smss", "csrss", "wininit", "services", "lsass", "svchost", "dwm", "explorer")
    if ($criticalProcesses -contains $ProcessName) {
        Write-Detection "Skipping critical process: $ProcessName" -Level "WARNING"
        return
    }
    
    try {
        Stop-Process -Id $ProcessId -Force -ErrorAction Stop
        Write-Detection "Terminated process: $ProcessName (PID: $ProcessId)"
    }
    catch {
        Write-Detection "Failed to terminate $ProcessName (PID: $ProcessId): $($_.Exception.Message)" -Level "WARNING"
    }
}

function Start-Detection {
    # File-based detection
    $scanPaths = @(
        "$env:TEMP",
        "$env:LOCALAPPDATA\Temp",
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Desktop"
    )
    
    $suspiciousExtensions = @(".exe", ".dll", ".ps1", ".vbs", ".bat", ".cmd", ".scr")
    
    foreach ($basePath in $scanPaths) {
        if (-not (Test-Path $basePath)) { continue }
        
        try {
            $files = Get-ChildItem -Path $basePath -File -ErrorAction SilentlyContinue | 
                     Where-Object { $suspiciousExtensions -contains $_.Extension.ToLower() }
            
            foreach ($file in $files) {
                $key = "File_$($file.FullName)"
                if (Test-ShouldReport -Key $key) {
                    Write-Detection "Suspicious file found: $($file.FullName)" -Level "WARNING"
                }
            }
        }
        catch {
            # Silent continue on access errors
        }
    }
    # Registry-based detection
    $registryPaths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    
    foreach ($regPath in $registryPaths) {
        if (-not (Test-Path $regPath)) { continue }
        
        try {
            $entries = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
            $properties = $entries.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" }
            
            foreach ($prop in $properties) {
                $value = $prop.Value
                if ($value -match "\.exe|\.dll|\.ps1|\.vbs|\.bat|powershell|cmd\.exe") {
                    $key = "Reg_$regPath_$($prop.Name)"
                    if (Test-ShouldReport -Key $key) {
                        Write-Detection "Registry persistence found: $regPath\$($prop.Name) = $value" -Level "WARNING"
                    }
                }
            }
        }
        catch {
            # Silent continue on access errors
        }
    }
    # Driver monitoring
    try {
        $drivers = Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | 
                   Where-Object { $_.State -eq "Running" }
        
        foreach ($drv in $drivers) {
            if ($drv.PathName) {
                $pathLower = $drv.PathName.ToLower()
                
                # Check for drivers loaded from non-standard paths
                if ($pathLower -notmatch "system32\\drivers|windows") {
                    $key = "Drv_$($drv.Name)"
                    if (Test-ShouldReport -Key $key) {
                        Write-Detection "Non-standard driver path: $($drv.Name) - $($drv.PathName)" -Level "WARNING"
                    }
                }
            }
        }
    }
    catch {
        # Silent continue on driver errors
    }
}
# Main execution
function Invoke-CredentialHardening {
    $now = Get-Date
    if ($script:LastRun -ne [DateTime]::MinValue -and ($now - $script:LastRun).TotalSeconds -lt $script:TickInterval) {
        return
    }
    $script:LastRun = $now
    
    try {
        Start-Detection
    }
    catch {
        Write-Detection "Error in $ModuleName : $($_.Exception.Message)" -Level "ERROR"
    }
}

# Execute
Invoke-CredentialHardening

