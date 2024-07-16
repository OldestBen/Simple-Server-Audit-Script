# Define the output path for the audit folder and the CSV file
$desktopPath = [environment]::GetFolderPath("Desktop")
$auditFolder = Join-Path -Path $desktopPath -ChildPath "audit"
$csvPath = Join-Path -Path $auditFolder -ChildPath "server_info.csv"

# Create the audit folder if it does not exist
if (-not (Test-Path -Path $auditFolder)) {
    New-Item -Path $auditFolder -ItemType Directory
}

# Function to get server IP address and check if it's static
function Get-ServerIPInfo {
    $ipInfo = Get-NetIPAddress | Where-Object { $_.AddressFamily -eq 'IPv4' -and $_.IPAddress -ne '127.0.0.1' -and $_.InterfaceAlias -ne "Loopback Pseudo-Interface 1" }
    $ipAddress = ($ipInfo | Select-Object -First 1).IPAddress
    $isStatic = ($ipInfo | Select-Object -First 1).PrefixOrigin -eq 'Manual'
    return @($ipAddress, $isStatic)
}

# Function to determine access method
function Get-AccessMethod {
    $accessMethods = @()

    # Check for the presence of specific software
    $installedPrograms = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
                         Select-Object DisplayName
    $installedPrograms += Get-ItemProperty "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
                          Select-Object DisplayName

    $softwareChecks = @{
        "TeamViewer"    = "TeamViewer"
        "ITSupport247"  = "ConnectWise"
        "ScreenConnect" = "ScreenConnect"
    }

    foreach ($key in $softwareChecks.Keys) {
        if ($installedPrograms.DisplayName -match $softwareChecks[$key]) {
            $accessMethods += $key
        }
    }

    # If no specific software is found
    if ($accessMethods.Count -eq 0) {
        $accessMethods = "PLEASE REVIEW"
    } else {
        $accessMethods = $accessMethods -join ", "
    }

    return $accessMethods
}

# Function to format uptime in days, hours, and minutes
function Format-Uptime {
    param ($lastBootUpTime)
    
    $uptimeSpan = [DateTime]::Now - $lastBootUpTime
    $days = $uptimeSpan.Days
    $hours = $uptimeSpan.Hours
    $minutes = $uptimeSpan.Minutes

    return "$days days, $hours hours, $minutes minutes"
}

# Function to get server roles
function Get-ServerRoles {
    # Check if the machine is domain joined
    $domainRole = (Get-WmiObject Win32_ComputerSystem).DomainRole
    $serverRoles = @()

    if ($domainRole -ge 3) { # 3 and above indicates the machine is domain joined
        # Get FSMO roles
        try {
            $fsmoRoles = Get-ADDomain | Select-Object -ExpandProperty FSMORoleOwner
            $serverRoles = $fsmoRoles -join ", "
        } catch {
            $serverRoles = "Domain Joined but FSMO roles cannot be determined"
        }
    } else {
        # Check if Hyper-V is installed
        $hyperVInstalled = Get-WindowsFeature -Name Hyper-V | Select-Object -ExpandProperty InstallState
        if ($hyperVInstalled -eq "Installed") {
            $serverRoles = "Hypervisor"
        } else {
            $serverRoles = "Non-domain joined, no Hyper-V"
        }
    }

    return $serverRoles
}

# Function to get recent errors from event logs
function Get-RecentErrors {
    $errorLogs = @()
    $logs = @("Application", "Security", "System")
    foreach ($log in $logs) {
        $errors = Get-EventLog -LogName $log -EntryType Error -Newest 10 -ErrorAction SilentlyContinue
        if ($errors) {
            $errorLogs += $errors | Select-Object -Property TimeGenerated, Source, EventID, Message
        }
    }
    return $errorLogs
}

# Function to get CPU and RAM usage
function Get-SystemUsage {
    $cpu = Get-WmiObject Win32_Processor | Measure-Object -Property LoadPercentage -Average | Select-Object -ExpandProperty Average
    $totalMemory = (Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory
    $freeMemory = (Get-WmiObject Win32_OperatingSystem).FreePhysicalMemory * 1024
    $usedMemory = $totalMemory - $freeMemory
    $memoryUsage = [math]::Round(($usedMemory / $totalMemory) * 100, 2)

    return @{
        CPUUsage = "$cpu %"
        MemoryUsage = "$memoryUsage %"
        TotalMemory = "{0:N2} GB" -f ($totalMemory / 1GB)
        UsedMemory = "{0:N2} GB" -f ($usedMemory / 1GB)
        FreeMemory = "{0:N2} GB" -f ($freeMemory / 1GB)
    }
}

# Function to get drive information and shares
function Get-DriveInfoAndShares {
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -gt 0 }
    $driveInfo = @()
    $shares = Get-SmbShare | Where-Object { $_.Special -eq $false }
    foreach ($drive in $drives) {
        $freeSpace = [math]::Round($drive.Free / 1GB, 2)
        $usedSpace = [math]::Round($drive.Used / 1GB, 2)
        $totalSize = [math]::Round(($drive.Used + $drive.Free) / 1GB, 2)
        $driveStatus = Check-DriveHealth -Drive $drive.Name
        $driveShares = $shares | Where-Object { $_.Path -eq $drive.Root }

        $shareNames = $driveShares | ForEach-Object { $_.Name }
        $shareNames = $shareNames -join ", "
        
        $driveInfo += [PSCustomObject]@{
            Drive = $drive.Name
            FreeSpace = "$freeSpace GB"
            UsedSpace = "$usedSpace GB"
            TotalSize = "$totalSize GB"
            Status = $driveStatus
            Shares = $shareNames
        }
    }
    return $driveInfo
}

# Function to check for failed or predictive fail drives using iDRAC/ILO
function Check-DriveHealth {
    param (
        [string]$Drive
    )
    # Placeholder for iDRAC/ILO checks, depending on tools availability
    $idracStatus = Check-iDRACDriveHealth -Drive $Drive
    $iloStatus = Check-ILODriveHealth -Drive $Drive

    if ($idracStatus) {
        return $idracStatus
    } elseif ($iloStatus) {
        return $iloStatus
    } else {
        return "Unknown"
    }
}

# Function to check iDRAC drive health (example)
function Check-iDRACDriveHealth {
    param (
        [string]$Drive
    )
    try {
        $racadmOutput = racadm storage get pdisks -o -p state, predictiveFailure -r 0
        $diskInfo = $racadmOutput | Where-Object { $_ -match $Drive }
        if ($diskInfo -match "Predicted failure") {
            return "Predicted failure"
        } elseif ($diskInfo -match "Failure") {
            return "Failure"
        } else {
            return "Healthy"
        }
    } catch {
        return $null
    }
}

# Function to check ILO drive health (example)
function Check-ILODriveHealth {
    param (
        [string]$Drive
    )
    try {
        $iloOutput = hponcfg /w ilo_status.xml
        $iloXml = [xml](Get-Content ilo_status.xml)
        $diskInfo = $iloXml.SelectNodes("//Drive[Name='$Drive']")
        foreach ($disk in $diskInfo) {
            if ($disk.PredictiveFailure -eq "true") {
                return "Predicted failure"
            } elseif ($disk.Status -ne "OK") {
                return "Failure"
            }
        }
        return "Healthy"
    } catch {
        return $null
    }
}

# Function to get the number of shares
function Get-ShareCount {
    $shares = Get-SmbShare | Where-Object { $_.Special -eq $false }
    return $shares.Count
}

# Function to get security software information
function Get-SecuritySoftware {
    $securitySoftwareNames = @(
        "Windows Defender",
        "Norton",
        "McAfee",
        "Bitdefender",
        "Symantec",
        "Kaspersky",
        "Trend Micro",
        "Sophos",
        "ESET",
        "CrowdStrike",
        "Palo Alto",
        "Carbon Black",
        "F-Secure",
        "Avast",
        "Cisco",
        "Webroot",
        "SentinelOne",
        "Malwarebytes",
        "Comodo",
        "FireEye",
        "ZoneAlarm",
        "Avira",
        "Heimdal",
        "WatchGuard",
        "Fortinet",
        "G DATA",
        "Check Point",
        "VIPRE",
        "Ivanti",
        "Cylance",
        "SecPod",
        "Absolute",
        "ArcSight",
        "Ziften",
        "Bromium",
        "Cybereason",
        "Elastic",
        "Proofpoint",
        "AhnLab",
        "Seqrite",
        "Quick Heal",
        "Panda",
        "N-able",
        "Sentinel",
        "Deep Instinct"
    )
    
    $installedSecuritySoftware = @()
    
    $installedPrograms = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
                         Select-Object DisplayName
    $installedPrograms += Get-ItemProperty "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
                          Select-Object DisplayName

    foreach ($software in $securitySoftwareNames) {
        if ($installedPrograms.DisplayName -match $software) {
            $installedSecuritySoftware += $software
        }
    }

    if ($installedSecuritySoftware.Count -gt 0) {
        return $installedSecuritySoftware -join ", "
    } else {
        return "No security software found"
    }
}

# Function to check if Windows Defender is running
function Check-WindowsDefenderRunning {
    $defenderStatus = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
    if ($defenderStatus -and $defenderStatus.Status -eq 'Running') {
        return "Running"
    } else {
        return "Not Running"
    }
}

# Function to check if RDP is enabled
function Check-RDPEnabled {
    $rdpStatus = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\' -Name "fDenyTSConnections"
    if ($rdpStatus.fDenyTSConnections -eq 0) {
        return "Enabled"
    } else {
        return "Disabled"
    }
}

# Collecting server information
$serverName = $env:COMPUTERNAME
$serverIPInfo = Get-ServerIPInfo
$serverIPAddress = $serverIPInfo[0]
$isStaticIP = if ($serverIPInfo[1]) { "Yes" } else { "No" }
$serverRoles = Get-ServerRoles
$accessMethod = Get-AccessMethod
$isVirtualMachine = if ((Get-WmiObject -Class Win32_ComputerSystem).Model -match "Virtual") { "Yes" } else { "No" }
$lastBootUpTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$uptime = Format-Uptime -lastBootUpTime $lastBootUpTime
$serverOSVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ProductName
$systemUsage = Get-SystemUsage
$driveInfo = Get-DriveInfoAndShares
$shareCount = Get-ShareCount
$securitySoftware = Get-SecuritySoftware
$windowsDefenderStatus = Check-WindowsDefenderRunning
$rdpStatus = Check-RDPEnabled

# Export server information to CSV
$serverInfo = [PSCustomObject]@{
    ServerName = $serverName
    ServerIPAddress = $serverIPAddress
    IsStaticIP = $isStaticIP
    ServerRoles = $serverRoles
    AccessMethod = $accessMethod
    IsVirtualMachine = $isVirtualMachine
    Uptime = $uptime
    OSVersion = $serverOSVersion
    CPUUsage = $systemUsage.CPUUsage
    MemoryUsage = $systemUsage.MemoryUsage
    TotalMemory = $systemUsage.TotalMemory
    UsedMemory = $systemUsage.UsedMemory
    FreeMemory = $systemUsage.FreeMemory
    ShareCount = $shareCount
    SecuritySoftware = $securitySoftware
    WindowsDefenderStatus = $windowsDefenderStatus
    RDPStatus = $rdpStatus
}

$serverInfo | Export-Csv -Path $csvPath -NoTypeInformation

# Export drive information and shares to CSV
$driveInfoPath = Join-Path -Path $auditFolder -ChildPath "drive_info.csv"
$driveInfo | Export-Csv -Path $driveInfoPath -NoTypeInformation

# Export Event Viewer logs
$eventLogPath = Join-Path -Path $auditFolder -ChildPath "EventLogs"
if (-not (Test-Path -Path $eventLogPath)) {
    New-Item -Path $eventLogPath -ItemType Directory
}

$logs = @("Application", "Security", "System")
foreach ($log in $logs) {
    Get-EventLog -LogName $log | Export-Clixml -Path (Join-Path -Path $eventLogPath -ChildPath "$log.xml")
}

# Get recent errors and write to a text file
$recentErrors = Get-RecentErrors
$errorReportPath = Join-Path -Path $eventLogPath -ChildPath "RecentErrors.txt"
$recentErrors | Format-Table -AutoSize | Out-String | Set-Content -Path $errorReportPath

Write-Output "Server information and event logs have been exported to $auditFolder"

# Attempt to run domain administration tasks
try {
    # PowerShell Script to Collect Information for Domain Administration

    # Define the path to the "audit" folder on the desktop
    $auditPath = Join-Path -Path $desktopPath -ChildPath "audit"

    # Create the "audit" folder if it doesn't exist
    if (-Not (Test-Path -Path $auditPath)) {
        New-Item -Path $auditPath -ItemType Directory | Out-Null
    }

    # Import Active Directory Module
    Import-Module ActiveDirectory

    # Collect information
    $domainAdmins = Get-ADGroupMember -Identity "Domain Admins" | Select-Object -ExpandProperty Name
    $domainAdminNames = $domainAdmins -join "; "
    $dhcpScope = Get-DhcpServerv4Scope
    $dhcpScopeFull = foreach ($scope in $dhcpScope) {
        $percentInUse = ($scope.ScopeStatistics.PercentageInUse)
        [PSCustomObject]@{
            ScopeId        = $scope.ScopeId
            PercentInUse   = $percentInUse
            NearlyFull     = if ($percentInUse -gt 80) { "Yes" } else { "No" }
        }
    }
    $dhcpLeaseTime = Get-DhcpServerv4Scope | Select-Object ScopeId, LeaseDuration
    $dnsStatus = if (Resolve-DnsName -Name "google.com" -ErrorAction SilentlyContinue) { "Yes" } else { "No" }
    $computerName = [System.Environment]::MachineName
    $secondDC = Get-ADDomainController -Filter {Name -ne $computerName} | Select-Object -First 1
    $replicationStatus = if ($secondDC) {
        if (Get-ADReplicationPartnerMetadata -Target $secondDC.HostName) {
            "Working"
        } else {
            "Not Working"
        }
    } else {
        "No second DC found."
    }
    $gpoCount = (Get-Gpo -All).Count
    $userCount = (Get-ADUser -Filter *).Count
    $deviceCount = (Get-ADComputer -Filter *).Count

    # Combine information into a single CSV
    $auditData = @()

    # Add summary information
    $auditData += [PSCustomObject]@{
        DomainAdminNames     = $domainAdminNames
        DomainAdminCount     = $domainAdmins.Count
        DnsWorking           = $dnsStatus
        ReplicationStatus    = $replicationStatus
        GpoCount             = $gpoCount
        UserCount            = $userCount
        DeviceCount          = $deviceCount
        ScopeId              = ''
        PercentInUse         = ''
        NearlyFull           = ''
        LeaseDuration        = ''
    }

    # Add DHCP scope information
    foreach ($scope in $dhcpScopeFull) {
        $auditData += [PSCustomObject]@{
            DomainAdminNames     = ''
            DomainAdminCount     = ''
            DnsWorking           = ''
            ReplicationStatus    = ''
            GpoCount             = ''
            UserCount            = ''
            DeviceCount          = ''
            ScopeId              = $scope.ScopeId
            PercentInUse         = $scope.PercentInUse
            NearlyFull           = $scope.NearlyFull
            LeaseDuration        = ''
        }
    }

    # Add DHCP lease information
    foreach ($lease in $dhcpLeaseTime) {
        $auditData += [PSCustomObject]@{
            DomainAdminNames     = ''
            DomainAdminCount     = ''
            DnsWorking           = ''
            ReplicationStatus    = ''
            GpoCount             = ''
            UserCount            = ''
            DeviceCount          = ''
            ScopeId              = $lease.ScopeId
            PercentInUse         = ''
            NearlyFull           = ''
            LeaseDuration        = $lease.LeaseDuration.TotalHours
        }
    }

    # Export to a single CSV file
    $auditData | Export-Csv -Path "$auditPath\Domain and related services information.csv" -NoTypeInformation

    # Export last logged in users and computers
    $lastLoggedInInfo = Get-ADUser -Filter * -Property LastLogonDate | Select-Object Name, LastLogonDate
    $lastLoggedInInfo += Get-ADComputer -Filter * -Property LastLogonDate | Select-Object Name, LastLogonDate
    $lastLoggedInInfo | Export-Csv -Path "$auditPath\LastLoggedInUsersAndComputers.csv" -NoTypeInformation

    Write-Output "Exported audit information to $auditPath\Domain and related services information.csv"
    Write-Output "Exported last logged in users and computers to $auditPath\LastLoggedInUsersAndComputers.csv"

} catch {
    $errorInfo = "could not complete - are you sure this is a domain controller?"
    $auditData = [PSCustomObject]@{
        DomainAdminNames     = $errorInfo
        DomainAdminCount     = $errorInfo
        DnsWorking           = $errorInfo
        ReplicationStatus    = $errorInfo
        GpoCount             = $errorInfo
        UserCount            = $errorInfo
        DeviceCount          = $errorInfo
        ScopeId              = $errorInfo
        PercentInUse         = $errorInfo
        NearlyFull           = $errorInfo
        LeaseDuration        = $errorInfo
    }
    $auditData | Export-Csv -Path "$auditPath\Domain and related services information.csv" -NoTypeInformation
    Write-Output "Error: $errorInfo"
}
