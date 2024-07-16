# PowerShell Script to Collect Information for Domain Administration

# Define the path to the "audit" folder on the desktop
$desktopPath = [System.Environment]::GetFolderPath('Desktop')
$auditPath = Join-Path -Path $desktopPath -ChildPath "audit"

# Create the "audit" folder if it doesn't exist
if (-Not (Test-Path -Path $auditPath)) {
    New-Item -Path $auditPath -ItemType Directory | Out-Null
}

# Import Active Directory Module
Import-Module ActiveDirectory

# Collect information
$domainAdmins = Get-ADGroupMember -Identity "Domain Admins" | Measure-Object
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
$lastLogonUsers = Get-ADUser -Filter * -Property LastLogonDate | Select-Object Name, LastLogonDate
$lastLogonComputers = Get-ADComputer -Filter * -Property LastLogonDate | Select-Object Name, LastLogonDate

# Combine information into a single CSV
$auditData = @()

# Add summary information
$auditData += [PSCustomObject]@{
    DomainAdmins         = $domainAdmins.Count
    DnsWorking           = $dnsStatus
    ReplicationStatus    = $replicationStatus
    GpoCount             = $gpoCount
    UserCount            = $userCount
    DeviceCount          = $deviceCount
}

# Add DHCP scope information
foreach ($scope in $dhcpScopeFull) {
    $auditData += [PSCustomObject]@{
        DomainAdmins         = ''
        DnsWorking           = ''
        ReplicationStatus    = ''
        GpoCount             = ''
        UserCount            = ''
        DeviceCount          = ''
        ScopeId              = $scope.ScopeId
        PercentInUse         = $scope.PercentInUse
        NearlyFull           = $scope.NearlyFull
        LeaseDuration        = ''
        LastLogonUser        = ''
        LastLogonUserDate    = ''
        LastLogonComputer    = ''
        LastLogonComputerDate = ''
    }
}

# Add DHCP lease information
foreach ($lease in $dhcpLeaseTime) {
    $auditData += [PSCustomObject]@{
        DomainAdmins         = ''
        DnsWorking           = ''
        ReplicationStatus    = ''
        GpoCount             = ''
        UserCount            = ''
        DeviceCount          = ''
        ScopeId              = $lease.ScopeId
        PercentInUse         = ''
        NearlyFull           = ''
        LeaseDuration        = $lease.LeaseDuration.TotalHours
        LastLogonUser        = ''
        LastLogonUserDate    = ''
        LastLogonComputer    = ''
        LastLogonComputerDate = ''
    }
}

# Add last logon users information
foreach ($user in $lastLogonUsers) {
    $auditData += [PSCustomObject]@{
        DomainAdmins         = ''
        DnsWorking           = ''
        ReplicationStatus    = ''
        GpoCount             = ''
        UserCount            = ''
        DeviceCount          = ''
        ScopeId              = ''
        PercentInUse         = ''
        NearlyFull           = ''
        LeaseDuration        = ''
        LastLogonUser        = $user.Name
        LastLogonUserDate    = $user.LastLogonDate
        LastLogonComputer    = ''
        LastLogonComputerDate = ''
    }
}

# Add last logon computers information
foreach ($computer in $lastLogonComputers) {
    $auditData += [PSCustomObject]@{
        DomainAdmins         = ''
        DnsWorking           = ''
        ReplicationStatus    = ''
        GpoCount             = ''
        UserCount            = ''
        DeviceCount          = ''
        ScopeId              = ''
        PercentInUse         = ''
        NearlyFull           = ''
        LeaseDuration        = ''
        LastLogonUser        = ''
        LastLogonUserDate    = ''
        LastLogonComputer    = $computer.Name
        LastLogonComputerDate = $computer.LastLogonDate
    }
}

# Export to a single CSV file
$auditData | Export-Csv -Path "$auditPath\AuditReport.csv" -NoTypeInformation

Write-Output "Exported audit information to $auditPath\AuditReport.csv"
