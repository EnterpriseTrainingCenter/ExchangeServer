[cmdletbinding()]

Param(
    [string]$BasePath = "C:\Temp",
    [string]$CoursePrefix = "sh",
    [switch]$InstallOrUpdateModules
)

# Enable TLS1.2 for this session
$TLS12Protocol = [System.Net.SecurityProtocolType] 'Tls12'
[System.Net.ServicePointManager]::SecurityProtocol = $TLS12Protocol

#
# Variable definition
#
# 
# $Tenantname = "myetcat.onmicrosoft.com"
#
# Store TenantID, AppID nad Certificate Thumbrprint fpr Logon
$TenantID = "905c7919-c8cb-479e-b394-6286e2875f10"
$Appid = "cce9c388-81d5-409a-878a-2590339025a8"
$CertThumbprint = "A14DD5A483326C75641C82CB83118F4CD1A24CDF"


# Logfile path and logging
[string]$LogfileFullPath = Join-Path -Path $BasePath (Join-Path "Logs" ("RemoveSMEXhybridDNSZones_{0:yyyyMMdd-HHmmss}.log" -f [DateTime]::Now))
$Script:NoLogging

$StudentDNSAdmins = "StudentDNSAdmins"

# End Variable definition
#

# Logging function
function Write-LogFile
{
    # Logging function, used for progress and error logging...
    # Uses the globally (script scoped) configured LogfileFullPath variable to identify the logfile and NoLogging to disable it.
    #
    [CmdLetBinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [string]$LogPrefix,
        [System.Management.Automation.ErrorRecord]$ErrorInfo = $null
    )
    # Prefix the string to write with the current Date and Time, add error message if present...

    if ($ErrorInfo)
    {
        $logLine = "{0:d.M.y H:mm:ss} : {1}: {2} Error: {3}" -f [DateTime]::Now, $LogPrefix, $Message, $ErrorInfo.Exception.Message
    }

    else
    {
        $logLine = "{0:d.M.y H:mm:ss} : {1}: {2}" -f [DateTime]::Now, $LogPrefix, $Message
    }

    if (!$Script:NoLogging)
    {
        # Create the Script:Logfile and folder structure if it doesn't exist
        if (-not (Test-Path $Script:LogfileFullPath -PathType Leaf))
        {
            New-Item -ItemType File -Path $Script:LogfileFullPath -Force -Confirm:$false -WhatIf:$false | Out-Null
            Add-Content -Value "Logging started." -Path $Script:LogfileFullPath -Encoding UTF8 -WhatIf:$false -Confirm:$false
        }

        # Write to the Script:Logfile
        Add-Content -Value $logLine -Path $Script:LogfileFullPath -Encoding UTF8 -WhatIf:$false -Confirm:$false
        Write-Verbose $logLine
    }
    else
    {
        Write-Host $logLine
    }
}

# Function to connect to Azure

function ConnectToOnlineService
{
    [cmdletbinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Azure", "AzureAD")]
        [string]$ServiceName
    )
    
    $LogPrefixConnection = "Connection"

    try
    {
        Switch ($ServiceName)
        {
            "Azure" { Connect-AzAccount -ApplicationId $Appid -CertificateThumbprint $CertThumbprint -Tenant $TenantID -ErrorAction Stop }
            "AzureAD" { Connect-AzureAD -ApplicationId $Appid -CertificateThumbprint $CertThumbprint -Tenant $TenantID -ErrorAction Stop }
        }
        
        $Message = "Successfully connected to $ServiceName."
        Write-Host -ForegroundColor Green $Message
        Write-LogFile -LogPrefix $LogPrefixConnection -Message $Message
    }

    catch
    {
        $Errormessage = "Could not connect to $ServiceName"
        Write-Host -ForegroundColor Red -Message $Errormessage -Exception $_
        Write-LogFile -LogPrefix $LogPrefixConnection -Message $Errormessage -ErrorInfo $_
        Throw $_
        Exit
    }
}

Function UpdateAndImportModule
{
    Param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName
    )

    $LogPrefixModules = "Module loading"
    $InstalledModuleVersion = (Get-Module -ListAvailable | Where-Object Name -eq $($ModuleName) | Sort-Object Version -Descending | Select-Object Version -First 1).Version

    if ($InstalledModuleVersion)
    {

        $OnlineModuleVersion = (Find-Module $ModuleName).Version

        if ($OnlineModuleVersion -gt $InstalledModuleVersion)
        {
            Remove-Module $ModuleName -Force -ErrorAction SilentlyContinue

            try
            {
                Update-Module -Name $ModuleName -Force -ErrorAction Stop
                Write-LogFile -LogPrefix $LogPrefixModules -Message "Module $Modulename successfully updated"
            }

            catch
            {
                Write-LogFile -LogPrefix $LogPrefixModules -Message "Unable to update module $Modulename" -ErrorInfo $_
                Write-Host -ForegroundColor Red "Unable to update module $ModuleName. See logfile for details."
                Exit
            }
        }
    }

    else
    {
        try
        {
            Install-Module -Name $ModuleName -Force -ErrorAction Stop -Scope CurrentUser
            Write-LogFile -LogPrefix $LogPrefixModules -Message "Module $Modulename successfully installed"
        }

        catch
        {
            Write-LogFile -LogPrefix $LogPrefixModules -Message "Unable to install module $Modulename" -ErrorInfo $_
            Write-Host -ForegroundColor Red "Unable to install module $ModuleName. See logfile for details."
            Exit
        }
    }

    try
    {
        Import-Module -Name $ModuleName -ErrorAction Stop -WarningAction SilentlyContinue
        Write-LogFile -LogPrefix $LogPrefixModules -Message "Successfully loaded module $Modulename"
    }

    catch
    {
        Write-LogFile -LogPrefix $LogPrefixModules -Message "Unable to import module $Modulename" -ErrorInfo $_
        Write-Host -ForegroundColor Red "Unable to import module $ModuleName. See logfile for details."
        Exit
    }
}

#
# Main Script

# import or update modules and assemblies
if ($InstallOrUpdateModules)
{   
    Write-Host -ForegroundColor Green "Updating and importing modules..."
    Import-Module PackageManagement
    Import-Module PowerShellGet 
    UpdateAndImportModule -ModuleName Az.Accounts
    UpdateAndImportModule -ModuleName Az.DNS
    UpdateAndImportModule -ModuleName Az.Resources
    UpdateAndImportModule -ModuleName AzureAD
}

else
{
    Write-Host -ForegroundColor Green "Importing modules..."
    Import-Module Az.Accounts
    Import-Module Az.Dns
    Import-Module Az.Resources
    Import-Module AzureAD
}

# Connect to Azure
ConnectToOnlineService -ServiceName Azure

# Connect to Azure AD
ConnectToOnlineService -ServiceName AzureAD

# Retrieve Group Members of StudentDNSAdmins Group
$Group = Get-AzureADGroup -SearchString $StudentDNSAdmins
$GroupMembers = $Group | Get-AzureADGroupMember | Where-Object UserPrincipalname -like "$($CoursePrefix)*"

# Remove Users
foreach ($GroupMember in $GroupMembers)
{
    $LogPrefixUsers = "User removal"
    try
    {
        $UserSuccessMessage = "Successfully removed user $($GroupMember.UserPrincipalname) from Group $StudentDNSAdmins"
        Remove-AzureADGroupMember -ObjectId $Group.ObjectID -MemberId $GroupMember.ObjectID -ErrorAction Stop
        Write-LogFile -LogPrefix $LogPrefixUsers -Message $UserSuccessMessage
        Write-Host -ForegroundColor Green -Object $UserSuccessMessage
    }

    catch
    {
        $UserCatchMessage = "Unable to remove user $($GroupMember.UserPrincipalname) from Group $StudentDNSAdmins"
        Write-LogFile -LogPrefix $LogPrefixUsers -Message $UserCatchMessage -ErrorInfo $_
        Write-Host -ForegroundColor Red "$($UserCatchMessage). See logfile for details."
    }

    try
    {
        $UserSuccessMessage = "Successfully removed user $($GroupMember.UserPrincipalname)"
        Remove-AzureADUser -ObjectId $GroupMember.ObjectId -ErrorAction Stop
        Write-LogFile -LogPrefix $LogPrefixUsers -Message $UserSuccessMessage
        Write-Host -ForegroundColor Green -Object $UserSuccessMessage
    }

    catch
    {
        $UserCatchMessage = "Unable to remove user $($GroupMember.UserPrincipalname)"
        Write-LogFile -LogPrefix $LogPrefixUsers -Message $UserCatchMessage -ErrorInfo $_
        Write-Host -ForegroundColor Red "$($UserCatchMessage). See logfile for details."
    } 

}

# Retrieve DNS Zones
$DNSZones = Get-AzDnsZone -ResourceGroupName DNS-RG | Where-Object Name -Like "$($CoursePrefix)*.myetc.at"

# Remove DNS Zones and NS Records
foreach ($DNSZone in $DNSZones)
{
    $LogPrefixZones = "Remove DNS Zones"

    try
    { 
        $ZoneSuccessMessage = "Successfully removed DNS Zone $($DNSZone.Name)"
        Remove-AzDnsZone -Name $DNSZone.Name -ResourceGroupName "DNS-RG" -Confirm:$false -ErrorAction Stop
        Write-LogFile -LogPrefix $LogPrefixZones -Message $ZoneSuccessMessage
        Write-Host -ForegroundColor Green -Object $ZoneSuccessMessage
    }
    
    catch
    {
        $ZoneCatchMessage = "Unable to remove DNS Zone $($DNSZone.Name)"
        Write-LogFile -LogPrefix $LogPrefixZones -Message $ZoneCatchMessage -ErrorInfo $_
        Write-Host -ForegroundColor Red "$($ZoneCatchMessage). See logfile for details."
    }

    try
    {
        $RecordSuccessMessage = "Successfully removed DNS delegation record for Zone $($DNSZone.Name)"
        Remove-AzDnsRecordSet -Name $DNSZone.Name.Split(".")[0] -RecordType NS -ZoneName "myetc.at" -ResourceGroupName "DNS-RG" -Confirm:$false -ErrorAction Stop
        Write-LogFile -LogPrefix $LogPrefixZones -Message $RecordSuccessMessage
        Write-Host -ForegroundColor Green -Object $RecordSuccessMessage
    }
    
    catch
    {
        $RecordCatchMessage = "Unable to remove DNS delegation record for Zone $($DNSZone.Name)"
        Write-LogFile -LogPrefix $LogPrefixZones -Message $RecordCatchMessage -ErrorInfo $_
        Write-Host -ForegroundColor Red -Object "$($RecordCatchMessage). See logfile for details."
    }
}
