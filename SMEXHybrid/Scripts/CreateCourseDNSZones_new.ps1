[cmdletbinding()]

Param(
    [Parameter(Mandatory = $true)]
    [int]$NumberOfStudents,
    [string]$BasePath = "C:\Temp",
    [Parameter(Mandatory = $false)]    
    [DateTime]$StartDate,
    [String]$CoursePrefix = "sh",
    [switch]$InstallOrUpdateModules
)

# Enable TLS1.2 for this session
$TLS12Protocol = [System.Net.SecurityProtocolType] 'Tls12'
[System.Net.ServicePointManager]::SecurityProtocol = $TLS12Protocol

#
# Variable definition
#
$HelperModulePath = "https://github.com/EnterpriseTrainingCenter/ExchangeServer/tree/main/SMEXHybrid/Scripts/HelperFunctions.psm1"

# $Tenantname = "myetcat.onmicrosoft.com"
#
# Store TenantID, AppID nad Certificate Thumbrprint fpr Logon
$TenantID = "905c7919-c8cb-479e-b394-6286e2875f10"
$Appid = "cce9c388-81d5-409a-878a-2590339025a8"
$CertThumbprint = "A14DD5A483326C75641C82CB83118F4CD1A24CDF"

# DNS Zone names and IDs
$ParentZoneName = "myetc.at"
$UPNDomain = "@" + $ParentZoneName

# Get Calendarweek of specified $Startdate
if ($StartDate)
{
    $StartDateObject = Get-date $StartDate
    $CalendarWeek = (Get-Culture).Calendar.GetWeekOfYear($StartDateObject, [System.Globalization.CalendarWeekRule]::FirstFourDayWeek, ((Get-Culture).DateTimeFormat.FirstDayOfWeek))

    $CalendarYear = Get-Date -UFormat %y
    $CourseID = $CoursePrefix + $CalendarYear + $CalendarWeek
}

else
{
    $CourseID = $CoursePrefix
}

# Azure Role definition for DNS Admins
# $TrainerRoleDefinitionName = "Trainer Child DNS Zone Admin"
$StudentRoleDefinitionName = "Student DNS Zone Admin"

# Trainer DNS Admin Account
# $TrainerDNSAdminAccount = "trainer-dns-admin@myetc.at"

# Logfile path and logging
[string]$LogFileNamePrefix = "Create_" + $CourseID + "_DNSZones"
[string]$LogfileFullPath = Join-Path -Path $BasePath (Join-Path "Logs" ($LogFileNamePrefix + "_{0:yyyyMMdd-HHmmss}.log" -f [DateTime]::Now))
$Script:NoLogging

#File with user passwords
[string]$UserPasswordsFile = Join-Path -Path $BasePath (Join-Path "Passwords" ($CourseID + "_Student-DNS-Admin-Passwords_{0:yyyyMMdd-HHmmss}.txt" -f [DateTime]::Now))
# End Variable definition
#

# Main Script

# import or update modules and assemblies
Import-Module 
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

# Retrieve parent DNS zone information
$ParentZoneInfo = RetrieveParentDNSZone -ParentZoneName $ParentZoneName

# Retrieve ObjectId of Azure AD User Group "StudentDNSAdmins"
[string]$StudentDNSAdminGroupID = (Get-AzureADGroup -Filter "Displayname eq 'StudentDNSAdmins'").ObjectID

# Loop through usercount and perform the magic...
for ($i = 1; $i -le $NumberOfStudents; $i++)
{
    $StudentCourseID = $CourseID + $i.ToString()
    $StudentZoneID = $StudentCourseID + "." + $ParentZoneName
    $StudentUPN = ($StudentCourseID + $UPNDomain)

    # Create user account in AAD
    Write-Host "`r`n"
    NewAzureADUser -UserPrincipalName $StudentUPN
    
    # Retrieve the user Account
    Get-AzureADUser -ObjectId $StudentUPN | Out-Null
    
    # Wait for 20 seconds, so that AZ knows about the new user account...
    Write-Host -ForegroundColor Green "Waiting 20 seconds for AAD to converge..."
    Start-Sleep -Seconds 20
    
    # Create new DNS child zone
    NewDNSChildZone -ZoneName $StudentZoneID -ParentZoneName $ParentZoneInfo.Name -ResourceGroup $ParentZoneInfo.ResourceGroupName
    
    # Assign RBAC role for student user to DNS child zone
    AssignDNSAdminRole -ZoneName $StudentZoneID -SignInName $StudentUPN -Role $StudentRoleDefinitionName
    
    # Add student user account to dashboard group
    AddUserToGroup -UserPrincipalName $StudentUPN -GroupID $StudentDNSAdminGroupID
}

# Create Trainer Zone
$TrainerCourseID = $CourseID + "T"
$TrainerZoneID = $TrainerCourseID + "." + $ParentZoneName
NewDNSChildZone -ZoneName $TrainerZoneID -ParentZoneName $ParentZoneInfo.Name -ResourceGroup $ParentZoneInfo.ResourceGroupName
