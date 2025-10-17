[cmdletbinding()]

Param(
    [Parameter(Mandatory = $true)]
    [int]$NumberOfStudents,
    [string]$BasePath = 'C:\Temp',
    [Parameter(Mandatory = $false)]
    [DateTime]$StartDate,
    [String]$CoursePrefix,
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
$TenantID = '905c7919-c8cb-479e-b394-6286e2875f10'
$Appid = 'cce9c388-81d5-409a-878a-2590339025a8'
$CertThumbprint = (Get-ChildItem Cert:\CurrentUser\My |Where-Object Subject -eq "cn=DNSAdminServiceLogon").Thumbprint

# DNS Zone names and IDs
$ParentZoneName = 'myetc.at'
$UPNDomain = '@' + $ParentZoneName

# Get Calendarweek of specified $Startdate
if ($StartDate) {
    $StartDateObject = Get-Date $StartDate
    $CalendarWeek = (Get-Culture).Calendar.GetWeekOfYear($StartDateObject, [System.Globalization.CalendarWeekRule]::FirstFourDayWeek, ((Get-Culture).DateTimeFormat.FirstDayOfWeek))

    $CalendarYear = Get-Date -UFormat %y
    $CourseID = $CoursePrefix + $CalendarYear + $CalendarWeek
}

else {
    $CourseID = $CoursePrefix
}

# Azure Role definition for DNS Admins
# $TrainerRoleDefinitionName = "Trainer Child DNS Zone Admin"
$StudentRoleDefinitionName = 'Student DNS Zone Admin'

# Trainer DNS Admin Account
# $TrainerDNSAdminAccount = "trainer-dns-admin@myetc.at"

# Logfile path and logging
[string]$LogFileNamePrefix = 'Create_' + $CourseID + '_DNSZones'
[string]$LogfileFullPath = Join-Path -Path $BasePath (Join-Path 'Logs' ($LogFileNamePrefix + '_{0:yyyyMMdd-HHmmss}.log' -f [DateTime]::Now))
$Script:NoLogging

#File with user passwords
[string]$UserPasswordsFile = Join-Path -Path $BasePath (Join-Path 'Passwords' ($CourseID + '_Student-DNS-Admin-Passwords_{0:yyyyMMdd-HHmmss}.txt' -f [DateTime]::Now))
# End Variable definition
#

# Required modules
[array]$RequiredModules = @("Az.Accounts", "Az.Dns", "Az.Resources", "Microsoft.Entra.Authentication", "Microsoft.Entra.Users", "Microsoft.Entra.Groups")

# Logging function
function Write-LogFile {
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

    if ($ErrorInfo) {
        $logLine = '{0:d.M.y H:mm:ss} : {1}: {2} Error: {3}' -f [DateTime]::Now, $LogPrefix, $Message, $ErrorInfo.Exception.Message
    }

    else {
        $logLine = '{0:d.M.y H:mm:ss} : {1}: {2}' -f [DateTime]::Now, $LogPrefix, $Message
    }

    if (!$Script:NoLogging) {
        # Create the Script:Logfile and folder structure if it doesn't exist
        if (-not (Test-Path $Script:LogfileFullPath -PathType Leaf)) {
            New-Item -ItemType File -Path $Script:LogfileFullPath -Force -Confirm:$false -WhatIf:$false | Out-Null
            Add-Content -Value 'Logging started.' -Path $Script:LogfileFullPath -Encoding UTF8 -WhatIf:$false -Confirm:$false
        }

        # Write to the Script:Logfile
        Add-Content -Value $logLine -Path $Script:LogfileFullPath -Encoding UTF8 -WhatIf:$false -Confirm:$false
        Write-Verbose $logLine
    }
    else {
        Write-Host $logLine
    }
}

# Function to write user passwords to a file
function WriteUserPasswordsToFile {
    [CmdLetBinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Username,
        [Parameter(Mandatory = $true)]
        [string]$PW
    )

    # Create the userinfo string
    # Format: Username,Password
    $UserInfo = ($Username + ',' + $PW)

    # Check if the passwords file exists, if not create it
    if (-not (Test-Path $UserPasswordsFile -PathType Leaf))
    {
        # Create the passwords file
        New-Item -ItemType File -Path $UserPasswordsFile -Force -Confirm:$false -WhatIf:$false | Out-Null
        # Add the header line to the file
        # Header: Username,Password
        Add-Content -Value 'Username,Password' -Path $UserPasswordsFile -Encoding UTF8 -WhatIf:$false -Confirm:$false
    }

    # Append the userinfo to the file
    Add-Content -Value $UserInfo -Path $UserPasswordsFile -Encoding UTF8 -WhatIf:$false -Confirm:$false
    Write-Verbose $UserInfo

}

# Function to create the DNS child zone
function NewDNSChildZone {
    [cmdletbinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$ZoneName,
        [Parameter(Mandatory = $true)]
        [string]$ParentZoneName,
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroup
    )

    try {
        New-AzDnsZone -Name $ZoneName -ParentZoneName $ParentZoneName -ResourceGroupName $ResourceGroup -ErrorAction Stop
        $Message = 'Successfully created DNS zone'
        Write-Host -ForegroundColor Green ($Message + ' ' + $ZoneName)
        Write-LogFile -LogPrefix $ZoneName -Message $Message
    }

    catch {
        $Errormessage = 'Could not create DNS zone'
        Write-Host -ForegroundColor Red ($Errormessage + ' ' + $ZoneName) -Exception $_
        Write-LogFile -LogPrefix $ZoneName -Message $Errormessage -ErrorInfo $_
    }
}

# Function to create a secure password
function GeneratePassword {
    function Get-RandomCharacters($length, $characters) {
        $random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length }
        $private:ofs = ''
        return [String]$characters[$random]
    }

    function Scramble-String([string]$inputString) {
        $characterArray = $inputString.ToCharArray()
        $scrambledStringArray = $characterArray | Get-Random -Count $characterArray.Length
        $outputString = -join $scrambledStringArray
        return $outputString
    }

    $PW = Get-RandomCharacters -length 5 -characters 'abcdefghiklmnoprstuvwxyz'
    $PW += Get-RandomCharacters -length 1 -characters 'ABCDEFGHKLMNOPRSTUVWXYZ'
    $PW += Get-RandomCharacters -length 2 -characters '1234567890'
    $PW = Scramble-String $PW
    Return $PW
}

# Function to create a new custom role in Azure
function AssignDNSAdminRole {
    [cmdletbinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$ZoneName,
        [Parameter(Mandatory = $true)]
        [string]$SignInName,
        [Parameter(Mandatory = $true)]
        [String]$Role
    )

    #    $RoleDefinition = Get-AzRoleDefinition -Name $Role
    $Scope = (Get-AzResource -Name $ZoneName).ResourceId

    if ($Scope) {
        try {
            New-AzRoleAssignment -SignInName $SignInName -RoleDefinitionName $Role -Scope $Scope -ErrorAction Stop -WarningAction SilentlyContinue
            $Message = "Successfully assigned role $Role to User $SignInName for Scope $Scope"
            Write-Host -ForegroundColor Green $Message
            Write-LogFile -LogPrefix $ZoneName -Message $Message
        }

        catch {
            $Errormessage = "Failed to assign role $Role to user $SignInName for Scope $Scope"
            Write-Host -ForegroundColor Red $Errormessage
            Write-LogFile -LogPrefix $ZoneName -Message $Errormessage -ErrorInfo $_
        }
    }

    else {
        $Message = 'No Scope was found for role assignment'
        Write-LogFile -LogPrefix $ZoneName -Message $Message
    }
}

# Function to create a new Entra user
function NewEntraUser {
    [cmdletbinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName
    )

    # Instantiate Passwordprofile object
    $PWProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile

    # Encrypt password
    $PW = GeneratePassword

    # Assign password
    $PWProfile.Password = $PW

    # Disable passwordpolicy enforcement and do not require change password at next login
    $PWProfile.EnforceChangePasswordPolicy = $false
    $PWProfile.ForceChangePasswordNextLogin = $false

    # Create Entra user
    try {
        $Username = $UserPrincipalName.Split('@')[0].ToUpper()
        $newuser = New-EntraUser -DisplayName $Username -AccountEnabled $true -UserPrincipalName $UserPrincipalName -PasswordProfile $PWProfile -MailNickName $Username -ErrorAction Stop
        $Message = 'Successfully created user'
        Write-Host -ForegroundColor Green ($Message + ' ' + $Username)
        Write-LogFile -LogPrefix $UserPrincipalName -Message $Message
    }

    catch {
        $Errormessage = 'Could not create user'
        Write-Host -ForegroundColor Red ($Errormessage + ' ' + $Username + ':' + $_)
        Write-LogFile -LogPrefix $UserPrincipalName -Message $Errormessage -ErrorInfo $_
    }

    if (-not [System.String]::IsNullOrEmpty($newuser))
    {
        WriteUserPasswordsToFile -Username $UserPrincipalName -PW $PW
    }
}

function AddUserToGroup {
    [cmdletbinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName,
        [Parameter(Mandatory = $true)]
        [string]$GroupID
    )

    $GroupLogPrefix = 'Group StudentDNSAdmins'

    try {
        $ReferenceUserID = (Get-EntraUser -ObjectId $UserPrincipalName).ObjectID
        Add-EntraGroupMember -ObjectId $GroupID -RefObjectId $ReferenceUserID -ErrorAction Stop
        Write-LogFile -Message "Sucessfully added User $UserPrincipalName as member of group." -LogPrefix $GroupLogPrefix
    }

    catch {
        $GroupErrorMessage = "Could not add User $UserPrincipalName as member if the group"
        Write-LogFile -LogPrefix $GroupLogPrefix -Message $GroupErrorMessage -ErrorInfo $_
    }
}

# Function to connect to Azure
function ConnectToOnlineService {
    [cmdletbinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Azure', 'Entra')]
        [string]$ServiceName
    )

    $LogPrefixConnection = 'Connection'
    # Connect to Azure or Entra ID using the specified ServiceName
    Write-LogFile -LogPrefix $LogPrefixConnection -Message "Connecting to $ServiceName Tenant with AppID $Appid and Certificate Thumbprint $CertThumbprint"
    try {
        Switch ($ServiceName) {
            'Azure' { Connect-AzAccount -ApplicationId $Appid -CertificateThumbprint $CertThumbprint -Tenant $TenantID -ErrorAction Stop }
            'Entra' { Connect-Entra -ClientId $Appid -CertificateThumbprint $CertThumbprint -TenantId $TenantID -ErrorAction Stop }
        }

        $Message = "Successfully connected to $ServiceName Tenant."
        Write-Host -ForegroundColor Green $Message
        Write-LogFile -LogPrefix $LogPrefixConnection -Message $Message
    }

    catch {
        $Errormessage = "Could not connect to $ServiceName"
        Write-Host -ForegroundColor Red -Message $Errormessage
        Write-LogFile -LogPrefix $LogPrefixConnection -Message $Errormessage -ErrorInfo $_
        Throw $_
        Exit
    }
}

# Function to retrieve parent DNS zone information
function RetrieveParentDNSZone {
    [cmdletbinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$ParentZoneName
    )

    try {
        $ParentZone = Get-AzDnsZone | Where-Object Name -EQ $ParentZoneName -ErrorAction Stop
        $Message = 'Successfully retrieved properties from parent DNS zone'
        #            Write-Verbose -Message ($Message + " for zone " + $ParentZoneName)
        Write-LogFile -LogPrefix $ParentZoneName -Message $Message
        Return $ParentZone
    }

    catch {
        $Errormessage = 'Could not retrieve parent DNS Zone properties.'
        #            Write-Error -Message $Errormessage -Exception $_
        Write-LogFile -LogPrefix $ParentZoneName -Message $Errormessage -Exception $_
        Throw $_
        Exit
    }
}

Function InstallOrUpdateModule
{
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$ModuleName
    )

    $LogPrefixModules = 'Module loading'
    $InstalledModuleVersion = (Get-Module -ListAvailable | Where-Object Name -EQ $($ModuleName) | Sort-Object Version -Descending | Select-Object Version -First 1).Version

    if ($InstalledModuleVersion)
    {

        $OnlineModuleVersion = (Find-Module $ModuleName).Version

        if ($OnlineModuleVersion -gt $InstalledModuleVersion)
        {
            Write-Host -ForegroundColor Green "A newer version for module $ModuleName is available. Trying to update..."
            Remove-Module $ModuleName -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

            try
            {
                Update-Module -Name $ModuleName -Force -ErrorAction Stop
                $Message = "Module $Modulename successfully updated"
                Write-Host -ForegroundColor Green $Message
                Write-LogFile -LogPrefix $LogPrefixModules -Message $Message
            }

            catch
            {
                Write-LogFile -LogPrefix $LogPrefixModules -Message "Unable to update module $Modulename" -ErrorInfo $_
                Write-Host -ForegroundColor Red "Unable to update module $ModuleName. See logfile for details."
                Exit
            }
        }
    }

    else {
        try {
            Install-Module -Name $ModuleName -Force -ErrorAction Stop -Scope CurrentUser
            $Message = "Module $Modulename successfully installed"
            Write-Host -ForegroundColor Green $Message
            Write-LogFile -LogPrefix $LogPrefixModules -Message $Message
        }

        catch {
            Write-LogFile -LogPrefix $LogPrefixModules -Message "Unable to install module $Modulename" -ErrorInfo $_
            Write-Host -ForegroundColor Red "Unable to install module $ModuleName. See logfile for details."
            Exit
        }
    }
}
function ImportModule
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ModuleName
    )

    try {
        Import-Module -Name $ModuleName -ErrorAction Stop -WarningAction SilentlyContinue
        $Message = "Successfully loaded module $Modulename"
        Write-Host -ForegroundColor Green $Message
        Write-LogFile -LogPrefix $LogPrefixModules -Message $Message
    }

    catch {
        Write-LogFile -LogPrefix $LogPrefixModules -Message "Unable to import module $Modulename" -ErrorInfo $_
        Write-Host -ForegroundColor Red "Unable to import module $ModuleName. See logfile for details."
        Exit
    }
}
#
# Main Script

# import or update modules and assemblies
if ($InstallOrUpdateModules) {
    Write-Host -ForegroundColor Green 'Updating and importing modules...'
    Import-Module PackageManagement
    Import-Module PowerShellGet
    foreach ($module in $RequiredModules)
    {
        InstallOrUpdateModule -ModuleName $module
    }
}

# Import modules without updating
Write-Host -ForegroundColor Green 'Importing modules...'
foreach ($module in $RequiredModules)
{
    ImportModule -ModuleName $module
}

# Connect to Azure
ConnectToOnlineService -ServiceName Azure

# Connect to Entra ID
ConnectToOnlineService -ServiceName Entra

# Retrieve parent DNS zone information
$ParentZoneInfo = RetrieveParentDNSZone -ParentZoneName $ParentZoneName

# Retrieve ObjectId of Entra ID User Group "StudentDNSAdmins"
[string]$StudentDNSAdminGroupID = (Get-EntraGroup -Filter "Displayname eq 'StudentDNSAdmins'").ObjectID

# Loop through usercount and perform the magic...
for ($i = 1; $i -le $NumberOfStudents; $i++) {
    $StudentCourseID = $CourseID + $i.ToString()
    $StudentZoneID = $StudentCourseID + '.' + $ParentZoneName
    $StudentUPN = ($StudentCourseID + $UPNDomain)

    # Create user account in Entra
    Write-Host "`r`n"
    NewEntraUser -UserPrincipalName $StudentUPN

    # Retrieve the user Account
    Get-EntraUser -ObjectId $StudentUPN | Out-Null

    # Wait for 20 seconds, so that AZ knows about the new user account...
    Write-Host -ForegroundColor Green 'Waiting 20 seconds for Entra to converge...'
    Start-Sleep -Seconds 20

    # Create new DNS child zone
    NewDNSChildZone -ZoneName $StudentZoneID -ParentZoneName $ParentZoneInfo.Name -ResourceGroup $ParentZoneInfo.ResourceGroupName

    # Assign RBAC role for student user to DNS child zone
    AssignDNSAdminRole -ZoneName $StudentZoneID -SignInName $StudentUPN -Role $StudentRoleDefinitionName

    # Add student user account to dashboard group
    AddUserToGroup -UserPrincipalName $StudentUPN -GroupID $StudentDNSAdminGroupID
}

# Create Trainer Zone
$TrainerCourseID = $CourseID + 'T'
$TrainerZoneID = $TrainerCourseID + '.' + $ParentZoneName
NewDNSChildZone -ZoneName $TrainerZoneID -ParentZoneName $ParentZoneInfo.Name -ResourceGroup $ParentZoneInfo.ResourceGroupName
