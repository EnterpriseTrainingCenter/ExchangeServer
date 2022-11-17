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
# 
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

# Function to write user passwords to a file
function WriteUserPasswordsToFile
{
    [CmdLetBinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Username,
        [Parameter(Mandatory = $true)]
        [string]$Password
    )
    # Prefix the string to write with the current Date and Time, add error message if present...

    $UserInfo = ($Username + "," + $Password)

    # Create the Script:Logfile and folder structure if it doesn't exist
    if (-not (Test-Path $UserPasswordsFile -PathType Leaf))
    {
        New-Item -ItemType File -Path $UserPasswordsFile -Force -Confirm:$false -WhatIf:$false | Out-Null
        Add-Content -Value "Username,Password" -Path $UserPasswordsFile -Encoding UTF8 -WhatIf:$false -Confirm:$false
    }

    # Write to the Script:Logfile
    Add-Content -Value $UserInfo -Path $UserPasswordsFile -Encoding UTF8 -WhatIf:$false -Confirm:$false
    Write-Verbose $UserInfo

}

# Function to create the DNS child zone
function NewDNSChildZone
{
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

    try
    {
        New-AzDnsZone -Name $ZoneName -ParentZoneName $ParentZoneName -ResourceGroupName $ResourceGroup -ErrorAction Stop
        $Message = "Successfully created DNS zone"
        Write-Host -ForegroundColor Green ($Message + " " + $ZoneName)
        Write-LogFile -LogPrefix $ZoneName -Message $Message
    }
    
    catch
    {
        $Errormessage = "Could not create DNS zone"
        Write-Host -ForegroundColor Red ($Errormessage + " " + $ZoneName) -Exception $_
        Write-LogFile -LogPrefix $ZoneName -Message $Errormessage -ErrorInfo $_
    }
}

# Function to create a secure password
function GeneratePassword
{
    function Get-RandomCharacters($length, $characters)
    {
        $random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length }
        $private:ofs = ""
        return [String]$characters[$random]
    }
    
    function Scramble-String([string]$inputString)
    {     
        $characterArray = $inputString.ToCharArray()   
        $scrambledStringArray = $characterArray | Get-Random -Count $characterArray.Length     
        $outputString = -join $scrambledStringArray
        return $outputString 
    }
    
    $password = Get-RandomCharacters -length 5 -characters 'abcdefghiklmnoprstuvwxyz'
    $password += Get-RandomCharacters -length 1 -characters 'ABCDEFGHKLMNOPRSTUVWXYZ'
    $password += Get-RandomCharacters -length 2 -characters '1234567890'
    $password = Scramble-String $password    
    Return $password
}

# Function to create a new custom role in Azure
function AssignDNSAdminRole
{
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

    if ($Scope)
    {
        try
        {
            New-AzRoleAssignment -SignInName $SignInName -RoleDefinitionName $Role -Scope $Scope -ErrorAction Stop -WarningAction SilentlyContinue
            $Message = "Successfully assigned role $Role to User $SignInName for Scope $Scope"
            Write-Host -ForegroundColor Green $Message
            Write-LogFile -LogPrefix $ZoneName -Message $Message          
        }
        
        catch
        {
            $Errormessage = "Failed to assign role $Role to user $SignInName for Scope $Scope"
            Write-Host -ForegroundColor Red $Errormessage
            Write-LogFile -LogPrefix $ZoneName -Message $Errormessage -ErrorInfo $_
        }
    }

    else
    {
        $Message = "No Scope was found for role assignment"
        Write-LogFile -LogPrefix $ZoneName -Message $Message 
    }
}

# Function to create a new AAD user
function NewAzureADUser
{
    [cmdletbinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName
    )

    # Instantiate Passwordprofile object
    $PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile

    # Encrypt password
    $Password = GeneratePassword

    # Assign password
    $PasswordProfile.Password = $Password

    # Disable passwordpolicy enforcement and do not require change password at next login
    $PasswordProfile.EnforceChangePasswordPolicy = $false
    $PasswordProfile.ForceChangePasswordNextLogin = $false
    
    # Create AAD user
    try
    {
        $Username = $UserPrincipalName.Split("@")[0].ToUpper()
        $NewUser = New-AzureADUser -DisplayName $Username -AccountEnabled $true -UserPrincipalName $UserPrincipalName -PasswordProfile $PasswordProfile -MailNickName $Username -ErrorAction Stop | Out-Null
        $Message = "Successfully created user"
        Write-Host -ForegroundColor Green ($Message + " " + $Username)
        Write-LogFile -LogPrefix $UserPrincipalName -Message $Message
        WriteUserPasswordsToFile -Username $UserPrincipalName -Password $Password
        Return $NewUser
    }
    
    catch
    {
        $Errormessage = "Could not create user"
        Write-Host -ForegroundColor Red ($Errormessage + " " + $Username + ":" + $_)
        Write-LogFile -LogPrefix $UserPrincipalName -Message $Errormessage -ErrorInfo $_
    }
}

function AddUserToGroup
{
    [cmdletbinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName,
        [Parameter(Mandatory = $true)]
        [string]$GroupID 
    )

    $GroupLogPrefix = "Group StudentDNSAdmins"

    try
    {
        $ReferenceUserID = (Get-AzureADUser -ObjectId $UserPrincipalName).ObjectID
        Add-AzureADGroupMember -ObjectId $GroupID -RefObjectId $ReferenceUserID -ErrorAction Stop
        Write-LogFile -Message "Sucessfully added User $UserPrincipalName as member of group." -LogPrefix $GroupLogPrefix    
    }
    
    catch
    {
        $GroupErrorMessage = "Could not add User $UserPrincipalName as member if the group"
        Write-LogFile -LogPrefix $GroupLogPrefix -Message $GroupErrorMessage -ErrorInfo $_
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
        
        $Message = "Successfully connected to $ServiceName Tenant."
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

# Function to retrieve parent DNS zone information
function RetrieveParentDNSZone
{
    [cmdletbinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$ParentZoneName
    )

    try
    {
        $ParentZone = Get-AzDnsZone | Where-Object Name -EQ $ParentZoneName -ErrorAction Stop
        $Message = "Successfully retrieved properties from parent DNS zone"
        #            Write-Verbose -Message ($Message + " for zone " + $ParentZoneName)
        Write-LogFile -LogPrefix $ParentZoneName -Message $Message
        Return $ParentZone
    }

    catch
    {
        $Errormessage = "Could not retrieve parent DNS Zone properties."
        #            Write-Error -Message $Errormessage -Exception $_
        Write-LogFile -LogPrefix $ParentZoneName -Message $Errormessage -Exception $_
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

    else
    {
        try
        {
            Install-Module -Name $ModuleName -Force -ErrorAction Stop -Scope CurrentUser
            $Message = "Module $Modulename successfully installed"
            Write-Host -ForegroundColor Green $Message
            Write-LogFile -LogPrefix $LogPrefixModules -Message $Message
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
        $Message = "Successfully loaded module $Modulename"
        Write-Host -ForegroundColor Green $Message
        Write-LogFile -LogPrefix $LogPrefixModules -Message $Message
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
