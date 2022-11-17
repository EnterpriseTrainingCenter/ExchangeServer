function Write-LogFile
{
    # Logging function, used for progress and error logging...
    # Uses the globally (script scoped) configured variables 'LogfileFullPath' to identify the logfile and 'NoLogging' to disable it.
    #
    [CmdLetBinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [string]$LogSuffix,
        [System.Management.Automation.ErrorRecord]$ErrorInfo = $null
    )

    # Prefix the string to write with the current Date and Time, add error message if present...
    if ($ErrorInfo)
    {
        $logLine = "{0:d.M.y H:mm:ss}: ERROR {1} {2}: {3}" -f [DateTime]::Now, $Message, $LogSuffix, $ErrorInfo.Exception.Message
    }

    else
    {
        $logLine = "{0:d.M.y H:mm:ss}: INFO {1} {2}" -f [DateTime]::Now, $Message, $LogSuffix
    }

    if (!$Script:NoLogging)
    {
        # Create the Script:Logfile and folder structure if it doesn't exist
        if (-not (Test-Path $LogfileFullPath -PathType Leaf))
        {
            New-Item -ItemType File -Path $LogfileFullPath -Force -Confirm:$false -WhatIf:$false | Out-Null
            Add-Content -Value "Logging started." -Path $LogfileFullPath -Encoding UTF8 -WhatIf:$false -Confirm:$false
        }

        # Write to the Script:Logfile
        Add-Content -Value $logLine -Path $LogfileFullPath -Encoding UTF8 -WhatIf:$false -Confirm:$false
        Write-Verbose $logLine
    }

    else
    {
        Write-Host $logLine
    }
}

function WriteUserPasswordsToFile
{
    # Function to write User Passwords to a file

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

    # Create the UserPasswordsFile and folder structure if it doesn't exist
    if (-not (Test-Path $UserPasswordsFile -PathType Leaf))
    {
        New-Item -ItemType File -Path $UserPasswordsFile -Force -Confirm:$false -WhatIf:$false | Out-Null
        Add-Content -Value "Username,Password" -Path $UserPasswordsFile -Encoding UTF8 -WhatIf:$false -Confirm:$false
    }

    # Write to UserPasswordsFile
    Add-Content -Value $UserInfo -Path $UserPasswordsFile -Encoding UTF8 -WhatIf:$false -Confirm:$false
    Write-Verbose $UserInfo

}

function NewDNSChildZone
{
    # Function to create a DNS child zone in Azure DNS

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
        Write-LogFile -LogSuffix $ZoneName -Message $Message
    }
    
    catch
    {
        $Errormessage = "Could not create DNS zone"
        Write-Host -ForegroundColor Red ($Errormessage + " " + $ZoneName) -Exception $_
        Write-LogFile -LogSuffix $ZoneName -Message $Errormessage -ErrorInfo $_
    }
}

function ConvertTo-SecurePassword
{
    # Function convert a cleartext password to a scrambled password

    [cmdletbinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$inputString  
    )

    $characterArray = $inputString.ToCharArray()   
    $scrambledStringArray = $characterArray | Get-Random -Count $characterArray.Length     
    $Scrambledpassword = -join $scrambledStringArray
    return $Scrambledpassword
}

function GeneratePassword
{
    # Function to generate a random password

    function Get-RandomCharacters
    {
        [cmdletbinding()]
        Param
        (
            [Parameter(Mandatory = $true)]
            [int]$length,  
            [Parameter(Mandatory = $true)]
            [string]$characters
        )
    
        $random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length }
        $private:ofs = ""
        return [String]$characters[$random]
    }
    
    $ClearTextPassword = Get-RandomCharacters -length 5 -characters 'abcdefghiklmnoprstuvwxyz'
    $ClearTextPassword += Get-RandomCharacters -length 1 -characters 'ABCDEFGHKLMNOPRSTUVWXYZ'
    $ClearTextPassword += Get-RandomCharacters -length 2 -characters '1234567890'
    $SecurePassword = ConvertTo-SecurePassword -inputString $ClearTextPassword    
    Return $Securepassword
}

function NewAzureADUser
{
    # Function to create a new AzureAD User and set disable the 'User must change password at next logon' requirement
    [cmdletbinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName,
        [string]$ClearTextPwd
    )

    # Instantiate Passwordprofile object
    $PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile

    if ($ClearTextPwd)
    {
        # Encrypt the given password
        $SecurePassword = $ClearTextPwd
    }

    else
    {
        # Generate and encrypt password
        $SecurePassword = GeneratePassword
    }
    
    # Assign password
    $PasswordProfile.Password = $SecurePassword

    # Disable passwordpolicy enforcement and do not require change password at next login
    $PasswordProfile.EnforceChangePasswordPolicy = $false
    $PasswordProfile.ForceChangePasswordNextLogin = $false
    
    # Create AAD user
    try
    {
        $Username = $UserPrincipalName.Split("@")[0].ToLower()
        $NewUser = New-AzureADUser -DisplayName $Username -AccountEnabled $true -UserPrincipalName $UserPrincipalName -PasswordProfile $PasswordProfile -MailNickName $Username -ErrorAction Stop | Out-Null
        $Message = "Successfully created user"
        Write-Host -ForegroundColor Green ($Message + " " + $Username)
        Write-LogFile -LogSuffix $UserPrincipalName -Message $Message
        WriteUserPasswordsToFile -Username $UserPrincipalName -Password $SecurePassword
        Return $NewUser
    }
    
    catch
    {
        $Errormessage = "Could not create user"
        Write-Host -ForegroundColor Red ($Errormessage + " " + $Username + ":" + $_)
        Write-LogFile -LogSuffix $UserPrincipalName -Message $Errormessage -ErrorInfo $_
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
        [string]$GroupID,
        [string]$Groupname = "StudentDNSAdmins"
    )

    $GroupLogSuffix = $Groupname

    try
    {
        $ReferenceUserID = (Get-AzureADUser -ObjectId $UserPrincipalName).ObjectID
        Add-AzureADGroupMember -ObjectId $GroupID -RefObjectId $ReferenceUserID -ErrorAction Stop
        Write-LogFile -Message "Sucessfully added User $UserPrincipalName as member of group" -LogSuffix $GroupLogSuffix    
    }
    
    catch
    {
        $GroupErrorMessage = "Could not add User $UserPrincipalName as member of group"
        Write-LogFile -LogSuffix $GroupLogSuffix -Message $GroupErrorMessage -ErrorInfo $_
    }
}

function ConnectToOnlineService
{
    # Function to connect to Azure subscription and AzureAD with 'UserPrincipalname' or an AppId
    
    [cmdletbinding()]
    Param
    (
        [Parameter(Mandatory = $true, ParameterSetName = "UPN")]
        [Parameter(Mandatory = $true, ParameterSetName = "AppId")]
        [ValidateSet("Azure", "AzureAD")]
        [string]$ServiceName,
        [Parameter(Mandatory = $true, ParameterSetName = "UPN")]
        [Parameter(Mandatory = $true, ParameterSetName = "AppId")]
        [string]$TenantID,
        [Parameter(Mandatory = $true, ParameterSetName = "UPN")]
        [string]$UserPrincipalName,
        [Parameter(ParameterSetName = "AppId")]
        [switch]$UseAppId,
        [Parameter(Mandatory = $true, ParameterSetName = "AppId")]
        [string]$CertificateThumbprint,
        [Parameter(Mandatory = $true, ParameterSetName = "AppId")]
        [string]$ApplicationID
    )
    
    try
    {
        Switch ($ServiceName)
        {
            "Azure"
            {
                if ($ApplicationID)
                {
                    Connect-AzAccount -ApplicationId $ApplicationID -CertificateThumbprint $CertificateThumbprint -Tenant $TenantID -ErrorAction Stop
                }

                else
                {
                    Connect-AzAccount -Tenant $TenantID -AccountId $UserPrincipalName -ErrorAction Stop
                }
            }
                
            "AzureAD"
            {
                if ($ApplicationID)
                {
                    Connect-AzureAD -ApplicationId $ApplicationID -CertificateThumbprint $CertificateThumbprint -Tenant $TenantID -ErrorAction Stop
                }

                else
                {
                    Connect-AzureAD -TenantId $TenantID -AccountId $UserPrincipalName -ErrorAction Stop    
                }
            }
        }
        
        $Message = "Successfully connected to $ServiceName in Tenant"
        Write-Host -ForegroundColor Green $Message
        Write-LogFile -LogSuffix $TenantID -Message $Message
    }

    catch
    {
        $Errormessage = "Could not connect to $ServiceName in Tenant"
        Write-Host -ForegroundColor Red -Message $Errormessage -Exception $_
        Write-LogFile -LogSuffix $TenantID -Message $Errormessage -ErrorInfo $_
        Throw $_
        Exit
    }
}

function AssignAADAdminRole
{
    # Function to assign AzureAD roles to user accounts

    [cmdletbinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName,
        [string]$RoleName = "Global Administrator"
    )

    $LogSuffixRoleAssignment = "AAD Role Assignment"

    try
    {
        $UserObject = Get-AzureADUser -ObjectId $UserPrincipalName -ErrorAction Stop
    }

    catch
    {
        $Errormessage = "Unable to fetch user $UserPrincipalName for"
        Write-Host -ForegroundColor Red -Message $Errormessage -Exception $_
        Write-LogFile -LogSuffix $LogSuffixRoleAssignment -Message $Errormessage -ErrorInfo $_
        Throw $_
        Exit
    }

    try
    {
        $AdminRoleDefinition = Get-AzureADMSRoleDefinition | Where-Object Displayname -EQ $Rolename -ErrorAction Stop
    }

    catch
    {
        $Errormessage = "Unable to fetch role definition for $RoleName for"
        Write-Host -ForegroundColor Red -Message $Errormessage -Exception $_
        Write-LogFile -LogSuffix $LogSuffixRoleAssignment -Message $Errormessage -ErrorInfo $_
        Throw $_
        Exit
    }

    try
    {
        New-AzureADMSRoleAssignment -DirectoryScopeId '/' -RoleDefinitionId $AdminRoleDefinition.Id -PrincipalId $UserObject.objectId -ErrorAction Stop
        $Message = "Successfully assigned role $RoleName to user $UserPrincipalName."
        Write-Host -ForegroundColor Green $Message
        Write-LogFile -Message $Message
    }

    catch
    {
        $Errormessage = "Unable to assign role $RoleName to user $UserPrincipalName"
        Write-Host -ForegroundColor Red -Message $Errormessage -Exception $_
        Write-LogFile -Message $Errormessage -ErrorInfo $_
        Throw $_
        Exit
    }


}

function AssignAzureRole
{
    # Function to assign Azure roles to user accounts

    [cmdletbinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Resourcename,
        [Parameter(Mandatory = $true)]
        [string]$SignInName,
        [Parameter(Mandatory = $true)]
        [String]$Role
    )

    $Scope = (Get-AzResource -Name $Resourcename).ResourceId

    if ($Scope)
    {
        try
        {
            New-AzRoleAssignment -SignInName $SignInName -RoleDefinitionName $Role -Scope $Scope -ErrorAction Stop -WarningAction SilentlyContinue
            $Message = "Successfully assigned role $Role to User $SignInName for"
            Write-Host -ForegroundColor Green $Message
            Write-LogFile -LogSuffix $Resourcename -Message $Message          
        }
        
        catch
        {
            $Errormessage = "Failed to assign role $Role to user $SignInName for"
            Write-Host -ForegroundColor Red $Errormessage
            Write-LogFile -LogSuffix $Resourcename -Message $Errormessage -ErrorInfo $_
        }
    }

    else
    {
        $Message = "No Scope for role assignment was found for resource"
        Write-LogFile -LogSuffix $Resourcename -Message $Message 
    }
}

function RetrieveParentDNSZone
{
    # Function to retrieve an Azure DNS parent zone

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
        # Write-Verbose -Message ($Message + " for zone " + $ParentZoneName)
        Write-LogFile -LogSuffix $ParentZoneName -Message $Message
        Return $ParentZone
    }

    catch
    {
        $Errormessage = "Could not retrieve parent DNS Zone properties for zone"
        # Write-Error -Message $Errormessage -Exception $_
        Write-LogFile -LogSuffix $ParentZoneName -Message $Errormessage -ErrorInfo $_
        Throw $_
        Exit
    }
}

Function UpdateAndImportModule
{
    # Function to update and import modules

    Param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName
    )

    $LogSuffixModules = "Module loading"
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
                Write-LogFile -Message $Message
            }

            catch
            {
                Write-Host -ForegroundColor Red "Unable to update module $ModuleName. See logfile for details."
                Write-LogFile -Message "Unable to update module $Modulename" -ErrorInfo $_
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
            Write-LogFile -Message $Message
        }

        catch
        {
            Write-Host -ForegroundColor Red "Unable to install module $ModuleName. See logfile for details."
            Write-LogFile -Message "Unable to install module $Modulename" -ErrorInfo $_
            Exit
        }
    }

    try
    {
        Import-Module -Name $ModuleName -ErrorAction Stop -WarningAction SilentlyContinue
        $Message = "Successfully loaded module $Modulename"
        Write-Host -ForegroundColor Green $Message
        Write-LogFile -Message $Message
    }

    catch
    {
        Write-Host -ForegroundColor Red "Unable to import module $ModuleName. See logfile for details."
        Write-LogFile -Message "Unable to import module $Modulename" -ErrorInfo $_
        Exit
    }
}
function AddCustomDomain
{
    # Function to add and verify a custom domain to an azure tenant

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Domain
    )

    # Add new Domain to AAD
    New-AzureADDomain -Name $Domain

    # Retrieve DNS verfication record value
    $TxTRecordValueString = (Get-AzureADDomainVerificationDnsRecord -Name $Domain | Where-Object RecordType -EQ "Txt").Text
    $TxTRecordValue = New-AzDnsRecordConfig -Value $TxTRecordValueString

    # Create DNS record for verification
    New-AzDnsRecordSet -Name "@" -ZoneName $Domain -RecordType TXT -ResourceGroupName DNS-RG -DnsRecords $TxTRecordValue -Ttl 300
    Start-Sleep -Seconds 10

    # Verify domain
    Confirm-AzureADDomain -Name $Domain

    # If the domain is verfified, delete the DNS TXT record
    while ((Get-AzureADDomain -Name $Domain).IsVerified -eq $false)
    {Start-Sleep -Seconds 5}
    
    Remove-AzDnsRecordSet -ZoneName $Domain -Name "@" -RecordType TXT -ResourceGroupName DNS-RG -Confirm:$false
}

Export-ModuleMember -Function *
