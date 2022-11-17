
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

$Tenants = Get-AzTenant | Where-Object Name -ne "MyETC"
foreach ($tenant in $Tenants)
{


}
