[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]
    $DomainName,
    [Parameter(Mandatory = $true)]
    [ValidateSet("MX", "SPF", "Autodiscover")]
    $ServiceType
)

Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

$RequiredModules = @("Microsoft.Graph.Authentication","Microsoft.Graph.Identity.DirectoryManagement")

foreach ($Module in $RequiredModules)
{
    $CurrentVersion = Find-Module -Name $Module -Repository PSGallery
    $IsInstalled = Get-Module -Name $Module -ErrorAction SilentlyContinue

    if ($IsInstalled.Name -eq $Module)
    {
        continue
    }

    Else
    {
        Try
        {
            Write-Host -ForegroundColor Green -Object "Trying to install module $($Module) in Current User Scope..."
            Install-Module -Name $Module -Repository PSGallery -Scope CurrentUser -WarningAction SilentlyContinue -ErrorAction Stop -Verbose -AllowClobber
            Write-Host -ForegroundColor Green -Object "Successfully installed module $($Module) in Current User Scope."
        }

        Catch
        {
            Write-Host -ForegroundColor Red -Object "Module $($Module) could not be installed! Error $($_). Exiting..."
            Exit
        }
    }
}

# Import Graph modules
Foreach ($Module in $RequiredModules)
{
    Write-Host -ForegroundColor Green -Object "Importing Module $($Module)..."
    Import-Module -Name $Module -DisableNameChecking
}

# Connect to Microsoft Graph
Connect-MgGraph -Scopes Domain.Read.All -NoWelcome

# Retrieve domain data for e-mail related services
$Records = Get-MgDomainServiceConfigurationRecord -DomainId $DomainName | Where-Object SupportedService -EQ "Email"

Function Get-RecordTypeInfo
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Object]
        $Records,
        [Parameter(Mandatory = $true)]
        [string]
        $RecordType
    )

    $RecordData = $Records | Where-Object RecordType -EQ $($RecordType) | Select-Object Label, RecordType, Ttl, AdditionalProperties
    Return $RecordData
}

Switch ($ServiceType)
{
    "MX" { $MXData = Get-RecordTypeInfo -Records $Records -RecordType "MX"; Write-Host -ForegroundColor Green -Object "`nMX Record for Domain $($DomainName) should point to:`r"; Write-Host -ForegroundColor Yellow -Object "$($MXData.AdditionalProperties.mailExchange)`n" }
    "SPF" { $SPFData = Get-RecordTypeInfo -Records $Records -RecordType "TxT"; Write-Host -ForegroundColor Green -Object "`nSPF Record for Domain $($DomainName) should contain:`r"; Write-Host -ForegroundColor Yellow -Object "$($SPFData.AdditionalProperties.text)`n" }
    "Autodiscover" { $AutoDData = Get-RecordTypeInfo -Records $Records -RecordType "CNAME"; Write-Host -ForegroundColor Green -Object "`nAutodiscover CNAME Record for Domain $($DomainName) should point to:`r"; Write-Host -ForegroundColor Yellow -Object "$($AutoDData.AdditionalProperties.canonicalName)`n" }
}


