[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$Domain
)

# Enable TLS1.2 for this session
$TLS12Protocol = [System.Net.SecurityProtocolType] 'Tls12'
[System.Net.ServicePointManager]::SecurityProtocol = $TLS12Protocol

#
# Variable definition
#
# Store TenantID, AppID nad Certificate Thumbrprint fpr Logon
$TenantID = "905c7919-c8cb-479e-b394-6286e2875f10"
$Appid = "cce9c388-81d5-409a-878a-2590339025a8"
$CertThumbprint = "A14DD5A483326C75641C82CB83118F4CD1A24CDF"

# Import Modules
Import-Module Az.Accounts
Import-Module Az.DNS
Import-Module Az.Resources
Import-Module AzureAD

# Connect to Azure AD
Connect-AzureAD

# Connect to "myetcat.onmicrosoft.com" Azure Tenant with Application User
Connect-AzAccount -ApplicationId $Appid -CertificateThumbprint $CertThumbprint -Tenant $TenantID

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

# Check status of Domain
$DomainState = Get-AzureADDomain -Name $Domain

# If the domain is verfified, delete the DNS TXT record
if ($DomainState.IsVerified -eq $true)
{
    Remove-AzDnsRecordSet -ZoneName $Domain -Name "@" -RecordType TXT -ResourceGroupName DNS-RG -Confirm:$false
}



