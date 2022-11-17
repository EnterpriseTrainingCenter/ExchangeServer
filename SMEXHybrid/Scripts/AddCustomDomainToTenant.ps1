function AddCustomDomain
{
    
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

# Check status of Domain
$DomainState = Get-AzureADDomain -Name $Domain

# If the domain is verfified, delete the DNS TXT record
if ($DomainState.IsVerified -eq $true)
{
    Remove-AzDnsRecordSet -ZoneName $Domain -Name "@" -RecordType TXT -ResourceGroupName DNS-RG -Confirm:$false
}
}



