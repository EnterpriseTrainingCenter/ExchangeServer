PARAM
(
[Parameter(Mandatory=$true)]
[string]$Domain
)

$FQDN = "mail." + $Domain
Get-OWAVirtualDirectory -ADPropertiesOnly -Server EX2019-2 | Set-OwaVirtualDirectory -InternalUrl https://$FQDN/owa -ExternalUrl https://$FQDN/owa
Get-ECPVirtualDirectory -ADPropertiesOnly -Server EX2019-2 | Set-ECPVirtualDirectory -InternalUrl https://$FQDN/ecp -ExternalUrl https://$FQDN/ecp
Get-OabVirtualDirectory -ADPropertiesOnly -Server EX2019-2 | Set-OabVirtualDirectory -InternalUrl https://$FQDN/oab -ExternalUrl https://$FQDN/oab -RequireSSL $true
Get-ActiveSyncVirtualDirectory -ADPropertiesOnly -Server EX2019-2 | Set-ActiveSyncVirtualDirectory -ExternalUrl https://$FQDN/Microsoft-Server-ActiveSync
Get-WebServicesVirtualDirectory -ADPropertiesOnly -Server EX2019-2 | Set-WebServicesVirtualDirectory -InternalUrl https://$FQDN/ews/exchange.asmx -ExternalUrl https://$FQDN/ews/exchange.asmx -Confirm:$true -Force
Get-MapiVirtualDirectory -ADPropertiesOnly -Server EX2019-2 | Set-MAPIVirtualDirectory -InternalURL https://$FQDN/mapi -ExternalURL https://$FQDN/mapi -IISAuthenticationMethods Negotiate,NTLM,Basic
Get-ClientAccessService | Set-ClientAccessService –AutoDiscoverServiceInternalUri https://$FQDN/autodiscover/autodiscover.xml
Get-OutlookAnywhere -ADPropertiesOnly -Server EX2019-2 | Set-OutlookAnywhere -ExternalHostname $FQDN -DefaultAuthenticationMethod Negotiate -SSLOffloading $false -ExternalClientsRequireSsl $true
