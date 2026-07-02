$ski = [System.Guid]::NewGuid().ToString(“N”)
$cert = New-ExchangeCertificate -FriendlyName “Microsoft Federation Gateway” -DomainName yourdomain.com -Services Federation -KeySize 2048 -PrivateKeyExportable $true -SubjectKeyIdentifier $ski
Get-FederationTrust | Set-FederationTrust -Thumbprint $cert.Thumbprint
