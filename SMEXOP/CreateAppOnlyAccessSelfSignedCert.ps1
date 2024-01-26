[cmdletbinding()]
Param(
    $ExportPath
)

# Create self signed cert for App only access to exchange online management shell
$cert = New-SelfSignedCertificate -KeyLength 2048 -Subject "cn=ExchangeOnline-ReadOnlyApp" -CertStoreLocation Cert:\CurrentUser\My\ -KeySpec KeyExchange -Provider "Microsoft Strong Cryptographic Provider"

$ExportFileName = (Join-Path -Path Cert:\CurrentUser\My -ChildPath $cert.Thumbprint)

# Export public key to .cer fuile
Export-Certificate -Cert $ExportFileName -FilePath (Join-Path -Path $ExportPath -ChildPath "ExchangeOnline-ReadOnlyApp.cer")

# Export Keypair
Export-PfxCertificate -Cert $ExportFileName -FilePath (Join-Path -Path $ExportPath -ChildPath "ExchangeOnline-ReadOnlyApp.pfx") -Password (ConvertTo-SecureString -AsPlainText -Force -String 'Pa$$w0rd')
