$c = New-ExchangeCertificate -DomainName mail.smexhX.myetc.at,autodiscover.smexhX.myetc.at,sts.smexhX.myetc.at -GenerateRequest -KeySize 2048 -PrivateKeyExportable $true -FriendlyName SMEXH-Cert -Server EX2019-1
Set-Item -Value $c -Path C:\smexh.txt
