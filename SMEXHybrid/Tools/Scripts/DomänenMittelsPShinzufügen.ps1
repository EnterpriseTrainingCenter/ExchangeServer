install-Module msonline
Connect-MSOLService
Get-MSOLDomain
Import-Csv -Path C:\Users\administrator.SMART\Documents\Domains.txt |% {New-MsolDomain -Name $_.Name}
Import-Csv -Path C:\Users\administrator.SMART\Documents\Domains.txt |% {(Get-MsolDomainVerificationDns -DomainName $_.Name -Mode DnsTxtRecord).Text}
Import-Csv -Path C:\Users\administrator.SMART\Documents\Domains.txt |% {Confirm-MsolDomain -DomainName $_.Name}
