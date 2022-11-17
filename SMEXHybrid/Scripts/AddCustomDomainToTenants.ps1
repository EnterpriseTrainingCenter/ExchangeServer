$Domains = @("mig22481.myetc.at", "mig22483.myetc.at", "mig22484.myetc.at", "mig22485.myetc.at", "mig22486.myetc.at", "mig2248t.myetc.at")
$Tenants = Get-AzTenant | Where-Object Name -ne "MyETC"
Import-Module $HelperModulePath
$TrainerDNSAdminAccount = "trainer-dns-admin@myetc.at"

foreach ($domain in $Domains)
{
    $Tenant = $tenants | Where-Object Domains -Match $domain.Split(".")[0]
    Connect-AzureAD -TenantId $Tenant.Id -AccountId $TrainerDNSAdminAccount
    AddCustomDomain -Domain $Domain
}