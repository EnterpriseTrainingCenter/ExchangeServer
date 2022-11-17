[cmdletbinding()]

Param(
[Parameter(Mandatory = $true)]
[System.IO.FileInfo]$Path
)

# Import Excel Module
if (Get-Module -ListAvailable ImportExcel)
{
    Import-Module ImportExcel
}

Else
{
    Write-Host -ForegroundColor Yellow "Module ImportExcel not found. Please install this module!"
    Exit
}

# Import Excel File
$x = Import-Excel -Path $Path.FullName -StartRow 3 -StartColumn 1 -EndColumn 11  -NoHeader

foreach ($entry in $x)
{
    $Filename = $entry.P1.Replace(" ","") + ".txt"
    $OutputFile = Join-Path -Path $Path.Directory -ChildPath (Join-Path -Path "Kursinfo Dateien" -ChildPath $Filename)

    if (-not (Test-Path $OutputFile -PathType Leaf))
        {
            New-Item -ItemType File -Path $OutputFile -Force -Confirm:$false -WhatIf:$false | Out-Null
        }
    
    $TNDomain = $entry.p3+$entry.p4
    $Customdomain = $TNDomain + ".myetc.at"
    $Tenantname = $entry.p6.replace(" ","") + $entry.p7
    $Tenantadmin = "admin@" + $Tenantname
    Add-Content -Value "Teilnehmer-Domain: $TNDomain" -Path $OutputFile -Encoding UTF8 -WhatIf:$false -Confirm:$false
    Add-Content -Value "Custom-Domain: $Customdomain`n" -Path $OutputFile -Encoding UTF8 -WhatIf:$false -Confirm:$false
    Add-Content -Value "Tenantname: $Tenantname" -Path $OutputFile -Encoding UTF8 -WhatIf:$false -Confirm:$false
    Add-Content -Value "Tenantadmin: $Tenantadmin`n" -Path $OutputFile -Encoding UTF8 -WhatIf:$false -Confirm:$false
    Add-Content -Value "IP Netz: 78.142.168.129" -Path $OutputFile -Encoding UTF8 -WhatIf:$false -Confirm:$false
    Add-Content -Value "Subnet Mask: 255.255.255.192" -Path $OutputFile -Encoding UTF8 -WhatIf:$false -Confirm:$false
    Add-Content -Value "Gateway: 78.142.168.129`n" -Path $OutputFile -Encoding UTF8 -WhatIf:$false -Confirm:$false
    Add-Content -Value "IP1: 78.142.168.$($entry.p8)" -Path $OutputFile -Encoding UTF8 -WhatIf:$false -Confirm:$false
    Add-Content -Value "IP2: 78.142.168.$($entry.p9)`n" -Path $OutputFile -Encoding UTF8 -WhatIf:$false -Confirm:$false
    Add-Content -Value "Azure DNS User: $($entry.p10)" -Path $OutputFile -Encoding UTF8 -WhatIf:$false -Confirm:$false
    Add-Content -Value "Azure DNS User PW: $($entry.p11)" -Path $OutputFile -Encoding UTF8 -WhatIf:$false -Confirm:$false
}