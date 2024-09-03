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
$x = Import-Excel -Path $Path.FullName -StartRow 3 -StartColumn 1 -EndColumn 12 -NoHeader

foreach ($entry in $x)
{
    $Filename = $entry.P1.ToString() + ".txt"
    $OutputFile = Join-Path -Path $Path.Directory -ChildPath (Join-Path -Path "Kursinfo Dateien" -ChildPath $Filename)

    if (-not (Test-Path $OutputFile -PathType Leaf))
    {
        New-Item -ItemType File -Path $OutputFile -Force -Confirm:$false -WhatIf:$false | Out-Null
    }
    
    Add-Content -Value "Teilnehmer-Domain:`t$($entry.p2)$($entry.P3)" -Path $OutputFile -Encoding UTF8 -WhatIf:$false -Confirm:$false
    Add-Content -Value "Custom-Domain:`t`t$($entry.p2)$($entry.P3)$($entry.P4)`n" -Path $OutputFile -Encoding UTF8 -WhatIf:$false -Confirm:$false
    Add-Content -Value "Tenantdomain:`t`t$($entry.p5)" -Path $OutputFile -Encoding UTF8 -WhatIf:$false -Confirm:$false
    Add-Content -Value "Tenantadmin:`t`t$($entry.p6)" -Path $OutputFile -Encoding UTF8 -WhatIf:$false -Confirm:$false
    Add-Content -Value "Tenantadmin PW:`t`t$($entry.p7)`n" -Path $OutputFile -Encoding UTF8 -WhatIf:$false -Confirm:$false
    Add-Content -Value "Azure DNS User:`t`t$($entry.p10)" -Path $OutputFile -Encoding UTF8 -WhatIf:$false -Confirm:$false
    Add-Content -Value "Azure DNS User PW:`t$($entry.p11)`n" -Path $OutputFile -Encoding UTF8 -WhatIf:$false -Confirm:$false
    Add-Content -Value "IP1:`t`t`t$($entry.p8)" -Path $OutputFile -Encoding UTF8 -WhatIf:$false -Confirm:$false
    Add-Content -Value "IP2:`t`t`t$($entry.p9)" -Path $OutputFile -Encoding UTF8 -WhatIf:$false -Confirm:$false
    Add-Content -Value "Subnet Mask:`t`t255.255.255.192" -Path $OutputFile -Encoding UTF8 -WhatIf:$false -Confirm:$false
    Add-Content -Value "Gateway:`t`t78.142.168.129" -Path $OutputFile -Encoding UTF8 -WhatIf:$false -Confirm:$false
}