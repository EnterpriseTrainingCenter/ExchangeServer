# Check-UnresolvedSIDs.ps1 
# 
# This script will remove all unresolved SIDs from public folder permissions. 
# This will take quite some time to run against a large hierarchy.
 
param([string]$Server, [bool]$Remove)
 
if ([System.String]::IsNullOrEmpty($Server)) 
{ 
    "You must specify a server." 
    return 
}
 
function CheckUnresolvedForFolder($folder) 
{ 
    ($folder.Identity.ToString() + ": Checking folder") 
    $unresolved = Get-PublicFolderClientPermission -Identity $folder -Server $Server| WHERE { $_.User -like "NT User:*" } 
    if ($unresolved -ne $null) 
    { 
        ($folder.Identity.ToString() + " has unresolved SIDs:") 
        foreach ($item in $unresolved) 
        { 
            ("     " + $item.User.ToString()) 
        }
 
        if ($Remove) 
        { 
            ("     Removing the unresolved SIDs...") 
            foreach ($item in $unresolved) 
            { 
                $item | Remove-PublicFolderClientPermission -Identity $folder -Server $Server -Confirm:$false 
            } 
            ("     Unresolved SIDs were removed.") 
        } 
    } 
}
 
function DoFolderRecursive($folder) 
{ 
    CheckUnresolvedForFolder($folder) 
    $subfolders = Get-PublicFolder -Identity $folder -GetChildren 
    if ($subfolders -ne $null) 
    { 
        foreach ($subfolder in $subfolders) 
        { 
            DoFolderRecursive($subfolder) 
        } 
    } 
}
 
$ipmSubtree = Get-PublicFolder "\" -Server $Server 
DoFolderRecursive($ipmSubtree) 
$nonIpmSubtree = Get-PublicFolder "\NON_IPM_SUBTREE" -Server $Server 
DoFolderRecursive($nonIpmSubtree)
