$FullDomain = "@smart.etc"

# Get all mailboxes
$mailboxes = Get-Mailbox | ? {$_.EmailAddresses -like "*$FullDomain*"}

Write-host -ForegroundColor Cyan "`nRemoving Email-Addresses with Domain $FullDomain..."
 
# Loop through each mailbox
foreach ($mailbox in $mailboxes) {
    
    Write-Host -ForegroundColor Yellow "`nNow processing mailbox $($Mailbox.Displayname)"

    $emailaddresses = $mailbox.emailaddresses;
 
    #Loop through each SMTP address found on each mailbox
    for ($i=0; $i -lt $emailaddresses.count; $i++) {
        
        # Change the domain name below to what you want to remove
        if ($emailaddresses[$i].smtpaddress -like "*$Fulldomain*") {
 
            # Remove the unwanted email address

            $badaddress = $emailaddresses[$i];
            Write-Host -ForegroundColor Green "`nFound Address $badaddress. Removing...`n"

            $emailaddresses = $emailaddresses - $badaddress;
            $mailbox | set-mailbox -emailaddresses $emailaddresses;
 
        }
 
    }
 
}
 