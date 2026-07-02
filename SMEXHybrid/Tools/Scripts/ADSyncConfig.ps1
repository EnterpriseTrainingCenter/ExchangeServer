Set-ADSyncBasicReadPermissions -ADConnectorAccountName svc_aadc -ADConnectorAccountDomain smart.etc -confirm:$false
Set-ADSyncPasswordHashSyncPermissions -ADConnectorAccountName svc_aadc -ADConnectorAccountDomain smart.etc -Confirm:$false
Set-ADSyncMsDsConsistencyGuidPermissions -ADConnectorAccountName svc_aadc -ADConnectorAccountDomain smart.etc -Confirm:$false
Set-ADSyncExchangeHybridPermissions -ADConnectorAccountName svc_aadc -ADConnectorAccountDomain smart.etc -Confirm:$false
Set-ADSyncExchangeMailPublicFolderPermissions -ADConnectorAccountName svc_aadc -ADConnectorAccountDomain smart.etc -Confirm:$false