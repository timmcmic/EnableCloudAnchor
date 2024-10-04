New-ADSyncRule  `
-Name 'Out to AD - Contact Write CloudAnchor' `
-Identifier '9d41063c-1713-425f-b097-cac31120ac0e' `
-Description '' `
-Direction 'Outbound' `
-Precedence 10 `
-PrecedenceAfter '00000000-0000-0000-0000-000000000000' `
-PrecedenceBefore '00000000-0000-0000-0000-000000000000' `
-SourceObjectType 'person' `
-TargetObjectType 'contact' `
-Connector '4f1cdd9e-00fa-4379-be83-4cf471f7c829' `
-LinkType 'Join' `
-SoftDeleteExpiryInterval 0 `
-ImmutableTag '' `
-OutVariable syncRule


Add-ADSyncAttributeFlowMapping  `
-SynchronizationRule $syncRule[0] `
-Source @('cloudAnchor') `
-Destination 'msDS-ExternalDirectoryObjectId' `
-FlowType 'Direct' `
-ValueMergeType 'Update' `
-OutVariable syncRule


Add-ADSyncRule  `
-SynchronizationRule $syncRule[0]


Get-ADSyncRule  `
-Identifier '9d41063c-1713-425f-b097-cac31120ac0e'


