
<#PSScriptInfo

.VERSION 1.0.10

.GUID 122be5c6-e80f-4f9f-a871-107e2b19ddb9

.AUTHOR timmcmic@microsoft.com

.COMPANYNAME Microsoft CSS

.COPYRIGHT

.TAGS

.LICENSEURI

.PROJECTURI

.ICONURI

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES


.PRIVATEDATA

#>

<# 

.DESCRIPTION 
 Script to enable cloud anchor to increase efficiency of migrations 

#> 
Param(
    [Parameter(Mandatory = $true)]
    [string]$forestRootFQDN=$NULL,
    [Parameter(Mandatory = $false)]
    [ValidateRange(-1, 99)]
    [int]$startingPrecedence=-1,
    [Parameter(Mandatory = $false)]
    [boolean]$enableContactProcessing=$false,
    [Parameter(Mandatory = $false)]
    [boolean]$enableGroupProcessing=$false,
    [Parameter(Mandatory = $false)]
    [boolean]$enableUserProcessing=$false,
    [Parameter(Mandatory = $true)]
    [string]$logFolderPath=$NULL
)

<#

Sample RAW powershell output for creating the user writeback rule disabled.


New-ADSyncRule  `
-Name 'Out to AD - User Write CloudAnchor (Revert WriteBack)' `
-Identifier '349d87ab-8dbf-4fe3-b2fc-dc55920ae826' `
-Description 'This rule sets an authoritativeNULL removing the Cloud_ value from users.' `
-Direction 'Outbound' `
-Precedence 9 `
-PrecedenceAfter '00000000-0000-0000-0000-000000000000' `
-PrecedenceBefore '00000000-0000-0000-0000-000000000000' `
-SourceObjectType 'person' `
-TargetObjectType 'user' `
-Connector '4f1cdd9e-00fa-4379-be83-4cf471f7c829' `
-LinkType 'Join' `
-SoftDeleteExpiryInterval 0 `
-ImmutableTag '' `
-Disabled  `
-OutVariable syncRule


Add-ADSyncAttributeFlowMapping  `
-SynchronizationRule $syncRule[0] `
-Destination 'msDS-ExternalDirectoryObjectId' `
-FlowType 'Expression' `
-ValueMergeType 'Update' `
-Expression 'AuthoritativeNull' `
-OutVariable syncRule


Add-ADSyncRule  `
-SynchronizationRule $syncRule[0]


Get-ADSyncRule  `
-Identifier '349d87ab-8dbf-4fe3-b2fc-dc55920ae826'

#>

<#

Sample RAW powershell output for creating the user writeback rule.

New-ADSyncRule  `
-Name 'Out to AD - User Write CloudAnchor' `
-Identifier '38270463-2ec8-4b1c-9e5e-f483a1db7abe' `
-Description 'This rule enables writing back Cloud Anchor to User in the form of User_Anchor' `
-Direction 'Outbound' `
-Precedence 8 `
-PrecedenceAfter '00000000-0000-0000-0000-000000000000' `
-PrecedenceBefore '00000000-0000-0000-0000-000000000000' `
-SourceObjectType 'person' `
-TargetObjectType 'user' `
-Connector '4f1cdd9e-00fa-4379-be83-4cf471f7c829' `
-LinkType 'Join' `
-SoftDeleteExpiryInterval 0 `
-ImmutableTag '' `
-OutVariable syncRule


Add-ADSyncRule  `
-SynchronizationRule $syncRule[0]


Get-ADSyncRule  `
-Identifier '38270463-2ec8-4b1c-9e5e-f483a1db7abe'


#>

<#

Sample RAW powershell output for creating the contact writeback rule.

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

#>

<#

Sample RAW powershell output for running authoritative null to revert writeback for contacts.

New-ADSyncRule  `
-Name 'Out to AD - Contact Write CloudAnchor (Revert WriteBack)' `
-Identifier '31645b42-bde4-4961-980a-d6c677dda74b' `
-Description '' `
-Direction 'Outbound' `
-Precedence 11 `
-PrecedenceAfter '00000000-0000-0000-0000-000000000000' `
-PrecedenceBefore '00000000-0000-0000-0000-000000000000' `
-SourceObjectType 'person' `
-TargetObjectType 'contact' `
-Connector '4f1cdd9e-00fa-4379-be83-4cf471f7c829' `
-LinkType 'Join' `
-SoftDeleteExpiryInterval 0 `
-ImmutableTag '' `
-Disabled  `
-OutVariable syncRule


Add-ADSyncAttributeFlowMapping  `
-SynchronizationRule $syncRule[0] `
-Destination 'msDS-ExternalDirectoryObjectId' `
-FlowType 'Expression' `
-ValueMergeType 'Update' `
-Expression 'AuthoritativeNull' `
-OutVariable syncRule


Add-ADSyncRule  `
-SynchronizationRule $syncRule[0]


Get-ADSyncRule  `
-Identifier '31645b42-bde4-4961-980a-d6c677dda74b'

#>

<#

Sample RAW powershell output for running authoritative null to revert writeback for groups.

New-ADSyncRule  `
-Name 'Out to AD - Group Write CloudAnchor (Revert WriteBack)' `
-Identifier '08eddddf-5451-40bc-9d8b-86d36dfb0e79' `
-Description '' `
-Direction 'Outbound' `
-Precedence 13 `
-PrecedenceAfter '00000000-0000-0000-0000-000000000000' `
-PrecedenceBefore '00000000-0000-0000-0000-000000000000' `
-SourceObjectType 'group' `
-TargetObjectType 'group' `
-Connector '4f1cdd9e-00fa-4379-be83-4cf471f7c829' `
-LinkType 'Join' `
-SoftDeleteExpiryInterval 0 `
-ImmutableTag '' `
-Disabled  `
-OutVariable syncRule


Add-ADSyncAttributeFlowMapping  `
-SynchronizationRule $syncRule[0] `
-Destination 'mS-DS-ConsistencyGuid' `
-FlowType 'Expression' `
-ValueMergeType 'Update' `
-Expression 'AuthoritativeNull' `
-OutVariable syncRule


Add-ADSyncRule  `
-SynchronizationRule $syncRule[0]


Get-ADSyncRule  `
-Identifier '08eddddf-5451-40bc-9d8b-86d36dfb0e79'

#>

<#

Sample RAW powershell output for creating the group writeback rule.

New-ADSyncRule  `
-Name 'Out to AD - Group Write CloudAnchor' `
-Identifier 'b16ffa1a-2620-4f7a-a43a-143406456bd5' `
-Description '' `
-Direction 'Outbound' `
-Precedence 12 `
-PrecedenceAfter '00000000-0000-0000-0000-000000000000' `
-PrecedenceBefore '00000000-0000-0000-0000-000000000000' `
-SourceObjectType 'group' `
-TargetObjectType 'group' `
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
-Identifier 'b16ffa1a-2620-4f7a-a43a-143406456bd5'

#>

$ErrorActionPreference = 'Stop'

#*****************************************************

Function new-LogFile
{
    [cmdletbinding()]

    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$logFileName,
        [Parameter(Mandatory = $true)]
        [string]$logFolderPath
    )

    [string]$logFileSuffix=".log"
    [string]$fileName=$logFileName+$logFileSuffix

    # Get our log file path

    $logFolderPath = $logFolderPath+"\"+$logFileName+"\"
    
    #Since $logFile is defined in the calling function - this sets the log file name for the entire script
    
    $global:LogFile = Join-path $logFolderPath $fileName

    #Test the path to see if this exists if not create.

    [boolean]$pathExists = Test-Path -Path $logFolderPath

    if ($pathExists -eq $false)
    {
        try 
        {
            #Path did not exist - Creating

            New-Item -Path $logFolderPath -Type Directory
        }
        catch 
        {
            throw $_
        } 
    }
}

#*****************************************************
Function Out-LogFile
{
    [cmdletbinding()]

    Param
    (
        [Parameter(Mandatory = $true)]
        $String,
        [Parameter(Mandatory = $false)]
        [boolean]$isError=$FALSE
    )

    # Get the current date

    [string]$date = Get-Date -Format G

    # Build output string
    #In this case since I abuse the function to write data to screen and record it in log file
    #If the input is not a string type do not time it just throw it to the log.

    if ($string.gettype().name -eq "String")
    {
        [string]$logstring = ( "[" + $date + "] - " + $string)
    }
    else 
    {
        $logString = $String
    }

    # Write everything to our log file and the screen

    $logstring | Out-File -FilePath $global:LogFile -Append

    #Write to the screen the information passed to the log.

    if ($string.gettype().name -eq "String")
    {
        Write-Host $logString
    }
    else 
    {
        write-host $logString | select-object -expandProperty *
    }

    #If the output to the log is terminating exception - throw the same string.

    if ($isError -eq $TRUE)
    {
        #Ok - so here's the deal.
        #By default error action is continue.  IN all my function calls I use STOP for the most part.
        #In this case if we hit this error code - one of two things happen.
        #If the call is from another function that is not in a do while - the error is logged and we continue with exiting.
        #If the call is from a function in a do while - write-error rethrows the exception.  The exception is caught by the caller where a retry occurs.
        #This is how we end up logging an error then looping back around.

        write-error $logString
    }
}

#*****************************************************

function validate-RuleID
{
    Param(
        [Parameter(Mandatory = $true)]
        [string]$testRuleID=$NULL
    )

    $functionValidateReturn = 1

    out-logfile -string ("Testing to ensure that rule ID: "+$testRuleID+ " does not exist.")

    if (Get-ADSyncRule -Identifier $TestRuleID)
    {
        out-logfile -string "Rule ID exists."
        $functionValidateReturn = 0
    }
    else 
    {
        out-logfile -string "Rule ID does not exist - proceed."
    }

    out-logfile -string ("Returning validation information: "+$functionValidateReturn.tostring())

    return $functionValidateReturn
}

#*****************************************************

function get-RuleID
{
    $functionClientGuid = $NULL

    out-logfile -string "Calculating a new rule ID for the AD Connect Rule."

    do {
        try
        {   
            out-logfile -string "Obtain new rule ID."
            $functionClientGuid = new-GUID -errorAction STOP
            out-logfile -string "Client GUID obtained successfully."
        }
        catch {
            out-logfile -string $_
            out-logfile -string "Unable to obtain client GUID." -isError:$true
        }
    } until (
        (validate-RuleID -testRuleID $functionClientGuid) -eq 1
    )

    return $functionClientGuid
}

#*****************************************************

function get-ADConnect
{
    $functionStaticServerVersion = "Microsoft.Synchronize.ServerConfigurationVersion"
    $functionConfigurationInformation = $null
    $functionConfigurationParamters = $null
    $functionConfigurationVersion = $null

    try {
        Out-logfile -string "Obtaining Entra Connnect configuration informaiton."
        $functionConfigurationInformation = Get-ADSyncGlobalSettings -errorAction STOP
        out-logfile -string "Entra Connect configuration information obtained successfully"
    }
    catch {
        out-logfile -string "Unable to obtain Entra Connect information."
        out-logfile -string "Please verify this script is installed and running on an Entra Connect server." 
        out-logfile -string $_ -isError:$true
    }

    $functionConfigurationParamters = $functionConfigurationInformation.parameters
    $functionConfigurationVersion = $functionConfigurationParamters | where {$_.name -eq $functionStaticServerVersion}

    out-logfile -string ("Entra Connect Version Name: " + $functionConfigurationVersion.name)
    out-logfile -string ("Entra Connect Version Number: " + $functionConfigurationVersion.value)
}

#*****************************************************

function get-ADConnector
{
    Param(
    [Parameter(Mandatory = $true)]
    [string]$forestRootFQDN=$NULL
    )

    $functionConnectors=$null
    $functionADConnectors=$null
    $functionReturnConnector = $null
    $connectorType = "AD"
    $connectorFound = $false

    try {
        Out-logfile -string "Obtaining all sync connectors."
        $functionConnectors = Get-ADSyncConnector -errorAction STOP
        out-logfile -string "Successfully obtained sync connectors."
    }
    catch {
        out-logfile -string "Unable to obtain sync connector configuration."
        out-logfile -string $_ -isError:$true
    }

    $functionADConnectors = $functionConnectors | where {$_.type -eq $connectorType}

    foreach ($connector in $functionADConnectors)
    {
        out-logfile -string ("Evaluating connector: "+ $connector.name)

        foreach ($partition in $connector.partitions)
        {
            out-logfile -string ("Evaluating parition: "+ $partition.name)

            if ($partition.name -eq $forestRootFQDN)
            {
                out-logfile -string "Correct active directory connector was found."
                out-logfile -string ("Correct connector id: "+$connector.identifier)

                $functionReturnConnector = $connector.identifier
            }
            else 
            {
                out-logfile -string "Partition not found on connector."
            }
        }
    }

    if ($functionReturnConnector -eq $NULL)
    {
        out-logfile -string "ERROR:  No active directory connector was found with the specified forest fqdn." -isError:$true
    }
    else 
    {
        return $functionReturnConnector
    }
}

#*****************************************************

function get-freePrecedence
{
    $highestPrecedence = 99
    $lowestPrecedence = 0
    $endTest = $highestPrecedence + 1
    $precedenceArray = @($false) * 100
    [int]$precendenceTest = -1
    $syncRules = $NULL

    try {
        out-logfile -string "Obtaining all sync rules."
        $syncRules = Get-ADSyncRule -errorAction STOP
        out-logfile -string "Successfully obtained all sync rules."
    }
    catch {
        out-logfile -string "Unable to obtain sync rules."
        out-logfile -string $_ -isError:$TRUE
    }

    foreach ($rule in $syncRules)
    {
        out-logfile -string "Evaluating rule precedence."
        out-logfile -string ("Ealuating rule precedence: "+$rule.precedence)

        $precedenceTest = [int]$rule.precedence

        if ($precedenceTest -lt $highestPrecedence)
        {
            out-logfile -string "Rule is in custom range - set spot to unavailable."

            out-logfile -string $precedenceArray[$precedenceTest]
            $precedenceArray[$precedenceTest] = $true
            out-logfile -string $precedenceArray[$precedenceTest]
        }
    }

    [int]$precendenceTest = -1 #Resetting precedenceTest

    for ($i = $lowestPrecedence ; $i -lt $highestPrecedence ; $i++)
    {
        out-logfile -string ("Evaluating precedence: "+$i.tostring() + " and " + ($i+1).tostring())

        if (($precedenceArray[$i] -eq $FALSE) -and ($precedenceArray[$i+1] -eq $FALSE))
        {
            out-logfile -string "Two adjoining precedences were found as free."
            $precendenceTest = $i
            $i = $endTest #Force loop to exit
        }
        else 
        {
            out-logfile -string "Adjoining precdences were not found as free this pass."
        }
    }

    if ($precendenceTest -eq -1)
    {
        out-logfile -string "There were no adjoining precedence that were free - administrator must specify precedence." -isError:$TRUE
    }
    else 
    {
        return $precendenceTest
    }
}

#*****************************************************

function  validate-userPrecedence
{
    Param(
        [Parameter(Mandatory = $true)]
        [int]$userPrecedence=-1
    )

    $precedenceArray = @($false) * 100
    $highestPrecedence = 99
    $lowestPrecedence = 0
    [int]$precendenceTest = -1
    $syncRules = $NULL

    try {
        out-logfile -string "Obtaining all sync rules."
        $syncRules = Get-ADSyncRule -errorAction STOP
        out-logfile -string "Successfully obtained all sync rules."
    }
    catch {
        out-logfile -string "Unable to obtain sync rules."
        out-logfile -string $_ -isError:$TRUE
    }

    foreach ($rule in $syncRules)
    {
        out-logfile -string "Evaluating rule precedence."
        out-logfile -string ("Ealuating rule precedence: "+$rule.precedence)

        $precedenceTest = [int]$rule.precedence

        if ($precedenceTest -lt $highestPrecedence)
        {
            out-logfile -string "Rule is in custom range - set spot to unavailable."

            out-logfile -string $precedenceArray[$precedenceTest]
            $precedenceArray[$precedenceTest] = $true
            out-logfile -string $precedenceArray[$precedenceTest]
        }
    }

    if (($precedenceArray[$userPrecedence] -eq $FALSE) -and ($precedenceArray[$userPrecedence+1] -eq $FALSE))
    {
        out-logfile -string "The administrator supplied precedence and the next higher are free - continue."
    }
    else 
    {
        out-logfile -string "The administrator supplied precedence must have the specified value + the next value free."
        out-logfile -string "For example if 2 is specified 2 and 3 must be avilable - this is not the case."
        out-logfile -string "Specify a precedence where both the specified value and next value are free." -isError:$TRUE
    }
}

#*****************************************************

function  validate-Parameters
{
    Param(
        [Parameter(Mandatory = $true)]
        [boolean]$enableContactProcessing,
        [Parameter(Mandatory = $true)]
        [boolean]$enableGroupProcessing,
        [Parameter(Mandatory = $true)]
        [boolean]$enableUserProcessing
    )

    out-logfile -string "Checking to ensure only one type of processing is enabled."

    if (($enableContactProcessing -eq $TRUE) -and ($enableGroupProcessing -eq $TRUE) -and ($enableUserProcessing -eq $TRUE))
    {
        out-logfile -string "Only one processing option may be enabled at a time."
        out-logfile -string "ERROR - PARAMETER EXCEPTION" -isError:$true
    }
    elseif (($enableContactProcessing -eq $TRUE) -and ($enableGroupProcessing -eq $TRUE))
    {
        out-logfile -string "Either contact processing or group processing may be enabled at one time."
        out-logfile -string "ERROR - PARAMETER EXCEPTION" -isError:$true
    }
    elseif (($enableContactProcessing -eq $TRUE) -and ($enableUserProcessing -eq $TRUE))
    {
        out-logfile -string "Either contact processing or user processing may be enabled at one time."
        out-logfile -string "ERROR - PARAMETER EXCEPTION" -isError:$true
    }
    elseif (($enableGroupProcessing -eq $TRUE) -and ($enableUserProcessing -eq $TRUE))
    {
        out-logfile -string "Either group processing or user processing may be enabled at one time."
        out-logfile -string "ERROR - PARAMETER EXCEPTION" -isError:$true
    }
}

#*****************************************************

function create-SyncRule
{
    Param(
        [Parameter(Mandatory = $true)]
        [string]$RuleID,
        [Parameter(Mandatory = $true)]
        [int]$precedence,
        [Parameter(Mandatory = $true)]
        [string]$adConnectorID,
        [Parameter(Mandatory = $true)]
        [ValidateSet("User","Group","Contact")]
        [string]$operationType,
        [Parameter(Mandatory = $true)]
        [boolean]$ruleEnabled = $true
    )

    $functionUserObjectType = "User"
    $functionContactObjectType = "Contact"
    $functionGroupObjectType = "Group"

    if ($ruleEnabled -eq $TRUE)
    {
        out-logfile -string "Using enabled parameter set."

        $functionDirection = "Outbound"
        $functionPrecedenceAfter = '00000000-0000-0000-0000-000000000000'
        $functionPrecedenceBefore = '00000000-0000-0000-0000-000000000000'
        $functionLinkType = "Join"
        $functionSoftDeleteExpiraryInterval = 0
        $functionImmutableTag = ""
        $functionSource = @('cloudAnchor')
        $functionDestination = 'msDS-ExternalDirectoryObjectId'
        $functionFlowType = "Direct"
        $functionValueMergeType = "Update"
    }
    else 
    {
        out-logfile -string "Using disabled parameter set."

        $functionDirection = "Outbound"
        $functionPrecedenceAfter = '00000000-0000-0000-0000-000000000000'
        $functionPrecedenceBefore = '00000000-0000-0000-0000-000000000000'
        $functionLinkType = "Join"
        $functionSoftDeleteExpiraryInterval = 0
        $functionImmutableTag = ""
        $functionSource = @('cloudAnchor')
        $functionDestination = 'msDS-ExternalDirectoryObjectId'
        $functionFlowType = "Expression"
        $functionValueMergeType = "Update"
        $functionExpression = "AuthoritativeNull"
    }

    if (($operationType -eq $functionUserObjectType) -and ($RuleEnabled -eq $TRUE))
    {
        out-logfile -string "Entering function user object type..."

        $functionRuleName = "Out to AD - User Write CloudAnchor"
        $functionDescription = "This rule enables writing back Cloud Anchor to User in the form of User_Anchor"
        $functionSourceObjectType = "person"
        $functionTargetObjectType = "user"
    }
    elseif (($operationType -eq $functionUserObjectType) -and ($RuleEnabled -eq $false))
    {
        out-logfile -string "Entering function user object type..."

        $functionRuleName = "Out to AD - User Write CloudAnchor (Revert WriteBack)"
        $functionDescription = "This rule sets an authoritativeNULL removing the Cloud_ value from users."
        $functionSourceObjectType = "person"
        $functionTargetObjectType = "user"
    }
    elseif (($operationType -eq $functionContactObjectType) -and ($ruleEnabled -eq $true))
    {
        out-logfile -string "Entering function contact object type..."

        $functionRuleName = "Out to AD - Contact Write CloudAnchor"
        $functionDescription = "This rule enables writing back Cloud Anchor to Contacts in the form of Cloud_Anchor"
        $functionSourceObjectType = "person"
        $functionTargetObjectType = "contact"
    }
    elseif (($operationType -eq $functionContactObjectType) -and ($ruleEnabled -eq $false))
    {
        out-logfile -string "Entering function contact object type..."

        $functionRuleName = "Out to AD - Contact Write CloudAnchor (Revert WriteBack)"
        $functionDescription = "This rule sets an authoritativeNULL removing the Cloud_ value from contacts"
        $functionSourceObjectType = "person"
        $functionTargetObjectType = "contact"
    }
    elseif (($operationType -eq $functionGroupObjectType) -and ($ruleEnabled -eq $true))
    {
        out-logfile -string "Entering function group object type..."

        $functionRuleName = "Out to AD - Group Write CloudAnchor"
        $functionDescription = "This rule enables writing back Cloud Anchor to Groups in the form of Group_Anchor"
        $functionSourceObjectType = "group"
        $functionTargetObjectType = "group"
    }
    elseif (($operationType -eq $functionGroupObjectType) -and ($ruleEnabled -eq $false))
    {
        out-logfile -string "Entering function group object type..."

        $functionRuleName = "Out to AD - Group Write CloudAnchor (Revert WriteBack)"
        $functionDescription = "This rule sets an authoritativeNULL removing the Cloud_ value from groups."
        $functionSourceObjectType = "group"
        $functionTargetObjectType = "group"
    }


    try 
    {
        out-logfile -string "Create the rule template."

        if ($ruleEnabled -eq $TRUE)
        {
            out-logfile -string "Using enabled rule template."

            new-ADSyncRule -name $functionRuleName -Identifier $RuleID -Description $functionDescription -Direction $functionDirection -Precedence $precedence -PrecedenceAfter $functionPrecedenceAfter -PrecedenceBefore $functionPrecedenceBefore -SourceObjectType $functionSourceObjectType -TargetObjectType $functionTargetObjectType -Connector $adConnectorID -LinkType $functionLinkType -SoftDeleteExpiryInterval $functionSoftDeleteExpiraryInterval -ImmutableTag $functionImmutableTag -OutVariable syncRule -errorAction STOP

            out-logfile -string "Rule templated created successfully."
        }
        else
        {
            out-logfile -string "Using disabled rule template."

            new-ADSyncRule -name $functionRuleName -Identifier $RuleID -Description $functionDescription -Direction $functionDirection -Precedence $precedence -PrecedenceAfter $functionPrecedenceAfter -PrecedenceBefore $functionPrecedenceBefore -SourceObjectType $functionSourceObjectType -TargetObjectType $functionTargetObjectType -Connector $adConnectorID -LinkType $functionLinkType -SoftDeleteExpiryInterval $functionSoftDeleteExpiraryInterval -ImmutableTag $functionImmutableTag -Disabled -OutVariable syncRule -errorAction STOP

            out-logfile -string "Rule templated created successfully."
        }
    }
    catch {
        out-logfile -string "Unable to create the rule template."
        out-logfile -string $_ -isError:$true
    }

    try {
        out-logfile -string "Updating attribute flow mapping."

        Add-ADSyncAttributeFlowMapping -SynchronizationRule $syncRule[0] -Source $functionSource -Destination $functionDestination -flowType $functionFlowType -ValueMergeType $functionValueMergeType -expression $functionExpression -OutVariable syncRule -errorAction STOP

        out-logfile -string "Attribute flow mapping updated."
    }
    catch {
        out-logfile -string "Unable to update the attribute flow mapping."

        out-logfile -string $_
    }

    try {
        out-logfile -string "Adding the new rule."

        add-ADSyncRule -SynchronizationRule $syncRule[0] -errorAction STOP

        out-logfile -string "Rule added successfully."
    }
    catch {
        out-logfile -string "Unable to add the rule."
        out-logfile -string $_ -isError:$TRUE
    }
}

#=====================================================================================
#Begin main function body.
#=====================================================================================

#Declare variables

$logFileName = "EnableCloudAnchor"
$activeDirectoryConnector = $NULL
$precedence = -1
$precedencePlusOne = -1
$activeRuleID = $null
$disabledRuleID = $null
$functionUserOperationType = "User"
$functionContactOperationType = "Contact"
$functionGroupOperationType = "Group"


new-logfile -logFileName $logFileName -logFolderPath $logFolderPath

out-logfile -string "====================================================================================="
out-logfile -string "Begin EnableCloudAnchor"
out-logfile -string "====================================================================================="

validate-Parameters -enableContactProcessing $enableContactProcessing -enableGroupProcessing $enableGroupProcessing -enableUserProcessing $enableUserProcessing

get-ADConnect #Validate that we are running the commands on an ADConnect Server

$activeDirectoryConnector = get-ADConnector -forestRootFQDN $forestRootFQDN #Get the active directory connector that we will be working with.

out-logfile -string ("Correct connector id: "+$activeDirectoryConnector)

if ($startingPrecedence -eq $precedence)
{
    out-logfile -string "Administrator did not specify a starting precedence."

    $precedence =  get-freePrecedence

    out-logfile -string ("Starting precedence found: "+$precedence)
}
else
{
    out-logfile -string "Beginning precedence evaluation."

    validate-userPrecedence -userPrecedence $startingPrecedence

    $precedence = $startingPrecedence
}

$precedencePlusOne = $precedence+1

out-logfile -string ("Active Rule precedence calculated or specified: "+$precedence.tostring())
out-logfile -string ("Disabled Rule precedence calculated or specified: "+$precedencePlusOne.tostring())

$activeRuleID = get-RuleID
out-logfile -string ("Active Rule ID: "+$activeRuleID)

$disabledRuleID = get-RuleID
out-logfile -string ("Disabled Rule ID: "+$disabledRuleID)

if ($enableContactProcessing -eq $TRUE)
{
    out-logfile -string "Entering contact rule processing."

    create-SyncRule -ruleID $activeRuleID -precedence $precedence -adConnectorID $activeDirectoryConnector -operationType $functionContactOperationType -ruleEnabled $TRUE

    create-SyncRule -ruleID $disabledRuleID -precedence $precedencePlusOne -adConnectorID $activeDirectoryConnector -operationType $functionContactOperationType -ruleEnabled $FALSE
}
elseif ($enableGroupProcessing -eq $true) 
{
    out-logfile -string "Entering group rule processing."

    create-SyncRule -ruleID $activeRuleID -precedence $precedence -adConnectorID $activeDirectoryConnector -operationType $functionGroupOperationType -ruleEnabled $TRUE

    create-SyncRule -ruleID $disabledRuleID -precedence $precedencePlusOne -adConnectorID $activeDirectoryConnector -operationType $functionGroupOperationType -ruleEnabled $FALSE
}
elseif ($enableUserProcessing -eq $true) 
{
    out-logfile -string "Entering user rule processing."

    create-SyncRule -ruleID $activeRuleID -precedence $precedence -adConnectorID $activeDirectoryConnector -operationType $functionUserOperationType -ruleEnabled $TRUE

    create-SyncRule -ruleID $disabledRuleID -precedence $precedencePlusOne -adConnectorID $activeDirectoryConnector -operationType $functionUserOperationType -ruleEnabled $FALSE
}
else 
{
    out-logfile -string "Wow - that was easy - no operation type specified."
    out-logfile -string "Specify -enableContactProcessing <or> -enableGroupProcessing <or> -enableUserProcess to a value of TRUE to perform an operation."
    out-logfile -string "Note:  Only one operation may be performed at a time."
}

out-logfile -string "This concludes EnableCloudAnchor."