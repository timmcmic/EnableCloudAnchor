
<#PSScriptInfo

.VERSION 1.0

.GUID 122be5c6-e80f-4f9f-a871-107e2b19ddb9

.AUTHOR timmcmic

.COMPANYNAME

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
    [Parameter(Mandatory = $true)]
    [string]$logFolderPath=$NULL
)

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

function get-RuleID
{
    $functionClientGuid = $NULL

    out-logfile -string "Entering new-ClientGuid"

    try
    {   
        out-logfile -string "Obtain client GUID."
        $functionClientGuid = new-GUID -errorAction STOP
        out-logfile -string "Client GUID obtained successfully."
    }
    catch {
        out-logfile -string $_
        out-logfile -string "Unable to obtain client GUID." -isError:$true
    }

    out-logfile -string "Exiting new-ClientGuid"

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

#=====================================================================================
#Begin main function body.
#=====================================================================================

#Declare variables

$logFileName = "EnableCloudAnchor"
$activeDirectoryConnector = $NULL
$precedence = -1
$activeRuleID = $null
$disabledRuleID = $null


new-logfile -logFileName $logFileName -logFolderPath $logFolderPath

out-logfile -string "====================================================================================="
out-logfile -string "Begin EnableCloudAnchor"
out-logfile -string "====================================================================================="

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

out-logfile -string ("Staring precedence specified or calculated: "+$precedence.tostring())

