
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

        #Now if we're not in a do while we end up here -> go ahead and create the status file this was not a retryable operation and is a hard failure.

        exit
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
        out-logfile -string "Please verify this script is installed and running on an Entra Connect server." -isError:$true
    }

    $functionConfigurationParamters = $functionConfigurationInformation.parameters
    $functionConfigurationVersion = $functionConfigurationParamters | where {$_.name -eq $functionStaticServerVersion}

    out-logfile -string ("Entra Connect Version Name: " + $functionConfigurationVersion.name)
    out-logfile -string ("Entra Connect Version Number: " + $functionConfigurationVersion.value)
}

#=====================================================================================
#Begin main function body.
#=====================================================================================

out-logfile -string "Begin EnableCloudAnchor"

get-ADConnect

