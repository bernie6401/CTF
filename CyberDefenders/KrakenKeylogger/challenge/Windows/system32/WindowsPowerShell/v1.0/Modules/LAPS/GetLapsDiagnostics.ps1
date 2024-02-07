# Copyright (C) Microsoft Corporation. All rights reserved.
#
# File:   GetLapsDiagnostics.ps1
# Author: jsimmons@microsoft.com
# Date:   May 6, 2022
#
# This file implements the Get-LapsDiagnostics PowerShell cmdlet. This cmdlet
# gathers configuration state, health info, and other info useful to have
# when diagnosing issues. Trace logs are also captured, either across a
# process-policy directive (the default) or across a forced reset-password
# operation (if specified).
#

function RunProcess()
{
    Param (
        [Parameter(Mandatory=$true)]
        [string]$fileName,

        [Parameter(Mandatory=$true)]
        [string]$args
        )

    Write-Verbose "Running process: $fileName $args"

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo.Filename = $fileName
    $process.StartInfo.Arguments = $args
    $process.StartInfo.RedirectStandardError = $true
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.UseShellExecute = $false
    $process.Start() | Out-Null
    $process.WaitForExit() | Out-Null

    if ($process.ExitCode -ne 0)
    {
        Write-Error "$fileName returned an error code: $process.ExitCode"
    }
}

function StartLapsWPPTracing()
{
    Param (
        [Parameter(Mandatory=$true)]
        [string]$DataFolder
        )

    $etlFile = "$DataFolder\" + "LAPSTrace.etl"

    $logman = $Env:windir + "\system32\logman.exe"

    $logmanArgs = "start LAPSTrace"
    $logmanArgs += " -o $etlFile"
    $logmanArgs += " -p {177720b0-e8fe-47ed-bf71-d6dbc8bd2ee7} 0x7FFFFFFF 0xFF"
    $logmanArgs += " -ets"

    Write-Verbose "Starting log trace"

    RunProcess $logman $logmanArgs
}

function StopLapsWPPTracing()
{
    Param (
        [Parameter(Mandatory=$true)]
        [string]$DataFolder
        )

    $logman = $Env:windir + "\system32\logman.exe"

    $logmanArgs = "stop LAPSTrace -ets"

    Write-Verbose "Stopping log trace"

    RunProcess $logman $logmanArgs
}


function StartLdapTracing()
{
    Param (
        [Parameter(Mandatory=$true)]
        [string]$DataFolder
        )

    New-Item -Path HKLM:\SYSTEM\CurrentControlSet\Services\ldap\tracing -Name lsass.exe -Force | Out-Null
    $etlFile = "$DataFolder\" + "LdapTrace.etl"

    $logmanLdap = $Env:windir + "\system32\logman.exe"

    $logmanLdapArgs = "start LdapTrace"
    $logmanLdapArgs += " -o $etlFile"
    $logmanLdapArgs += " -p Microsoft-Windows-LDAP-Client 0x1a59afa3 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096"
    $logmanLdapArgs += " -ets"

    Write-Verbose "Starting Ldap trace"

    RunProcess $logmanLdap $logmanLdapArgs
}

function StopLdapTracing()
{
    Param (
        [Parameter(Mandatory=$true)]
        [string]$DataFolder
        )

    $logmanLdap = $Env:windir + "\system32\logman.exe"

    $logmanLdapArgs = "stop LdapTrace -ets"

    Write-Verbose "Stopping Ldap trace"

    RunProcess $logmanLdap $logmanLdapArgs

    Remove-Item -Path HKLM:\SYSTEM\CurrentControlSet\Services\ldap\tracing\lsass.exe -Force
}

function StartNetworkTrace()
{
    Param (
        [Parameter(Mandatory=$true)]
        [string]$DataFolder
        )

    $netsh = $Env:windir + "\system32\netsh.exe"

    $traceFile = "$DataFolder\" + "netsh.etl"

    $netshArgs = "trace start"
    $netshArgs += " capture=yes"
    $netshArgs += " persistent=no"
    $netshArgs += " maxSize=250"
    $netshArgs += " perfMerge=no"
    $netshArgs += " sessionname=$DataFolder"
    $netshArgs += " tracefile=$traceFile"

    Write-Verbose "Starting network trace"

    RunProcess $netsh $netshArgs
}

function StopNetworkTrace()
{
    Param (
        [Parameter(Mandatory=$true)]
        [string]$DataFolder
        )

    $netsh = $Env:windir + "\system32\netsh.exe"

    $netshArgs = "trace stop"
    $netshArgs += " sessionname=$DataFolder"

    Write-Verbose "Stopping network trace - may take a moment..."

    RunProcess $netsh $netshArgs
}

function CopyOSBinaries()
{
    Param (
        [Parameter(Mandatory=$true)]
        [string]$DataFolder
        )

    Copy-Item "$env:SystemRoot\system32\samsrv.dll" -Destination $DataFolder
    Copy-Item "$env:SystemRoot\system32\wldap32.dll" -Destination $DataFolder
    Copy-Item "$env:SystemRoot\system32\laps.dll" -Destination $DataFolder
    Copy-Item "$env:SystemRoot\system32\lapscsp.dll" -Destination $DataFolder
    Copy-Item "$env:SystemRoot\system32\windowspowershell\v1.0\modules\laps\lapspsh.dll" -Destination $DataFolder
    Copy-Item "$env:SystemRoot\system32\windowspowershell\v1.0\modules\laps\lapsutil.dll" -Destination $DataFolder
}

function ExportLAPSEventLog()
{
    Param (
        [Parameter(Mandatory=$true)]
        [string]$DataFolder
        )

    # Export individual LAPS log entries to csv file for easy viewing
    $exportedCsvLogEntries = $DataFolder + "\laps_events.csv"
    Write-Verbose "Exporting Microsoft-Windows-LAPS/Operational event log entries to $exportedCsvLogEntries"
    Get-WinEvent -LogName "Microsoft-Windows-LAPS/Operational" | Select RecordId,TimeCreated,Id,LevelDisplayName, @{n='Message';e={$_.Message -replace '\s+', " "}} ,Version,ProviderName,ProviderId,LogName,ProcessId,ThreadId,MachineName,UserId,ActivityId | Export-CSV $exportedCsvLogEntries -NoTypeInformation

    # Export the entire LAPS event log to an evtx file as well
    $exportedLog = $DataFolder + "\laps_events.evtx"
    $wevtutil = $Env:windir + "\system32\wevtutil.exe"
    $wevtutilArgs = "epl Microsoft-Windows-LAPS/Operational $exportedLog"
    Write-Verbose "Exporting Microsoft-Windows-LAPS/Operational event log to $exportedLog"
    RunProcess $wevtutil $wevtutilArgs
}

function PostProcessRegistryValue()
{
    Param (
        [Parameter(Mandatory=$true)]
        [string]$Name,

        [Parameter(Mandatory=$true)]
        [string]$Value
        )

    switch ($Name)
    {
        'BackupDirectory'
        {
            switch ($Value)
            {
                '0' { $notes = "Disabled" }
                '1' { $notes = "AAD" }
                '2' { $notes = "AD" }
                default { $notes = "<unrecognized>" }
            }
        }
        'PolicySource'
        {
            switch ($Value)
            {
                '1' { $notes = "CSP" }
                '2' { $notes = "GPO" }
                '3' { $notes = "Local" }
                '4' { $notes = "LegacyLAPS" }
                default { $notes = "<unrecognized>" }
            }
        }
        # Convert 64-bit UTC timestamp values into human-readable string
        'LastPasswordUpdateTime'
        {
            $dateTime = [DateTime]::FromFileTimeUtc($Value)
            $notes = $dateTime.ToString("O")
        }
        'AzurePasswordExpiryTime'
        {
            $dateTime = [DateTime]::FromFileTimeUtc($Value)
            $notes = $dateTime.ToString("O")
        }
        'PostAuthResetDeadline'
        {
            $dateTime = [DateTime]::FromFileTimeUtc($Value)
            $notes = $dateTime.ToString("O")
        }
        'PostAuthResetAuthenticationTime'
        {
            $dateTime = [DateTime]::FromFileTimeUtc($Value)
            $notes = $dateTime.ToString("O")
        }
        default
        {
            $notes = ""
        }
    }
    return $notes
}

function ExportRegistryKey()
{
    Param (
        [Parameter(Mandatory=$true)]
        [object]$RegistrySettingsTable,

        [Parameter(Mandatory=$true)]
        [string]$Source,

        [Parameter(Mandatory=$true)]
        [string]$RegistryKey
        )

    $keyPath = "HKLM:\$RegistryKey"
    $keyExists = Test-Path -Path $keyPath
    if ($keyExists)
    {
        $rowToAdd = $RegistrySettingsTable.NewRow()
        $rowToAdd.Source = $Source
        $rowToAdd.KeyName = $RegistryKey
        $RegistrySettingsTable.Rows.Add($rowToAdd)

        $key = Get-Item $keyPath
        $valueNames = $key | Select-Object -ExpandProperty Property
        foreach ($valueName in $valueNames)
        {
            $valueData = Get-ItemProperty -LiteralPath $keyPath -Name $valueName | Select-Object -ExpandProperty $valueName
            if ($valueName -eq "(default)")
            {
                $valueType = $key.GetValueKind("")
            }
            else
            {
                $valueType = $key.GetValueKind($valueName)
            }

            $rowToAdd = $RegistrySettingsTable.NewRow()
            $rowToAdd.Source = ""
            $rowToAdd.ValueName = $valueName
            $rowToAdd.ValueData = $valueData
            $rowToAdd.ValueType = $valueType
            $rowToAdd.Notes = PostProcessRegistryValue -Name $valueName -Value $valueData
            $rowToAdd.KeyName = $RegistryKey

            $RegistrySettingsTable.Rows.Add($rowToAdd)
        }
    }
    else
    {
         $rowToAdd = $RegistrySettingsTable.NewRow()
         $rowToAdd.Source = $Source + " - key not found"
         $rowToAdd.KeyName = $RegistryKey
         $RegistrySettingsTable.Rows.Add($rowToAdd)
    }

    $rowToAdd = $RegistrySettingsTable.NewRow()
    $rowToAdd.Source = ""
    $RegistrySettingsTable.Rows.Add($rowToAdd)
}

function ExportRegistryKeys()
{
    Param (
        [Parameter(Mandatory=$true)]
        [string]$DataFolder
        )

    Write-Verbose "Collecting registry key data of interest"

    $registrySettingsTable = New-Object System.Data.DataTable

    $registrySettingsTable.Columns.Add("Source", "string") | Out-Null
    $registrySettingsTable.Columns.Add("ValueName", "string") | Out-Null
    $registrySettingsTable.Columns.Add("ValueData", "string") | Out-Null
    $registrySettingsTable.Columns.Add("ValueType", "string") | Out-Null
    $registrySettingsTable.Columns.Add("Notes", "string") | Out-Null
    $registrySettingsTable.Columns.Add("KeyName", "string") | Out-Null

    $source = "CSP"
    $regKey = "Software\Microsoft\Policies\LAPS"
    ExportRegistryKey -RegistrySettingsTable $registrySettingsTable -Source $source -RegistryKey $regKey

    $source = "GPO"
    $regKey = "Software\Microsoft\Windows\CurrentVersion\Policies\LAPS"
    ExportRegistryKey -RegistrySettingsTable $registrySettingsTable -Source $source -RegistryKey $regKey

    $source = "LegacyLaps"
    $regKey = "Software\Policies\Microsoft Services\AdmPwd"
    ExportRegistryKey -RegistrySettingsTable $registrySettingsTable -Source $source -RegistryKey $regKey

    $source = "LocalConfig"
    $regKey = "Software\Microsoft\Windows\CurrentVersion\LAPS\Config"
    ExportRegistryKey -RegistrySettingsTable $registrySettingsTable -Source $source -RegistryKey $regKey

    $source = "LocalState"
    $regKey = "Software\Microsoft\Windows\CurrentVersion\LAPS\State"
    ExportRegistryKey -RegistrySettingsTable $registrySettingsTable -Source $source -RegistryKey $regKey

    $source = "LegacyLAPSGPExtension"
    $regKey = "Software\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}"
    ExportRegistryKey -RegistrySettingsTable $registrySettingsTable -Source $source -RegistryKey $regKey

    $exportedKeys = $DataFolder + "\laps_registry.csv"

    Write-Verbose "Exporting registry key data to $exportedKeys"

    $registrySettingsTable | Export-Csv $exportedKeys -NoTypeInformation

    Write-Verbose "Done exporting registry keys"
}

function LapsDiagnosticsPrologue()
{
    Param (
        [Parameter(Mandatory=$true)]
        [string]$DataFolder,

        [Parameter(Mandatory=$true)]
        [bool]$CollectNetworkTrace
        )

    Write-Verbose "Get-LapsDiagnostics: LapsDiagnosticsPrologue starting"

    StartLapsWPPTracing $DataFolder

    StartLdapTracing $DataFolder

    if ($CollectNetworkTrace)
    {
        StartNetworkTrace $DataFolder
    }
}

function LapsDiagnosticsEpilogue()
{
    Param (
        [Parameter(Mandatory=$true)]
        [string]$DataFolder,

        [Parameter(Mandatory=$true)]
        [bool]$CollectNetworkTrace
        )

    Write-Verbose "Get-LapsDiagnostics: LapsDiagnosticsEpilogue starting"

    if ($CollectNetworkTrace)
    {
        StopNetworkTrace $DataFolder
    }

    StopLapsWPPTracing $DataFolder

    StopLdapTracing $DataFolder

    CopyOSBinaries $DataFolder

    ExportLAPSEventLog $DataFolder

    ExportRegistryKeys $DataFolder

    Write-Verbose "Get-LapsDiagnostics: LapsDiagnosticsEpilogue ending"
}

# This function is exported from the module
function Get-LapsDiagnostics
{
    [CmdletBinding()]
    Param (
        [string]$OutputFolder,

        [Parameter()]
        [Switch]$CollectNetworkTrace,

        [Parameter()]
        [Switch]$ResetPassword
        )

    Write-Verbose "Get-LapsDiagnostics: starting OutputFolder:$OutputFolder CollectNetworkTrace:$CollectNetworkTrace ResetPassword:$ResetPassword"

    # Must run in a native bitness host to ensure proper exporting of registry keys
    if ([Environment]::Is64BitOperatingSystem -and ![Environment]::Is64BitProcess)
    {
        Write-Error "You must run this cmdlet in a 64-bit PowerShell window"
        Exit
    }

    if (!($OutputFolder))
    {
        $OutputFolder = "$env:TEMP\LapsDiagnostics"
        Write-Verbose "Get-LapsDiagnostics: OutputFolder not specified - defaulting to $OutputFolder"
    }

    # Verify or create root output folder
    $exists = Test-Path $OutputFolder
    if ($exists)
    {
        Write-Verbose "Get-LapsDiagnostics: '$OutputFolder' already exists - using it"
    }
    else
    {
        Write-Verbose "Get-LapsDiagnostics: folder '$OutputFolder' does not exist - creating it"
        New-Item $OutputFolder -Type Directory | Out-Null
        Write-Verbose "Get-LapsDiagnostics: created output folder '$OutputFolder'"
    }

    # Create a temporary destination folder
    $currentTime = Get-Date -Format yyyyMMddMM_HHmmss
    $baseName = "LapsDiagnostics_" + $env:ComputerName + "_" + $currentTime
    $dataFolder = $OutputFolder + "\" + $baseName
    New-Item $dataFolder -Type Directory | Out-Null
    Write-Verbose "Get-LapsDiagnostics: all data for this run will be collected in $dataFolder"

    # Create a zip file name
    $dataZipFile = $OutputFolder + "\" + $baseName + ".zip"
    Write-Verbose "Get-LapsDiagnostics: final data for this run will be written to $dataZipFile"

    try
    {
        LapsDiagnosticsPrologue $dataFolder $CollectNetworkTrace

        if ($ResetPassword)
        {
            Write-Verbose "Get-LapsDiagnostics: calling Reset-LapsPassword cmdlet"
            Reset-LapsPassword -ErrorAction Ignore
            if ($? -eq $true)
            {
                Write-Verbose "Get-LapsDiagnostics: Reset-LapsPassword cmdlet succeeded"
            }
            else
            {
                Write-Verbose "Get-LapsDiagnostics: Reset-LapsPassword cmdlet failed - see logs"
            }
        }
        else
        {
            Write-Verbose "Get-LapsDiagnostics: calling Invoke-LapsPolicyProcessing cmdlet"
            Invoke-LapsPolicyProcessing -ErrorAction Ignore
            if ($? -eq $true)
            {
                Write-Verbose "Get-LapsDiagnostics: Invoke-LapsPolicyProcessing succeeded"
            }
            else
            {
                Write-Verbose "Get-LapsDiagnostics: Invoke-LapsPolicyProcessing failed - - see logs"
            }
        }
    }
    catch
    {
        Write-Error "Caught exception:"
        Write-Error $($_.Exception)
    }
    finally
    {
        LapsDiagnosticsEpilogue $dataFolder $CollectNetworkTrace

        # Zip up the folder
        Compress-Archive -DestinationPath $dataZipFile -LiteralPath $dataFolder -Force

        # Delete the folder
        Remove-Item -Recurse -Force $dataFolder -ErrorAction Ignore
    }

    Write-Verbose "Get-LapsDiagnostics: finishing"

    Write-Host "Get-LapsDiagnostics: all data for this run was written to the following zip file:"
    Write-Host
    $dataZipFile
    Write-Host
}

