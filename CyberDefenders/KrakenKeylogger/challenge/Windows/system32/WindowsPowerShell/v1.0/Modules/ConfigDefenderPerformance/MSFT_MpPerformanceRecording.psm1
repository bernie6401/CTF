## Copyright (c) Microsoft Corporation. All rights reserved.

<#
.SYNOPSIS
This cmdlet collects a performance recording of Microsoft Defender Antivirus
scans.

.DESCRIPTION
This cmdlet collects a performance recording of Microsoft Defender Antivirus
scans. These performance recordings contain Microsoft-Antimalware-Engine
and NT kernel process events and can be analyzed after collection using the
Get-MpPerformanceReport cmdlet.

This cmdlet requires elevated administrator privileges.

The performance analyzer provides insight into problematic files that could
cause performance degradation of Microsoft Defender Antivirus. This tool is
provided "AS IS", and is not intended to provide suggestions on exclusions.
Exclusions can reduce the level of protection on your endpoints. Exclusions,
if any, should be defined with caution.

.EXAMPLE
New-MpPerformanceRecording -RecordTo:.\Defender-scans.etl

#>
function New-MpPerformanceRecording {
    [CmdletBinding(DefaultParameterSetName='Interactive')]
    param(

        # Specifies the location where to save the Microsoft Defender Antivirus
        # performance recording.
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$RecordTo,

        # Specifies the duration of the performance recording in seconds.
        [Parameter(Mandatory=$true, ParameterSetName='Timed')]
        [ValidateRange(0,2147483)]
        [int]$Seconds,

        # Specifies the PSSession object in which to create and save the Microsoft
        # Defender Antivirus performance recording. When you use this parameter,
        # the RecordTo parameter refers to the local path on the remote machine.
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.Runspaces.PSSession[]]$Session,

        # Optional argument to specifiy a different tool for recording traces. Default is wpr.exe
        # When $Session parameter is used this path represents a location on the remote machine.
        [Parameter(Mandatory=$false)]
        [string]$WPRPath = $null

    )

    [bool]$interactiveMode = ($PSCmdlet.ParameterSetName -eq 'Interactive')
    [bool]$timedMode = ($PSCmdlet.ParameterSetName -eq 'Timed')

    # Hosts
    [string]$powerShellHostConsole = 'ConsoleHost'
    [string]$powerShellHostISE = 'Windows PowerShell ISE Host'
    [string]$powerShellHostRemote = 'ServerRemoteHost'

    if ($interactiveMode -and ($Host.Name -notin @($powerShellHostConsole, $powerShellHostISE, $powerShellHostRemote))) {
        $ex = New-Object System.Management.Automation.ItemNotFoundException 'Cmdlet supported only on local PowerShell console, Windows PowerShell ISE and remote PowerShell console.'
        $category = [System.Management.Automation.ErrorCategory]::NotImplemented
        $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'NotImplemented',$category,$Host.Name
        $psCmdlet.WriteError($errRecord)
        return
    }

    if ($null -ne $Session) {
        [int]$RemotedSeconds = if ($timedMode) { $Seconds } else { -1 }

        Invoke-Command -Session:$session -ArgumentList:@($RecordTo, $RemotedSeconds) -ScriptBlock:{
            param(
                [Parameter(Mandatory=$true)]
                [ValidateNotNullOrEmpty()]
                [string]$RecordTo,

                [Parameter(Mandatory=$true)]
                [ValidateRange(-1,2147483)]
                [int]$RemotedSeconds
            )

            if ($RemotedSeconds -eq -1) {
                New-MpPerformanceRecording -RecordTo:$RecordTo -WPRPath:$WPRPath
            } else {
                New-MpPerformanceRecording -RecordTo:$RecordTo -Seconds:$RemotedSeconds -WPRPath:$WPRPath
            }
        }

        return
    }

    if (-not (Test-Path -LiteralPath:$RecordTo -IsValid)) {
        $ex = New-Object System.Management.Automation.ItemNotFoundException "Cannot record Microsoft Defender Antivirus performance recording to path '$RecordTo' because the location does not exist."
        $category = [System.Management.Automation.ErrorCategory]::InvalidArgument
        $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'InvalidPath',$category,$RecordTo
        $psCmdlet.WriteError($errRecord)
        return
    }

    # Resolve any relative paths
    $RecordTo = $psCmdlet.SessionState.Path.GetUnresolvedProviderPathFromPSPath($RecordTo)

    # Dependencies: WPR Profile
    [string]$wprProfile = "$PSScriptRoot\MSFT_MpPerformanceRecording.wprp"

    if (-not (Test-Path -LiteralPath:$wprProfile -PathType:Leaf)) {
        $ex = New-Object System.Management.Automation.ItemNotFoundException "Cannot find dependency file '$wprProfile' because it does not exist."
        $category = [System.Management.Automation.ErrorCategory]::ObjectNotFound
        $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'PathNotFound',$category,$wprProfile
        $psCmdlet.WriteError($errRecord)
        return
    }

    # Dependencies: WPR Version
    try 
    {
        # If user provides a valid string as $WPRPath we go with that.
        [string]$wprCommand = $WPRPath

        if (!$wprCommand) {
            $wprCommand = "wpr.exe"
            $wprs = @(Get-Command -All "wpr" 2> $null)

            if ($wprs -and ($wprs.Length -ne 0)) {
                $latestVersion = [System.Version]"0.0.0.0"

                $wprs | ForEach-Object {
                    $currentVersion = $_.Version
                    $currentFullPath = $_.Source
                    $currentVersionString = $currentVersion.ToString()
                    Write-Host "Found $currentVersionString at $currentFullPath"

                    if ($currentVersion -gt $latestVersion) {
                        $latestVersion = $currentVersion
                        $wprCommand = $currentFullPath
                    }
                }
            }
        }
    }
    catch
    {
        # Fallback to the old ways in case we encounter an error (ex: version string format change).
        [string]$wprCommand = "wpr.exe"
    }
    finally 
    {
        Write-Host "`nUsing $wprCommand version $((Get-Command $wprCommand).FileVersionInfo.FileVersion)`n"    
    }
 
    #
    # Test dependency presence
    #
    if (-not (Get-Command $wprCommand -ErrorAction:SilentlyContinue)) {
        $ex = New-Object System.Management.Automation.ItemNotFoundException "Cannot find dependency command '$wprCommand' because it does not exist."
        $category = [System.Management.Automation.ErrorCategory]::ObjectNotFound
        $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'PathNotFound',$category,$wprCommand
        $psCmdlet.WriteError($errRecord)
        return
    }

    # Exclude versions that have known bugs or are not supported any more.
    [int]$wprFileVersion = ((Get-Command $wprCommand).Version.Major) -as [int]
    if ($wprFileVersion -le 6) {
        $ex = New-Object System.Management.Automation.PSNotSupportedException "You are using an older and unsupported version of '$wprCommand'. Please download and install Windows ADK:`r`nhttps://docs.microsoft.com/en-us/windows-hardware/get-started/adk-install`r`nand try again."
        $category = [System.Management.Automation.ErrorCategory]::NotInstalled
        $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'NotSupported',$category,$wprCommand
        $psCmdlet.WriteError($errRecord)
        return
    }

    function CancelPerformanceRecording {
        Write-Host "`n`nCancelling Microsoft Defender Antivirus performance recording... " -NoNewline

        & $wprCommand -cancel -instancename MSFT_MpPerformanceRecording
        $wprCommandExitCode = $LASTEXITCODE

        switch ($wprCommandExitCode) {
            0 {}
            0xc5583000 {
                Write-Error "Cannot cancel performance recording because currently Windows Performance Recorder is not recording."
                return
            }
            default {
                Write-Error ("Cannot cancel performance recording: 0x{0:x08}." -f $wprCommandExitCode)
                return
            }
        }

        Write-Host "ok.`n`nRecording has been cancelled."
    }

    #
    # Ensure Ctrl-C doesn't abort the app without cleanup
    #

    # - local PowerShell consoles: use [Console]::TreatControlCAsInput; cleanup performed and output preserved
    # - PowerShell ISE: use try { ... } catch { throw } finally; cleanup performed and output preserved
    # - remote PowerShell: use try { ... } catch { throw } finally; cleanup performed but output truncated

    [bool]$canTreatControlCAsInput = $interactiveMode -and ($Host.Name -eq $powerShellHostConsole)
    $savedControlCAsInput = $null

    $shouldCancelRecordingOnTerminatingError = $false

    try
    {
        if ($canTreatControlCAsInput) {
            $savedControlCAsInput = [Console]::TreatControlCAsInput
            [Console]::TreatControlCAsInput = $true
        }

        #
        # Start recording
        #

        Write-Host "Starting Microsoft Defender Antivirus performance recording... " -NoNewline

        $shouldCancelRecordingOnTerminatingError = $true

        & $wprCommand -start "$wprProfile!Scans.Light" -filemode -instancename MSFT_MpPerformanceRecording
        $wprCommandExitCode = $LASTEXITCODE

        switch ($wprCommandExitCode) {
            0 {}
            0xc5583001 {
                $shouldCancelRecordingOnTerminatingError = $false
                Write-Error "Cannot start performance recording because Windows Performance Recorder is already recording."
                return
            }
            default {
                $shouldCancelRecordingOnTerminatingError = $false
                Write-Error ("Cannot start performance recording: 0x{0:x08}." -f $wprCommandExitCode)
                return
            }
        }

        Write-Host "ok.`n`nRecording has started." -NoNewline

        if ($timedMode) {
            Write-Host "`n`n   Recording for $Seconds seconds... " -NoNewline

            Start-Sleep -Seconds:$Seconds
            
            Write-Host "ok." -NoNewline
        } elseif ($interactiveMode) {
            $stopPrompt = "`n`n=> Reproduce the scenario that is impacting the performance on your device.`n`n   Press <ENTER> to stop and save recording or <Ctrl-C> to cancel recording"

            if ($canTreatControlCAsInput) {
                Write-Host "${stopPrompt}: "

                do {
                    $key = [Console]::ReadKey($true)
                    if (($key.Modifiers -eq [ConsoleModifiers]::Control) -and (($key.Key -eq [ConsoleKey]::C))) {

                        CancelPerformanceRecording

                        $shouldCancelRecordingOnTerminatingError = $false

                        #
                        # Restore Ctrl-C behavior
                        #

                        [Console]::TreatControlCAsInput = $savedControlCAsInput

                        return
                    }

                } while (($key.Modifiers -band ([ConsoleModifiers]::Alt -bor [ConsoleModifiers]::Control -bor [ConsoleModifiers]::Shift)) -or ($key.Key -ne [ConsoleKey]::Enter))

            } else {
                Read-Host -Prompt:$stopPrompt
            }
        }

        #
        # Stop recording
        #

        Write-Host "`n`nStopping Microsoft Defender Antivirus performance recording... "

        & $wprCommand -stop $RecordTo -instancename MSFT_MpPerformanceRecording
        $wprCommandExitCode = $LASTEXITCODE

        switch ($wprCommandExitCode) {
            0 {
                $shouldCancelRecordingOnTerminatingError = $false
            }
            0xc5583000 {
                $shouldCancelRecordingOnTerminatingError = $false
                Write-Error "Cannot stop performance recording because Windows Performance Recorder is not recording a trace."
                return
            }
            default {
                Write-Error ("Cannot stop performance recording: 0x{0:x08}." -f $wprCommandExitCode)
                return
            }
        }

        Write-Host "ok.`n`nRecording has been saved to '$RecordTo'."

        Write-Host `
'
The performance analyzer provides insight into problematic files that could
cause performance degradation of Microsoft Defender Antivirus. This tool is
provided "AS IS", and is not intended to provide suggestions on exclusions.
Exclusions can reduce the level of protection on your endpoints. Exclusions,
if any, should be defined with caution.
'
Write-Host `
'
The trace you have just captured may contain personally identifiable information,
including but not necessarily limited to paths to files accessed, paths to
registry accessed and process names. Exact information depends on the events that
were logged. Please be aware of this when sharing this trace with other people.
'
    } catch {
        throw
    } finally {
        if ($shouldCancelRecordingOnTerminatingError) {
            CancelPerformanceRecording
        }

        if ($null -ne $savedControlCAsInput) {
            #
            # Restore Ctrl-C behavior
            #

            [Console]::TreatControlCAsInput = $savedControlCAsInput
        }
    }
}

function PadUserDateTime
{
    [OutputType([DateTime])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [DateTime]$UserDateTime
    )

    # Padding user input to include all events up to the start of the next second.
    if (($UserDateTime.Ticks % 10000000) -eq 0)
    {
        return $UserDateTime.AddTicks(9999999)
    }
    else
    {
        return $UserDateTime
    }
}

function ValidateTimeInterval
{
    [OutputType([PSCustomObject])]
    param(
        [DateTime]$MinStartTime = [DateTime]::MinValue,
        [DateTime]$MinEndTime = [DateTime]::MinValue,
        [DateTime]$MaxStartTime = [DateTime]::MaxValue,
        [DateTime]$MaxEndTime = [DateTime]::MaxValue
    )

    $ret = [PSCustomObject]@{
        arguments = [string[]]@()
        status = $false
    }
    
    if ($MinStartTime -gt $MaxEndTime)
    {
        $ex = New-Object System.Management.Automation.ValidationMetadataException "MinStartTime '$MinStartTime' should have been lower than MaxEndTime '$MaxEndTime'"
        $category = [System.Management.Automation.ErrorCategory]::InvalidArgument
        $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'Invalid time interval',$category,"'$MinStartTime' .. '$MaxEndTime'"
        $psCmdlet.WriteError($errRecord)
        return $ret
    }

    if ($MinStartTime -gt $MaxStartTime)
    {
        $ex = New-Object System.Management.Automation.ValidationMetadataException "MinStartTime '$MinStartTime' should have been lower than MaxStartTime '$MaxStartTime'"
        $category = [System.Management.Automation.ErrorCategory]::InvalidArgument
        $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'Invalid time interval',$category,"'$MinStartTime' .. '$MaxStartTime'"
        $psCmdlet.WriteError($errRecord)
        return $ret
    }

    if ($MinEndTime -gt $MaxEndTime)
    {
        $ex = New-Object System.Management.Automation.ValidationMetadataException "MinEndTime '$MinEndTime' should have been lower than MaxEndTime '$MaxEndTime'"
        $category = [System.Management.Automation.ErrorCategory]::InvalidArgument
        $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'Invalid time interval',$category,"'$MinEndTime' .. '$MaxEndTime'"
        $psCmdlet.WriteError($errRecord)
        return $ret
    }

    if ($MinStartTime -gt [DateTime]::MinValue)
    {
        try
        {
            $MinStartFileTime = $MinStartTime.ToFileTime()
        }
        catch
        {
            $ex = New-Object System.Management.Automation.ValidationMetadataException "MinStartTime '$MinStartTime' is not a valid timestamp."
            $category = [System.Management.Automation.ErrorCategory]::InvalidArgument
            $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'Value has to be a local DateTime between "January 1, 1601 12:00:00 AM UTC" and "December 31, 9999 11:59:59 PM UTC"',$category,"'$MinStartTime'"
            $psCmdlet.WriteError($errRecord)
            return $ret
        }

        $ret.arguments += @('-MinStartTime', $MinStartFileTime)
    }

    if ($MaxEndTime -lt [DateTime]::MaxValue)
    {
        try 
        {
            $MaxEndFileTime = $MaxEndTime.ToFileTime()
        }
        catch 
        {
            $ex = New-Object System.Management.Automation.ValidationMetadataException "MaxEndTime '$MaxEndTime' is not a valid timestamp."
            $category = [System.Management.Automation.ErrorCategory]::InvalidArgument
            $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'Value has to be a local DateTime between "January 1, 1601 12:00:00 AM UTC" and "December 31, 9999 11:59:59 PM UTC"',$category,"'$MaxEndTime'"
            $psCmdlet.WriteError($errRecord)
            return $ret               
        }
    
        $ret.arguments += @('-MaxEndTime', $MaxEndFileTime)
    }

    if ($MaxStartTime -lt [DateTime]::MaxValue)
    {
        try
        {
            $MaxStartFileTime = $MaxStartTime.ToFileTime()
        }
        catch
        {
            $ex = New-Object System.Management.Automation.ValidationMetadataException "MaxStartTime '$MaxStartTime' is not a valid timestamp."
            $category = [System.Management.Automation.ErrorCategory]::InvalidArgument
            $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'Value has to be a local DateTime between "January 1, 1601 12:00:00 AM UTC" and "December 31, 9999 11:59:59 PM UTC"',$category,"'$MaxStartTime'"
            $psCmdlet.WriteError($errRecord)
            return $ret
        }

        $ret.arguments += @('-MaxStartTime', $MaxStartFileTime)
    }

    if ($MinEndTime -gt [DateTime]::MinValue)
    {
        try 
        {
            $MinEndFileTime = $MinEndTime.ToFileTime()
        }
        catch 
        {
            $ex = New-Object System.Management.Automation.ValidationMetadataException "MinEndTime '$MinEndTime' is not a valid timestamp."
            $category = [System.Management.Automation.ErrorCategory]::InvalidArgument
            $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'Value has to be a local DateTime between "January 1, 1601 12:00:00 AM UTC" and "December 31, 9999 11:59:59 PM UTC"',$category,"'$MinEndTime'"
            $psCmdlet.WriteError($errRecord)
            return $ret              
        }
        
        $ret.arguments += @('-MinEndTime', $MinEndFileTime)
    }

    $ret.status = $true
    return $ret
}

function ParseFriendlyDuration
{
    [OutputType([TimeSpan])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]
        $FriendlyDuration
    )

    if ($FriendlyDuration -match '^(\d+)(?:\.(\d+))?(sec|ms|us)$')
    {
        [string]$seconds = $Matches[1]
        [string]$decimals = $Matches[2]
        [string]$unit = $Matches[3]

        [uint32]$magnitude =
            switch ($unit)
            {
                'sec' {7}
                'ms' {4}
                'us' {1}
            }

        if ($decimals.Length -gt $magnitude)
        {
            throw [System.ArgumentException]::new("String '$FriendlyDuration' was not recognized as a valid Duration: $($decimals.Length) decimals specified for time unit '$unit'; at most $magnitude expected.")
        }

        return [timespan]::FromTicks([int64]::Parse($seconds + $decimals.PadRight($magnitude, '0')))
    }

    [timespan]$result = [timespan]::FromTicks(0)
    if ([timespan]::TryParse($FriendlyDuration, [ref]$result))
    {
        return $result
    }

    throw [System.ArgumentException]::new("String '$FriendlyDuration' was not recognized as a valid Duration; expected a value like '0.1234567sec' or '0.1234ms' or '0.1us' or a valid TimeSpan.")
}

[scriptblock]$FriendlyTimeSpanToString = { '{0:0.0000}ms' -f ($this.Ticks / 10000.0) }

function New-FriendlyTimeSpan
{
    param(
        [Parameter(Mandatory = $true)]
        [uint64]$Ticks,

        [bool]$Raw = $false
    )

    if ($Raw) {
        return $Ticks
    }

    $result = [TimeSpan]::FromTicks($Ticks)
    $result.PsTypeNames.Insert(0, 'MpPerformanceReport.TimeSpan')
    $result | Add-Member -Force -MemberType:ScriptMethod -Name:'ToString' -Value:$FriendlyTimeSpanToString
    $result
}

function New-FriendlyDateTime
{
    param(
        [Parameter(Mandatory = $true)]
        [uint64]$FileTime,

        [bool]$Raw = $false
    )

    if ($Raw) {
        return $FileTime
    }

    [DateTime]::FromFileTime($FileTime)
}

function Add-DefenderCollectionType
{
    param(
        [Parameter(Mandatory = $true)]
        [ref]$CollectionRef
    )

    if ($CollectionRef.Value.Length -and ($CollectionRef.Value | Get-Member -Name:'Processes','Files','Extensions','Scans','Folder'))
    {
        $CollectionRef.Value.PSTypeNames.Insert(0, 'MpPerformanceReport.NestedCollection')
    }
}

[scriptblock]$FriendlyScanInfoToString = { 
    [PSCustomObject]@{
        ScanType = $this.ScanType
        StartTime = $this.StartTime
        EndTime = $this.EndTime
        Duration = $this.Duration
        Reason = $this.Reason
        Path = $this.Path
        ProcessPath = $this.ProcessPath
        ProcessId = $this.ProcessId
        Image = $this.Image
    }
}

function Get-ScanComments
{
    param(
        [PSCustomObject[]]$SecondaryEvents,
        [bool]$Raw = $false
    )

    $Comments = @()

    foreach ($item in @($SecondaryEvents | Sort-Object -Property:StartTime)) {
        if (($item | Get-Member -Name:'Message' -MemberType:NoteProperty).Count -eq 1) {
            $Duration  = New-FriendlyTimeSpan -Ticks:$item.Duration -Raw:$Raw
            $StartTime = New-FriendlyDateTime -FileTime:$item.StartTime -Raw:$Raw

            $Comments += "Expensive operation `"{0}`" started at {1} lasted {2}" -f ($item.Message, $StartTime, $Duration.ToString())

            if (($item | Get-Member -Name:'Debug' -MemberType:NoteProperty).Count -eq 1) {
                $item.Debug | ForEach-Object {
                    if ($_.EndsWith("is NOT trusted") -or $_.StartsWith("Not trusted, ") -or $_.ToLower().Contains("error")) {
                        $Comments += "$_"
                    }
                }
            }
        }
        elseif (($item | Get-Member -Name:'ScanType' -MemberType:NoteProperty).Count -eq 1) {
            $Duration = New-FriendlyTimeSpan -Ticks:$item.Duration -Raw:$Raw
            $OpId = "Internal opertion"
            
            if (($item | Get-Member -Name:'Path' -MemberType:NoteProperty).Count -eq 1) {
                $OpId = $item.Path
            }
            elseif (($item | Get-Member -Name:'ProcessPath' -MemberType:NoteProperty).Count -eq 1) {
                $OpId = $item.ProcessPath
            }

            $Comments += "{0} {1} lasted {2}" -f ($item.ScanType, $OpId, $Duration.ToString())
        }
    }

    $Comments 
}

filter ConvertTo-DefenderScanInfo
{
    param(
        [bool]$Raw = $false
    )

    $result = [PSCustomObject]@{
        ScanType = [string]$_.ScanType
        StartTime = New-FriendlyDateTime -FileTime:$_.StartTime -Raw:$Raw
        EndTime = New-FriendlyDateTime -FileTime:$_.EndTime -Raw:$Raw
        Duration = New-FriendlyTimeSpan -Ticks:$_.Duration -Raw:$Raw
        Reason = [string]$_.Reason
        SkipReason = [string]$_.SkipReason
    }

    if (($_ | Get-Member -Name:'Path' -MemberType:NoteProperty).Count -eq 1) {
        $result | Add-Member -NotePropertyName:'Path' -NotePropertyValue:([string]$_.Path)
    }

    if (($_ | Get-Member -Name:'ProcessPath' -MemberType:NoteProperty).Count -eq 1) {
        $result | Add-Member -NotePropertyName:'ProcessPath' -NotePropertyValue:([string]$_.ProcessPath)
    }

    if (($_ | Get-Member -Name:'Image' -MemberType:NoteProperty).Count -eq 1) {
        $result | Add-Member -NotePropertyName:'Image' -NotePropertyValue:([string]$_.Image)
    }
    elseif ($_.ProcessPath -and (-not $_.ProcessPath.StartsWith("pid"))) {
        try {
            $result | Add-Member -NotePropertyName:'Image' -NotePropertyValue:([string]([System.IO.FileInfo]$_.ProcessPath).Name)
        } catch {
            # Silently ignore.
        }
    }

    $ProcessId = if ($_.ProcessId -gt 0) { [int]$_.ProcessId } elseif ($_.ScannedProcessId -gt 0) { [int]$_.ScannedProcessId } else { $null }
    if ($ProcessId) {
        $result | Add-Member -NotePropertyName:'ProcessId' -NotePropertyValue:([int]$ProcessId)
    }

    if ($result.Image -and $result.ProcessId) {
        $ProcessName = "{0} ({1})" -f $result.Image, $result.ProcessId
        $result | Add-Member -NotePropertyName:'ProcessName' -NotePropertyValue:([string]$ProcessName)
    }

    if ((($_ | Get-Member -Name:'Extra' -MemberType:NoteProperty).Count -eq 1) -and ($_.Extra.Count -gt 0)) {
        $Comments = @(Get-ScanComments -SecondaryEvents:$_.Extra -Raw:$Raw)
        $result | Add-Member -NotePropertyName:'Comments' -NotePropertyValue:$Comments
    }

    if (-not $Raw) {
        $result.PSTypeNames.Insert(0, 'MpPerformanceReport.ScanInfo')
    }

    $result | Add-Member -Force -MemberType:ScriptMethod -Name:'ToString' -Value:$FriendlyScanInfoToString
    $result
}

filter ConvertTo-DefenderScanStats
{
    param(
        [bool]$Raw = $false
    )

    $result = [PSCustomObject]@{
        Count = $_.Count
        TotalDuration = New-FriendlyTimeSpan -Ticks:$_.TotalDuration -Raw:$Raw
        MinDuration = New-FriendlyTimeSpan -Ticks:$_.MinDuration -Raw:$Raw
        AverageDuration = New-FriendlyTimeSpan -Ticks:$_.AverageDuration -Raw:$Raw
        MaxDuration = New-FriendlyTimeSpan -Ticks:$_.MaxDuration -Raw:$Raw
        MedianDuration = New-FriendlyTimeSpan -Ticks:$_.MedianDuration -Raw:$Raw
    }

    if (-not $Raw) {
        $result.PSTypeNames.Insert(0, 'MpPerformanceReport.ScanStats')
    }

    $result
}

[scriptblock]$FriendlyScannedFilePathStatsToString = {
    [PSCustomObject]@{
        Count = $this.Count
        TotalDuration = $this.TotalDuration
        MinDuration = $this.MinDuration
        AverageDuration = $this.AverageDuration
        MaxDuration = $this.MaxDuration
        MedianDuration = $this.MedianDuration
        Path = $this.Path
    }
}

filter ConvertTo-DefenderScannedFilePathStats
{
    param(
        [bool]$Raw = $false
    )

    $result = $_ | ConvertTo-DefenderScanStats -Raw:$Raw

    if (-not $Raw) {
        $result.PSTypeNames.Insert(0, 'MpPerformanceReport.ScannedFilePathStats')
    }
    
    $result | Add-Member -NotePropertyName:'Path' -NotePropertyValue:($_.Path)
    $result | Add-Member -Force -MemberType:ScriptMethod -Name:'ToString' -Value:$FriendlyScannedFilePathStatsToString

    if ($null -ne $_.Scans)
    {
        $result | Add-Member -NotePropertyName:'Scans' -NotePropertyValue:@(
            $_.Scans | ConvertTo-DefenderScanInfo -Raw:$Raw
        )

        if (-not $Raw) {
            Add-DefenderCollectionType -CollectionRef:([ref]$result.Scans)
        }
    }

    if ($null -ne $_.Processes)
    {
        $result | Add-Member -NotePropertyName:'Processes' -NotePropertyValue:@(
            $_.Processes | ConvertTo-DefenderScannedProcessStats -Raw:$Raw
        )

        if (-not $Raw) {
            Add-DefenderCollectionType -CollectionRef:([ref]$result.Processes)
        }
    }

    $result
}

[scriptblock]$FriendlyScannedPathsStatsToString = { 
    [PSCustomObject]@{
        Count = $this.Count
        TotalDuration = $this.TotalDuration
        MinDuration = $this.MinDuration
        AverageDuration = $this.AverageDuration
        MaxDuration = $this.MaxDuration
        MedianDuration = $this.MedianDuration
        Path = $this.Path
        Folder = $this.Folder
    }
}

filter ConvertTo-DefenderScannedPathsStats
{
    param(
        [bool]$Raw = $false
    )

    $result = $_ | ConvertTo-DefenderScanStats -Raw:$Raw

    if (-not $Raw) {
        $result.PSTypeNames.Insert(0, 'MpPerformanceReport.ScannedPathStats')
    }

    $result | Add-Member -NotePropertyName:'Path' -NotePropertyValue:($_.Path)

    if ($null -ne $_.Folder)
    {
        $result | Add-Member -NotePropertyName:'Folder' -NotePropertyValue:@(
            $_.Folder | ConvertTo-DefenderScannedPathsStats -Raw:$Raw
        )
        $result | Add-Member -Force -MemberType:ScriptMethod -Name:'ToString' -Value:$FriendlyScannedPathsStatsToString

        if (-not $Raw) {
            Add-DefenderCollectionType -CollectionRef:([ref]$result.Folder)
        }
    }

    if ($null -ne $_.Files)
    {
        $result | Add-Member -NotePropertyName:'Files' -NotePropertyValue:@(
            $_.Files | ConvertTo-DefenderScannedFilePathStats -Raw:$Raw
        )

        if (-not $Raw) {
            Add-DefenderCollectionType -CollectionRef:([ref]$result.Files)
        }
    }

    if ($null -ne $_.Scans)
    {
        $result | Add-Member -NotePropertyName:'Scans' -NotePropertyValue:@(
            $_.Scans | ConvertTo-DefenderScanInfo -Raw:$Raw
        )

        if (-not $Raw) {
            Add-DefenderCollectionType -CollectionRef:([ref]$result.Scans)
        }
    }

    if ($null -ne $_.Processes)
    {
        $result | Add-Member -NotePropertyName:'Processes' -NotePropertyValue:@(
            $_.Processes | ConvertTo-DefenderScannedProcessStats -Raw:$Raw
        )

        if (-not $Raw) {
            Add-DefenderCollectionType -CollectionRef:([ref]$result.Processes)
        }
    }

    $result
}

[scriptblock]$FriendlyScannedFileExtensionStatsToString = {
    [PSCustomObject]@{
        Count = $this.Count
        TotalDuration = $this.TotalDuration
        MinDuration = $this.MinDuration
        AverageDuration = $this.AverageDuration
        MaxDuration = $this.MaxDuration
        MedianDuration = $this.MedianDuration
        Extension = $this.Extension
    }
}

filter ConvertTo-DefenderScannedFileExtensionStats
{
    param(
        [bool]$Raw = $false
    )

    $result = $_ | ConvertTo-DefenderScanStats -Raw:$Raw

    if (-not $Raw) {
        $result.PSTypeNames.Insert(0, 'MpPerformanceReport.ScannedFileExtensionStats')
    }

    $result | Add-Member -NotePropertyName:'Extension' -NotePropertyValue:($_.Extension)
    $result | Add-Member -Force -MemberType:ScriptMethod -Name:'ToString' -Value:$FriendlyScannedFileExtensionStatsToString

    if ($null -ne $_.Scans)
    {
        $result | Add-Member -NotePropertyName:'Scans' -NotePropertyValue:@(
            $_.Scans | ConvertTo-DefenderScanInfo -Raw:$Raw
        )

        if (-not $Raw) {
            Add-DefenderCollectionType -CollectionRef:([ref]$result.Scans)
        }
    }

    if ($null -ne $_.Files)
    {
        $result | Add-Member -NotePropertyName:'Files' -NotePropertyValue:@(
            $_.Files | ConvertTo-DefenderScannedFilePathStats -Raw:$Raw
        )

        if (-not $Raw) {
            Add-DefenderCollectionType -CollectionRef:([ref]$result.Files)
        }
    }

    if ($null -ne $_.Processes)
    {
        $result | Add-Member -NotePropertyName:'Processes' -NotePropertyValue:@(
            $_.Processes | ConvertTo-DefenderScannedProcessStats -Raw:$Raw
        )

        if (-not $Raw) {
            Add-DefenderCollectionType -CollectionRef:([ref]$result.Processes)
        }
    }


    if ($null -ne $_.Folder)
    {
        $result | Add-Member -NotePropertyName:'Folder' -NotePropertyValue:@(
            $_.Folder | ConvertTo-DefenderScannedPathsStats -Raw:$Raw
        )

        if (-not $Raw) {
            Add-DefenderCollectionType -CollectionRef:([ref]$result.Folder)
        }
    }

    $result
}

[scriptblock]$FriendlyScannedProcessStatsToString = { 
    [PSCustomObject]@{
        Count = $this.Count
        TotalDuration = $this.TotalDuration
        MinDuration = $this.MinDuration
        AverageDuration = $this.AverageDuration
        MaxDuration = $this.MaxDuration
        MedianDuration = $this.MedianDuration
        ProcessPath = $this.ProcessPath
    }
}

filter ConvertTo-DefenderScannedProcessStats
{
    param(
        [bool]$Raw
    )

    $result = $_ | ConvertTo-DefenderScanStats -Raw:$Raw

    if (-not $Raw) {
        $result.PSTypeNames.Insert(0, 'MpPerformanceReport.ScannedProcessStats')
    }

    $result | Add-Member -NotePropertyName:'ProcessPath' -NotePropertyValue:($_.Process)
    $result | Add-Member -Force -MemberType:ScriptMethod -Name:'ToString' -Value:$FriendlyScannedProcessStatsToString

    if ($null -ne $_.Scans)
    {
        $result | Add-Member -NotePropertyName:'Scans' -NotePropertyValue:@(
            $_.Scans | ConvertTo-DefenderScanInfo -Raw:$Raw
        )

        if (-not $Raw) {
            Add-DefenderCollectionType -CollectionRef:([ref]$result.Scans)
        }
    }

    if ($null -ne $_.Files)
    {
        $result | Add-Member -NotePropertyName:'Files' -NotePropertyValue:@(
            $_.Files | ConvertTo-DefenderScannedFilePathStats -Raw:$Raw
        )

        if (-not $Raw) {
            Add-DefenderCollectionType -CollectionRef:([ref]$result.Files)
        }
    }

    if ($null -ne $_.Extensions)
    {
        $result | Add-Member -NotePropertyName:'Extensions' -NotePropertyValue:@(
            $_.Extensions | ConvertTo-DefenderScannedFileExtensionStats -Raw:$Raw
        )

        if (-not $Raw) {
            Add-DefenderCollectionType -CollectionRef:([ref]$result.Extensions)
        }
    }

    if ($null -ne $_.Folder)
    {
        $result | Add-Member -NotePropertyName:'Folder' -NotePropertyValue:@(
            $_.Folder | ConvertTo-DefenderScannedPathsStats -Raw:$Raw
        )

        if (-not $Raw) {
            Add-DefenderCollectionType -CollectionRef:([ref]$result.Folder)
        }
    }

    $result
}

<#
.SYNOPSIS
This cmdlet reports the file paths, file extensions, and processes that cause
the highest impact to Microsoft Defender Antivirus scans.

.DESCRIPTION
This cmdlet analyzes a previously collected Microsoft Defender Antivirus
performance recording and reports the file paths, file extensions and processes
that cause the highest impact to Microsoft Defender Antivirus scans.

The performance analyzer provides insight into problematic files that could
cause performance degradation of Microsoft Defender Antivirus. This tool is
provided "AS IS", and is not intended to provide suggestions on exclusions.
Exclusions can reduce the level of protection on your endpoints. Exclusions,
if any, should be defined with caution.

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopFiles:10 -TopExtensions:10 -TopProcesses:10 -TopScans:10

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopFiles:10 -TopExtensions:10 -TopProcesses:10 -TopScans:10 -Raw | ConvertTo-Json

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopScans:10

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopFiles:10

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopFiles:10 -TopScansPerFile:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopFiles:10 -TopProcessesPerFile:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopFiles:10 -TopProcessesPerFile:3 -TopScansPerProcessPerFile:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopPaths:10

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopPaths:10 -TopPathsDepth:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopPaths:10 -TopPathsDepth:3 -TopScansPerPath:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopPaths:10 -TopScansPerPath:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopPaths:10 -TopPathsDepth:3 -TopFilesPerPath:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopPaths:10 -TopFilesPerPath:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopPaths:10 -TopPathsDepth:3 -TopFilesPerPath:3 -TopScansPerFilePerPath:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopPaths:10 -TopFilesPerPath:3 -TopScansPerFilePerPath:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopPaths:10 -TopPathsDepth:3 -TopExtensionsPerPath:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopPaths:10 -TopExtensionsPerPath:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopPaths:10 -TopPathsDepth:3 -TopExtensionsPerPath:3 -TopScansPerExtensionPerPath:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopPaths:10 -TopExtensionsPerPath:3 -TopScansPerExtensionPerPath:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopPaths:10 -TopPathsDepth:3 -TopProcessesPerPath:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopPaths:10 -TopProcessesPerPath:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopPaths:10 -TopPathsDepth:3 -TopProcessesPerPath:3 -TopScansPerProcessPerPath:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopPaths:10 -TopProcessesPerPath:3 -TopScansPerProcessPerPath:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopExtensions:10

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopExtensions:10 -TopScansPerExtension:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopExtensions:10 -TopPathsPerExtension:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopExtensions:10 -TopPathsPerExtension:3 -TopPathsDepth:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopExtensions:10 -TopPathsPerExtension:3 -TopPathsDepth:3 -TopScansPerPathPerExtension:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopExtensions:10 -TopPathsPerExtension:3 -TopScansPerPathPerExtension:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopExtensions:10 -TopFilesPerExtension:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopExtensions:10 -TopFilesPerExtension:3 -TopScansPerFilePerExtension:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopExtensions:10 -TopProcessesPerExtension:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopExtensions:10 -TopProcessesPerExtension:3 -TopScansPerProcessPerExtension:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopProcesses:10

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopProcesses:10 -TopScansPerProcess:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopProcesses:10 -TopExtensionsPerProcess:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopProcesses:10 -TopExtensionsPerProcess:3 -TopScansPerExtensionPerProcess:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopProcesses:10 -TopFilesPerProcess:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopProcesses:10 -TopFilesPerProcess:3 -TopScansPerFilePerProcess:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopProcesses:10 -TopPathsPerProcess:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopProcesses:10 -TopPathsPerProcess:3 -TopPathsDepth:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopProcesses:10 -TopPathsPerProcess:3 -TopPathsDepth:3 -TopScansPerPathPerProcess:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopProcesses:10 -TopPathsPerProcess:3 -TopScansPerPathPerProcess:3

.EXAMPLE
# Find top 10 scans with longest durations that both start and end between MinStartTime and MaxEndTime:
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopScans:10 -MinStartTime:"5/14/2022 7:01:11 AM" -MaxEndTime:"5/14/2022 7:01:41 AM"

.EXAMPLE
# Find top 10 scans with longest durations between MinEndTime and MaxStartTime, possibly partially overlapping this period
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopScans:10 -MinEndTime:"5/14/2022 7:01:11 AM" -MaxStartTime:"5/14/2022 7:01:41 AM"

.EXAMPLE
# Find top 10 scans with longest durations between MinStartTime and MaxStartTime, possibly partially overlapping this period
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopScans:10 -MinStartTime:"5/14/2022 7:01:11 AM" -MaxStartTime:"5/14/2022 7:01:41 AM"

.EXAMPLE
# Find top 10 scans with longest durations that start at MinStartTime or later:
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopScans:10 -MinStartTime:"5/14/2022 7:01:11 AM"

.EXAMPLE
# Find top 10 scans with longest durations that start before or at MaxStartTime:
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopScans:10 -MaxStartTime:"5/14/2022 7:01:11 AM"

.EXAMPLE
# Find top 10 scans with longest durations that end at MinEndTime or later:
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopScans:10 -MinEndTime:"5/14/2022 7:01:11 AM"

.EXAMPLE
# Find top 10 scans with longest durations that end before or at MaxEndTime:
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopScans:10 -MaxEndTime:"5/14/2022 7:01:11 AM"

.EXAMPLE
# Find top 10 scans with longest durations, impacting the current interval, that did not start or end between MaxStartTime and MinEndTime.
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopScans:10 -MaxStartTime:"5/14/2022 7:01:11 AM" -MinEndTime:"5/14/2022 7:01:41 AM"

.EXAMPLE
# Find top 10 scans with longest durations, impacting the current interval, that started between MinStartTime and MaxStartTime, and ended later than MinEndTime.
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopScans:10 -MinStartTime:"5/14/2022 7:00:00 AM" -MaxStartTime:"5/14/2022 7:01:11 AM" -MinEndTime:"5/14/2022 7:01:41 AM"

.EXAMPLE
# Find top 10 scans with longest durations, impacting the current interval, that started before MaxStartTime, and ended between MinEndTime and MaxEndTime.
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopScans:10 -MaxStartTime:"5/14/2022 7:01:11 AM" -MinEndTime:"5/14/2022 7:01:41 AM" -MaxEndTime:"5/14/2022 7:02:00 AM"

.EXAMPLE
# Find top 10 scans with longest durations, impacting the current interval, that started between MinStartTime and MaxStartTime, and ended between MinEndTime and MaxEndTime.
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopScans:10 -MinStartTime:"5/14/2022 7:00:00 AM" -MaxStartTime:"5/14/2022 7:01:11 AM" -MinEndTime:"5/14/2022 7:01:41 AM" -MaxEndTime:"5/14/2022 7:02:00 AM"

.EXAMPLE
# Find top 10 scans with longest durations that both start and end between MinStartTime and MaxEndTime, using DateTime as raw numbers in FILETIME format, e.g. from -Raw report format:
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopScans:10 -MinStartTime:([DateTime]::FromFileTime(132969744714304340)) -MaxEndTime:([DateTime]::FromFileTime(132969745000971033))

.EXAMPLE
# Find top 10 scans with longest durations between MinEndTime and MaxStartTime, possibly partially overlapping this period, using DateTime as raw numbers in FILETIME format, e.g. from -Raw report format:
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopScans:10 -MinEndTime:([DateTime]::FromFileTime(132969744714304340)) -MaxStartTime:([DateTime]::FromFileTime(132969745000971033))

#>

function Get-MpPerformanceReport {
    [CmdletBinding()]
    param(
        # Specifies the location of Microsoft Defender Antivirus performance recording to analyze.
        [Parameter(Mandatory=$true,
                Position=0,
                ValueFromPipeline=$true,
                ValueFromPipelineByPropertyName=$true,
                HelpMessage="Location of Microsoft Defender Antivirus performance recording.")]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        # Requests a top files report and specifies how many top files to output, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopFiles = 0,

        # Specifies how many top scans to output for each top file, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScansPerFile = 0,

        # Specifies how many top processes to output for each top file, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopProcessesPerFile = 0,

        # Specifies how many top scans to output for each top process for each top file, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScansPerProcessPerFile = 0,

        # Requests a top paths report and specifies how many top entries to output, sorted by "Duration". This is called recursively for each directory entry. Scans are grouped hierarchically per folder and sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopPaths = 0,

        # Specifies the maxmimum depth (path-wise) that will be used to grop scans when $TopPaths is used.
        [ValidateRange(1,1024)]
        [int]$TopPathsDepth = 0,

        # Specifies how many top scans to output for each top path, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScansPerPath = 0,

        # Specifies how many top files to output for each top path, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopFilesPerPath = 0,

        # Specifies how many top scans to output for each top file for each top path, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScansPerFilePerPath = 0,

        # Specifies how many top extensions to output for each top path, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopExtensionsPerPath = 0,
    
        # Specifies how many top scans to output for each top extension for each top path, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScansPerExtensionPerPath = 0,

        # Specifies how many top processes to output for each top path, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopProcessesPerPath = 0,

        # Specifies how many top scans to output for each top process for each top path, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScansPerProcessPerPath = 0,

        # Requests a top extensions report and specifies how many top extensions to output, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopExtensions = 0,

        # Specifies how many top scans to output for each top extension, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScansPerExtension = 0,

        # Specifies how many top paths to output for each top extension, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopPathsPerExtension = 0,

        # Specifies how many top scans to output for each top path for each top extension, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScansPerPathPerExtension = 0,

        # Specifies how many top files to output for each top extension, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopFilesPerExtension = 0,

        # Specifies how many top scans to output for each top file for each top extension, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScansPerFilePerExtension = 0,

        # Specifies how many top processes to output for each top extension, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopProcessesPerExtension = 0,

        # Specifies how many top scans to output for each top process for each top extension, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScansPerProcessPerExtension = 0,

        # Requests a top processes report and specifies how many top processes to output, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopProcesses = 0,

        # Specifies how many top scans to output for each top process in the Top Processes report, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScansPerProcess = 0,

        # Specifies how many top files to output for each top process, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopFilesPerProcess = 0,

        # Specifies how many top scans to output for each top file for each top process, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScansPerFilePerProcess = 0,

        # Specifies how many top extensions to output for each top process, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopExtensionsPerProcess = 0,

        # Specifies how many top scans to output for each top extension for each top process, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScansPerExtensionPerProcess = 0,

        # Specifies how many top paths to output for each top process, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopPathsPerProcess = 0,

        # Specifies how many top scans to output for each top path for each top process, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScansPerPathPerProcess = 0,

        # Requests a top scans report and specifies how many top scans to output, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScans = 0,

        ## TimeSpan format: d | h:m | h:m:s | d.h:m | h:m:.f | h:m:s.f | d.h:m:s | d.h:m:.f | d.h:m:s.f => d | (d.)?h:m(:s(.f)?)? | ((d.)?h:m:.f)

        # Specifies the minimum duration of any scans or total scan durations of files, extensions and processes included in the report.
        # Accepts values like  '0.1234567sec' or '0.1234ms' or '0.1us' or a valid TimeSpan.
        [ValidatePattern('^(?:(?:(\d+)(?:\.(\d+))?(sec|ms|us))|(?:\d+)|(?:(\d+\.)?\d+:\d+(?::\d+(?:\.\d+)?)?)|(?:(\d+\.)?\d+:\d+:\.\d+))$')]
        [string]$MinDuration = '0us',

        # Specifies the minimum start time of scans included in the report. Accepts a valid DateTime.
        [DateTime]$MinStartTime = [DateTime]::MinValue,

        # Specifies the minimum end time of scans included in the report. Accepts a valid DateTime.
        [DateTime]$MinEndTime = [DateTime]::MinValue,

        # Specifies the maximum start time of scans included in the report. Accepts a valid DateTime.
        [DateTime]$MaxStartTime = [DateTime]::MaxValue,

        # Specifies the maximum end time of scans included in the report. Accepts a valid DateTime.
        [DateTime]$MaxEndTime = [DateTime]::MaxValue,

        # Specifies that the output should be machine readable and readily convertible to serialization formats like JSON.
        # - Collections and elements are not be formatted.
        # - TimeSpan values are represented as number of 100-nanosecond intervals.
        # - DateTime values are represented as number of 100-nanosecond intervals since January 1, 1601 (UTC).
        [switch]$Raw
    )

    #
    # Validate performance recording presence
    #

    if (-not (Test-Path -Path:$Path -PathType:Leaf)) {
        $ex = New-Object System.Management.Automation.ItemNotFoundException "Cannot find path '$Path'."
        $category = [System.Management.Automation.ErrorCategory]::ObjectNotFound
        $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'PathNotFound',$category,$Path
        $psCmdlet.WriteError($errRecord)
        return
    }

    function ParameterValidationError {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory)]
            [string]
            $ParameterName,

            [Parameter(Mandatory)]
            [string]
            $ParentParameterName
        )

        $ex = New-Object System.Management.Automation.ValidationMetadataException "Parameter '$ParameterName' requires parameter '$ParentParameterName'."
        $category = [System.Management.Automation.ErrorCategory]::MetadataError
        $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'InvalidParameter',$category,$ParameterName
        $psCmdlet.WriteError($errRecord)
    }

    #
    # Additional parameter validation
    #

    if ($TopFiles -eq 0)
    {
        if ($TopScansPerFile -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopScansPerFile' -ParentParameterName:'TopFiles'
        }

        if ($TopProcessesPerFile -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopProcessesPerFile' -ParentParameterName:'TopFiles'
        }
    }

    if ($TopProcessesPerFile -eq 0)
    {
        if ($TopScansPerProcessPerFile -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopScansPerProcessPerFile' -ParentParameterName:'TopProcessesPerFile'
        }
    }

    if ($TopPathsDepth -gt 0)
    {
        if (($TopPaths -eq 0) -and ($TopPathsPerProcess -eq 0) -and ($TopPathsPerExtension -eq 0))
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopPathsDepth' -ParentParameterName:'TopPaths or TopPathsPerProcess or TopPathsPerExtension'
        }
    }

    if ($TopPaths -eq 0) 
    {
        if ($TopScansPerPath -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopScansPerPath' -ParentParameterName:'TopPaths'
        }

        if ($TopFilesPerPath -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopFilesPerPath' -ParentParameterName:'TopPaths'
        }

        if ($TopExtensionsPerPath -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopExtensionsPerPath' -ParentParameterName:'TopPaths'
        }

        if ($TopProcessesPerPath -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopProcessesPerPath' -ParentParameterName:'TopPaths'
        }
    }

    if ($TopFilesPerPath -eq 0) 
    {
        if ($TopScansPerFilePerPath -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopScansPerFilePerPath' -ParentParameterName:'TopFilesPerPath'
        }
    }

    if ($TopExtensionsPerPath -eq 0) 
    {
        if ($TopScansPerExtensionPerPath -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopScansPerExtensionPerPath' -ParentParameterName:'TopExtensionsPerPath'
        }
    }

    if ($TopProcessesPerPath -eq 0) 
    {
        if ($TopScansPerProcessPerPath -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopScansPerProcessPerPath' -ParentParameterName:'TopProcessesPerPath'
        }
    }

    if ($TopExtensions -eq 0)
    {
        if ($TopScansPerExtension -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopScansPerExtension' -ParentParameterName:'TopExtensions'
        }

        if ($TopFilesPerExtension -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopFilesPerExtension' -ParentParameterName:'TopExtensions'
        }

        if ($TopProcessesPerExtension -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopProcessesPerExtension' -ParentParameterName:'TopExtensions'
        }

        if ($TopPathsPerExtension -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopPathsPerExtension' -ParentParameterName:'TopExtensions'
        } 
    }

    if ($TopFilesPerExtension -eq 0)
    {
        if ($TopScansPerFilePerExtension -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopScansPerFilePerExtension' -ParentParameterName:'TopFilesPerExtension'
        }
    }

    if ($TopProcessesPerExtension -eq 0)
    {
        if ($TopScansPerProcessPerExtension -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopScansPerProcessPerExtension' -ParentParameterName:'TopProcessesPerExtension'
        }
    }

    if ($TopPathsPerExtension -eq 0)
    {
        if ($TopScansPerPathPerExtension -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopScansPerPathPerExtension' -ParentParameterName:'TopPathsPerExtension'
        }
    }

    if ($TopProcesses -eq 0)
    {
        if ($TopScansPerProcess -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopScansPerProcess' -ParentParameterName:'TopProcesses'
        }

        if ($TopFilesPerProcess -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopFilesPerProcess' -ParentParameterName:'TopProcesses'
        }

        if ($TopExtensionsPerProcess -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopExtensionsPerProcess' -ParentParameterName:'TopProcesses'
        }

        if ($TopPathsPerProcess -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopPathsPerProcess' -ParentParameterName:'TopProcesses'
        }
    }

    if ($TopFilesPerProcess -eq 0)
    {
        if ($TopScansPerFilePerProcess -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopScansPerFilePerProcess' -ParentParameterName:'TopFilesPerProcess'
        }
    }

    if ($TopExtensionsPerProcess -eq 0)
    {
        if ($TopScansPerExtensionPerProcess -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopScansPerExtensionPerProcess' -ParentParameterName:'TopExtensionsPerProcess'
        }
    }

    if ($TopPathsPerProcess -eq 0)
    {
        if ($TopScansPerPathPerProcess -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopScansPerPathPerProcess' -ParentParameterName:'TopPathsPerProcess'
        }
    }

    if (($TopFiles -eq 0) -and ($TopExtensions -eq 0) -and ($TopProcesses -eq 0) -and ($TopScans -eq 0) -and ($TopPaths -eq 0)) {
        $ex = New-Object System.Management.Automation.ItemNotFoundException "At least one of the parameters 'TopFiles', 'TopPaths', 'TopExtensions', 'TopProcesses' or 'TopScans' must be present."
        $category = [System.Management.Automation.ErrorCategory]::InvalidArgument
        $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'InvalidArgument',$category,$wprProfile
        $psCmdlet.WriteError($errRecord)
        return
    }

    # Dependencies
    [string]$PlatformPath = (Get-ItemProperty -Path:'HKLM:\Software\Microsoft\Windows Defender' -Name:'InstallLocation' -ErrorAction:Stop).InstallLocation

    #
    # Test dependency presence
    #
    [string]$mpCmdRunCommand = "${PlatformPath}MpCmdRun.exe"

    if (-not (Get-Command $mpCmdRunCommand -ErrorAction:SilentlyContinue)) {
        $ex = New-Object System.Management.Automation.ItemNotFoundException "Cannot find '$mpCmdRunCommand'."
        $category = [System.Management.Automation.ErrorCategory]::ObjectNotFound
        $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'PathNotFound',$category,$mpCmdRunCommand
        $psCmdlet.WriteError($errRecord)
        return
    } 

    # assemble report arguments

    [string[]]$reportArguments = @(
        $PSBoundParameters.GetEnumerator() |
            Where-Object { $_.Key.ToString().StartsWith("Top") -and ($_.Value -gt 0) } |
            ForEach-Object { "-$($_.Key)"; "$($_.Value)"; }
        )

    [timespan]$MinDurationTimeSpan = ParseFriendlyDuration -FriendlyDuration:$MinDuration

    if ($MinDurationTimeSpan -gt [TimeSpan]::FromTicks(0))
    {
        $reportArguments += @('-MinDuration', ($MinDurationTimeSpan.Ticks))
    }

    $MaxEndTime   = PadUserDateTime -UserDateTime:$MaxEndTime
    $MaxStartTime = PadUserDateTime -UserDateTime:$MaxStartTime

    $ret = ValidateTimeInterval -MinStartTime:$MinStartTime -MaxEndTime:$MaxEndTime -MaxStartTime:$MaxStartTime -MinEndTime:$MinEndTime
    if ($false -eq $ret.status)
    {
        return
    }

    [string[]]$intervalArguments = $ret.arguments
    if (($null -ne $intervalArguments) -and ($intervalArguments.Length -gt 0))
    {
        $reportArguments += $intervalArguments
    }

    $report = (& $mpCmdRunCommand -PerformanceReport -RecordingPath $Path @reportArguments) | Where-Object { -not [string]::IsNullOrEmpty($_) } | ConvertFrom-Json

    $result = [PSCustomObject]@{}

    if (-not $Raw) {
        $result.PSTypeNames.Insert(0, 'MpPerformanceReport.Result')
    }

    if ($TopFiles -gt 0)
    {
        $reportTopFiles = @(if ($null -ne $report.TopFiles) { @($report.TopFiles | ConvertTo-DefenderScannedFilePathStats -Raw:$Raw) } else { @() })
        $result | Add-Member -NotePropertyName:'TopFiles' -NotePropertyValue:$reportTopFiles

        if (-not $Raw) {
            Add-DefenderCollectionType -CollectionRef:([ref]$result.TopFiles)
        }
    }

    if ($TopPaths -gt 0)
    {
        $reportTopPaths = @(if ($null -ne $report.TopPaths) { @($report.TopPaths | ConvertTo-DefenderScannedPathsStats -Raw:$Raw) } else { @() })
        $result | Add-Member -NotePropertyName:'TopPaths' -NotePropertyValue:$reportTopPaths
    
        if (-not $Raw) {
            Add-DefenderCollectionType -CollectionRef:([ref]$result.TopPaths)
        }
    }

    if ($TopExtensions -gt 0)
    {
        $reportTopExtensions = @(if ($null -ne $report.TopExtensions) { @($report.TopExtensions | ConvertTo-DefenderScannedFileExtensionStats -Raw:$Raw) } else { @() })
        $result | Add-Member -NotePropertyName:'TopExtensions' -NotePropertyValue:$reportTopExtensions

        if (-not $Raw) {
            Add-DefenderCollectionType -CollectionRef:([ref]$result.TopExtensions)
        }
    }

    if ($TopProcesses -gt 0)
    {
        $reportTopProcesses = @(if ($null -ne $report.TopProcesses) { @($report.TopProcesses | ConvertTo-DefenderScannedProcessStats -Raw:$Raw) } else { @() })
        $result | Add-Member -NotePropertyName:'TopProcesses' -NotePropertyValue:$reportTopProcesses

        if (-not $Raw) {
            Add-DefenderCollectionType -CollectionRef:([ref]$result.TopProcesses)
        }
    }

    if ($TopScans -gt 0)
    {
        $reportTopScans = @(if ($null -ne $report.TopScans) { @($report.TopScans | ConvertTo-DefenderScanInfo -Raw:$Raw) } else { @() })
        $result | Add-Member -NotePropertyName:'TopScans' -NotePropertyValue:$reportTopScans

        if (-not $Raw) {
            Add-DefenderCollectionType -CollectionRef:([ref]$result.TopScans)
        }
    }

    $result
}

$exportModuleMemberParam = @{
    Function = @(
        'New-MpPerformanceRecording'
        'Get-MpPerformanceReport'
        )
}

Export-ModuleMember @exportModuleMemberParam

# SIG # Begin signature block
# MIIllwYJKoZIhvcNAQcCoIIliDCCJYQCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBsICE0l2sYKs8a
# 2U0rCohI05sOtAwGt6ygrH3jTQGURqCCC1MwggTgMIIDyKADAgECAhMzAAAKdX3r
# GbkiXfErAAAAAAp1MA0GCSqGSIb3DQEBCwUAMHkxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xIzAhBgNVBAMTGk1pY3Jvc29mdCBXaW5kb3dzIFBD
# QSAyMDEwMB4XDTIzMDIxNjE5MDA0NloXDTI0MDEzMTE5MDA0NlowcDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEaMBgGA1UEAxMRTWljcm9zb2Z0
# IFdpbmRvd3MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCm8WsyPSBF
# EhzxVlIBXzf7oJ80Ie8UY2fgPE40Efe97fn7mMo3Pyr4zWv4B3mG5tfMta6fULwC
# 4FuNpgEHBntPXOpyCHpJXYIggff2YOllKtdP4jPi0kueDvim/+uhBVHVvQTJfuG1
# HhG6tAQ9Ts2+QtrMMUyvLuRT1Mt6dANp9XJ2dlshPAR0IMyvVr/B5UxrvsBBjGd9
# nwVJdGaMOEcX4GY1JS0WV+md+vKTeZBh+kAl8Vc21p2FkTqmgqlBSALAhZvWgisa
# RSRIQc330EKeTuqM8Isrpn+5sQ8khBzAaimOFtYu1DvnY0q2ZvCCcIcr3T39uyq1
# 4N88zal30wCtAgMBAAGjggFoMIIBZDAfBgNVHSUEGDAWBgorBgEEAYI3CgMGBggr
# BgEFBQcDAzAdBgNVHQ4EFgQUviUXPislHupG6qw+6BLkdAIZjgowRQYDVR0RBD4w
# PKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEWMBQGA1UEBRMN
# MjMwMDI4KzUwMDE4OTAfBgNVHSMEGDAWgBTRT6mKBwjO9CQYmOUA//PWeR03vDBT
# BgNVHR8ETDBKMEigRqBEhkJodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNXaW5QQ0FfMjAxMC0wNy0wNi5jcmwwVwYIKwYBBQUHAQEE
# SzBJMEcGCCsGAQUFBzAChjtodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2Nl
# cnRzL01pY1dpblBDQV8yMDEwLTA3LTA2LmNydDAMBgNVHRMBAf8EAjAAMA0GCSqG
# SIb3DQEBCwUAA4IBAQBX8cmfh/BkgIZ0YrvNBGc0eniJX+zamIxh08ELJtiKcmhA
# jiBOq6AU7PAT9bZq+zYSoyIkSV4K3YpYy6T4qZ755rbjPuh87Yjb/boFg5BL3SDH
# 0KQ/6Su2khM2T+HicYWro0JsiPGwPv/GFOMRGvQN0tf2IiYV+BedAM2TmNF2f6LS
# jX24PO6O81VcqJD13Qj0UlGG6OezTI/P9lxupc2MVxTullLlGXwjN2cP2rgGKZiE
# qQrCiO6/Y7hqEdNvhKrs9NnDo9PGbDWUMN4DwKGwJZFRySG+KogcZkk7ozOvM6p9
# +TLQS+3TmlFJlmRHtf7Fjma2sWc3mhyz17drnj05MIIGazCCBFOgAwIBAgIKYQxq
# GQAAAAAABDANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNh
# dGUgQXV0aG9yaXR5IDIwMTAwHhcNMTAwNzA2MjA0MDIzWhcNMjUwNzA2MjA1MDIz
# WjB5MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSMwIQYDVQQD
# ExpNaWNyb3NvZnQgV2luZG93cyBQQ0EgMjAxMDCCASIwDQYJKoZIhvcNAQEBBQAD
# ggEPADCCAQoCggEBAMB5uzqx8A+EuK1kKnUWc9C7B/Y+DZ0U5LGfwciUsDh8H9Az
# VfW6I2b1LihIU8cWg7r1Uax+rOAmfw90/FmV3MnGovdScFosHZSrGb+vlX2vZqFv
# m2JubUu8LzVs3qRqY1pf+/MNTWHMCn4x62wK0E2XD/1/OEbmisdzaXZVaZZM5Njw
# NOu6sR/OKX7ET50TFasTG3JYYlZsioGjZHeYRmUpnYMUpUwIoIPXIx/zX99vLM/a
# FtgOcgQo2Gs++BOxfKIXeU9+3DrknXAna7/b/B7HB9jAvguTHijgc23SVOkoTL9r
# XZ//XTMSN5UlYTRqQst8nTq7iFnho0JtOlBbSNECAwEAAaOCAeMwggHfMBAGCSsG
# AQQBgjcVAQQDAgEAMB0GA1UdDgQWBBTRT6mKBwjO9CQYmOUA//PWeR03vDAZBgkr
# BgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUw
# AwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBN
# MEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0
# cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoG
# CCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01p
# Y1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDCBnQYDVR0gBIGVMIGSMIGPBgkrBgEE
# AYI3LgMwgYEwPQYIKwYBBQUHAgEWMWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9Q
# S0kvZG9jcy9DUFMvZGVmYXVsdC5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcA
# YQBsAF8AUABvAGwAaQBjAHkAXwBTAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZI
# hvcNAQELBQADggIBAC5Bpoa1Bm/wgIX6O8oX6cn65DnClHDDZJTD2FamkI7+5Jr0
# bfVvjlONWqjzrttGbL5/HVRWGzwdccRRFVR+v+6llUIz/Q2QJCTj+dyWyvy4rL/0
# wjlWuLvtc7MX3X6GUCOLViTKu6YdmocvJ4XnobYKnA0bjPMAYkG6SHSHgv1QyfSH
# KcMDqivfGil56BIkmobt0C7TQIH1B18zBlRdQLX3sWL9TUj3bkFHUhy7G8JXOqiZ
# VpPUxt4mqGB1hrvsYqbwHQRF3z6nhNFbRCNjJTZ3b65b3CLVFCNqQX/QQqbb7yV7
# BOPSljdiBq/4Gw+Oszmau4n1NQblpFvDjJ43X1PRozf9pE/oGw5rduS4j7DC6v11
# 9yxBt5yj4R4F/peSy39ZA22oTo1OgBfU1XL2VuRIn6MjugagwI7RiE+TIPJwX9hr
# cqMgSfx3DF3Fx+ECDzhCEA7bAq6aNx1QgCkepKfZxpolVf1Ayq1kEOgx+RJUeRry
# DtjWqx4z/gLnJm1hSY/xJcKLdJnf+ZMakBzu3ZQzDkJQ239Q+J9iguymghZ8Zrzs
# mbDBWF2osJphFJHRmS9J5D6Bmdbm78rj/T7u7AmGAwcNGw186/RayZXPhxIKXezF
# ApLNBZlyyn3xKhAYOOQxoyi05kzFUqOcasd9wHEJBA1w3gI/h+5WoezrtUyFMYIZ
# mjCCGZYCAQEwgZAweTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEjMCEGA1UEAxMaTWljcm9zb2Z0IFdpbmRvd3MgUENBIDIwMTACEzMAAAp1fesZ
# uSJd8SsAAAAACnUwDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisG
# AQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcN
# AQkEMSIEIAcA8vRSRt2001GCjbhZulAiZ6IjSUyJ74Q3G0CP/VfOMEIGCisGAQQB
# gjcCAQwxNDAyoBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEAPQzdoMkE7Qnqg7taWLphzD/Z
# ikWumIsylJQNjTNB3cWwkmsboAG3f8N5F2vsJYTQA2pdNaHuOCOUrQYaGukeROpR
# +aSXXVy3aETL7ObZmFWAkGMvYDdRPnCMlY8gnn5PCb3xPiWRIRTH7g/ItEWJhEml
# QrhAV48oBancHQr9jCDO/PxV9xXwv4sU20GSZU9lWjHs6TKdODMiXuS7ZiK/hT42
# jsYPCzeVHoxntrooFMNvUMCwBycbiNuI2+2Al+Ob+c25SvCvIgu05XLPRvgAo4v/
# wctFCDfyCpHaP5wYgvymHQsiGFrpbL4S0EcXzMJoZPwGYftwHLzM4zJaxGPRmqGC
# FykwghclBgorBgEEAYI3AwMBMYIXFTCCFxEGCSqGSIb3DQEHAqCCFwIwghb+AgED
# MQ8wDQYJYIZIAWUDBAIBBQAwggFZBgsqhkiG9w0BCRABBKCCAUgEggFEMIIBQAIB
# AQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCBAJz/aRJn1l0IPajugPBej
# bCfnEhG3DBXDbLgzKPjAsQIGZGzy5Y5ZGBMyMDIzMDYwODA1MjEyMC45NzZaMASA
# AgH0oIHYpIHVMIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQx
# JjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkZDNDEtNEJENC1EMjIwMSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIReDCCBycwggUPoAMCAQIC
# EzMAAAG59gANZVRPvAMAAQAAAbkwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgUENBIDIwMTAwHhcNMjIwOTIwMjAyMjE3WhcNMjMxMjE0MjAyMjE3
# WjCB0jELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UE
# CxMkTWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQL
# Ex1UaGFsZXMgVFNTIEVTTjpGQzQxLTRCRDQtRDIyMDElMCMGA1UEAxMcTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
# AgoCggIBAONJPslh9RbHyQECbUIINxMF5uQkyN07VIShITXubLpWnANgBCLvCcJl
# 7o/2HHORnsRcmSINJ/qclAmLIrOjnYnrbocAnixiMEXC+a1sZ84qxYWtEVY7VYw0
# LCczY+86U/8shgxqsaezKpWriPOcpV1Sh8SsOxf30yO7jvld/IBA3T6lHM2pT/HR
# jWk/r9uyx0Q4atx0mkLVYS9y55/oTlKLE00h792S+maadAdy3VgTweiwoEOXD785
# wv3h+fwH/wTQtC9lhAxhMO4p+OP9888Wxkbl6BqRWXud54RTzqp2Vr+yen1Q1A6u
# myMB7Xq0snIYG5B1Acc4UgJlPQ/ZiMkqgxQNFCWQvz0G9oLgSPD8Ky0AkX22PcDO
# boPuNT4RceWPX0UVZUsX9IUgs7QF41HiQSwEeOOHGyrfQdmSslATrbmH/18M5Qrs
# TM5JINjct9G42xqN8VF9Z8WOiGMjNbvlpcEmmysYl5QyhrEDoFnQTU7bFrD3JX0f
# Ifu1sbLWeBqXwbp4Z8yACTtphK2VbzOvi4vc0RCmRNzvYQQ2PjZ7NaTXE4Gu3vgg
# AJ+rtzUTAfJotvOSqcMgNwLZa1Y+ET/lb0VyjrYwFuHtg0QWyQjP5350LTpv086p
# yVUh4A3w/Os5hTGFZgFe5bCyMnpY09M0yPdHaQ/56oYUsSIcyKyVAgMBAAGjggFJ
# MIIBRTAdBgNVHQ4EFgQUt7A4cdtYQ5oJjE1ZqrSonp41RFIwHwYDVR0jBBgwFoAU
# n6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFt
# cCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcw
# AoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3Nv
# ZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIw
# ADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZI
# hvcNAQELBQADggIBAM3cZ7NFUHRMsLKzjl7rJPIkv7oJ+s9kkut0hZif9WSt60Sz
# YGULp1zmdPqc+w8eHTkhqX0GKCp2TTqSzBXBhwHOm8+p6hUxNlDewGMZUos952aT
# XblAT3OKBnfVBLQyUavrSjuJGZAW30cNY3rjVDUlGD+VygQHySaDaviJQbK6/6fQ
# vUUFoqIk3ldGfjnAtnebsVlqh6WWamVc5AZdpWR1jSzN/oxKYqc1BG4SxxlPtcfr
# AdBz/cU4bxVXqAAf02NZscvJNpRnOALf5kVo2HupJXCsk9TzP5PNW2sTS3TmwhIQ
# mPxr0E0UqOojUrBJUOhbITAxcnSa/IMluL1HXRtLQZI+xs2eRtuPOUsKUW71/1Ye
# qsYCLHLvu82ceDVQQvP7GHEEkp2kEjiofbjYErBo2iCEaxxeX4Z9HvAgA4MsQkbn
# 6e4EFQf13sP+Kn3XgMIvJbqLJeFcQja+SUeOXu5cfkxe0GzTNojdyIwzaHlhOflV
# RZNrxee3B+yZwd3JHDIvv71uSI/SIzzt9cU2GyHQVqxBSrRtKW6W8Vw7zpVvoVsI
# v3ljxg+7NiGSlXX1s7zbBNDMUj9OnzOlHK/3mrOU8YEuRf6RwakW5UCeGamy5MiK
# u2YuyKiGBCv4OGhPstNe7ALkEOh8BX12t4ntuYu+gw9L6yCPY0jWYaQtzAP9MIIH
# cTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCB
# iDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMp
# TWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEw
# OTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzntHIh
# C3miy9ckeb0O1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xPx2b3lVNx
# WuJ+Slr+uDZnhUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFc
# UTE3oAo4bo3t1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAc
# nVL+tuhiJdxqD89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUo
# veO0hyTD4MmPfrVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXAhjBcTyzi
# YrLNueKNiOSWrAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9
# fvzZnkXftnIv231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdH
# GO2n6Jl8P0zbr17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7X
# KHYC4jMYctenIPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiE
# R9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/
# eKtFtvUeh17aj54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3
# FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAd
# BgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEE
# AYI3TIN9AQEwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMB
# Af8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1Ud
# HwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3By
# b2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQRO
# MEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2Vy
# dHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEBCwUAA4IC
# AQCdVX38Kq3hLB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pk
# bHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gng
# ugnue99qb74py27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3
# lbYoVSfQJL1AoL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHC
# gRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6
# MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEU
# BHG/ZPkkvnNtyo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvsh
# VGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+
# fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrp
# NPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784cETRkPHI
# qzqKOghif9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAtQwggI9AgEBMIIB
# AKGB2KSB1TCB0jELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEt
# MCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYw
# JAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpGQzQxLTRCRDQtRDIyMDElMCMGA1UEAxMc
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAx2Ie
# GHhk58MQkzzSWknGcLjfgTqggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOgr32IwIhgPMjAyMzA2MDgxMzAyMjZa
# GA8yMDIzMDYwOTEzMDIyNlowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA6CvfYgIB
# ADAHAgEAAgIBhjAHAgEAAgISyTAKAgUA6C0w4gIBADA2BgorBgEEAYRZCgQCMSgw
# JjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3
# DQEBBQUAA4GBAKbDQAm6ULeVrOwIACedPCWyPsS3JS3Ju4bNymL/sDGUU9fkhmsK
# mnBbAlmCH9IicCTban4Nq/Twt8FPsARXRebqqvgGh3x0wCC42gWqJRNeH3DOUIDb
# CYoqDCe9dgDPRLAWF9z+0080oP52I1J7rBnNqaik0pQPdtst1237YxHmMYIEDTCC
# BAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEm
# MCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAG59gAN
# ZVRPvAMAAQAAAbkwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsq
# hkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgHnQh5Z8pTqAt7zMcd5NOyaDu/qiu
# jjdoruvfy3vTBzIwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCBk60bO8W85
# uTAfJVEO3vX2aLaQFcgcGpdwsOoi+foP9DCBmDCBgKR+MHwxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1l
# LVN0YW1wIFBDQSAyMDEwAhMzAAABufYADWVUT7wDAAEAAAG5MCIEIOY7LlXCMLOI
# 0QK/gHOjDuSkf6NTnIv6KfazuDlhEuX1MA0GCSqGSIb3DQEBCwUABIICAHMggeuD
# YdaDHKAFIqE/FD/Vg+gwJlHjtb+z9K9wpu0yocCi8PTQcjvPs8XpIiW8xNLb5oYj
# ctFRkZiUxAoZsuRHsNry7Fz73oDLzfiYK/4FOgJJuyfsN8KiWh29dokWieQEQx60
# bjZGtGdIm9le7fY9HFUu3xwLrH5tYXekNEs6AlyAoNU0h84cEeUuVunUEdXjOK62
# OG0E3DsiHcYVHk0gBYZIWcpe4OL4UDIx7khdHdZ2Zphk0pjVKHf+7761Hr8AHh97
# uWX4sWaVY4UyJzhNYqVv0zFpx5Ex9IphUOR2qgCp5SyN6RjEpPMCvTZW6WNuhoEx
# 07t1yzbSEo9Rjfc23AKpLfd8TdLHA/2T5KsbNRFpwRx1goiIEUxuz6ZwDDQAY5d1
# cGDWiQjADB+j7UEZudjP4rnENSFwpgiRGb6NsaQPIlFSVph4Lg60GpoA7pm6GnwY
# yLez1XcVAa/NNho2sYoXQ86+OPftmVCIxGeBPI28x0jGiUTDF8EuECkwNCT0Ms47
# AXlljrdzYryc8JKFtlhx4yA0ZWVwD0AYu6PsN96rFu6BcGXMGArX4pB4gUTNL4DF
# C6ehLNPBs3F24noU5aURg12pYIB19a7wLtMVj/bK+tSbK9Kny2I76GUSL8b80VLl
# V5LB3y7XeKaCgbOYXAC8E3BFig6t37+K31tM
# SIG # End signature block