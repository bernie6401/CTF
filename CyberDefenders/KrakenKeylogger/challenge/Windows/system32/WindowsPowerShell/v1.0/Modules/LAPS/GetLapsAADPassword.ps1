# Copyright (C) Microsoft Corporation. All rights reserved.
#
# File:   GetLapsAADPassword.ps1
# Author: jsimmons@microsoft.com
# Date:   April 25, 2022
#
# This file implements the Get-LapsAADPassword PowerShell cmdlet. At its core,
# this cmdlet just submits MS graph queries and morphs the returned results
# into PowerShell objects.
#
# This cmdlet has a dependency on the MSGraph PowerShell library which may be
# installed like so:
#
#    Set-PSRepository PSGallery -InstallationPolicy Trusted
#    Install-Module Microsoft.Graph -Scope AllUsers
#
# Functional prerequisites:
#
#   You must be logged into into MSGraph before running this cmdlet - see the docs
#     on the Connect-MgGraph cmdlet.
#
#  An app needs to be created in your tenant that that configures the appropriate
#    scopes for querying DeviceLocalCredentials.
#

# ConvertBase64ToSecureString (internal helper function - not exported)
function ConvertBase64ToSecureString()
{
    Param (
        [string]$Base64
    )

    if ([string]::IsNullOrEmpty($Base64))
    {
        throw
    }

    $bytes = [System.Convert]::FromBase64String($Base64)

    $plainText = [System.Text.Encoding]::UTF8.GetString($bytes)

    $secureString = ConvertTo-SecureString $plainText -AsPlainText -Force

    $secureString
}

# ConvertBase64ToPlainText (internal helper function - not exported)
function ConvertBase64ToPlainText()
{
    Param (
        [string]$Base64
    )

    if ([string]::IsNullOrEmpty($Base64))
    {
        throw
    }

    $bytes = [System.Convert]::FromBase64String($Base64)

    $plainText = [System.Text.Encoding]::UTF8.GetString($bytes)

    $plainText
}

# ProcessOneDevice (internal helper function - not exported)
function ProcessOneDevice()
{
    Param (
        [string]$DeviceId,
        [boolean]$IncludePasswords,
        [boolean]$IncludeHistory,
        [boolean]$AsPlainText
    )

    Write-Verbose "ProcessOneDevice starting for DeviceId:'$DeviceId' IncludePasswords:$IncludePasswords IncludeHistory:$IncludeHistory AsPlainText:$AsPlainText"

    # Check if a guid was passed in. If it looks like a guid we assume it's the device id.
    $guid = New-Object([System.Guid])
    $isGuid = [System.Guid]::TryParse($DeviceId, [ref]$guid)
    if (!$isGuid)
    {
        # $DeviceId is not a guid. Assume it's a DisplayName and look it up:
        Write-Verbose "Querying device '$DeviceId' to get its device id"
        $filter = "DisplayName eq '$DeviceId'"
        try
        {
            $mgDevice = Get-MgDevice -Filter $filter
        }
        catch
        {
            $mgDevice = $null
        }
        if ($mgDevice -eq $null)
        {
            Write-Error "Failed to lookup '$DeviceId' by DisplayName"
            return
        }

        $deviceName = $mgDevice.DisplayName
        $DeviceId = $mgDevice.DeviceId
        Write-Verbose "Device DisplayName: '$deviceName'"
        Write-Verbose "Device DeviceId: '$DeviceId'"

        # Use guid device id
        $DeviceId = $mgDevice.DeviceId
    }

    # Build URI - beta graph endpoint for now
    $uri = 'beta/deviceLocalCredentials/' + $DeviceId

    # Get actual passwords if requested; note that $select=credentials will cause the server
    # to return all credentials, ie latest plus history. If -IncludeHistory was not actually
    # specified then we will drop the older passwords down below when displaying the results.
    if ($IncludePasswords)
    {
        $uri = $uri + '?$select=credentials'
    }

    # Create a new correlationID every time
    $correlationID = [System.Guid]::NewGuid()
    Write-Verbose "Created new GUID for cloud request correlation ID (client-request-id) '$correlationID'"

    $httpMethod = 'GET';

    $headers = @{}
    $headers.Add('ocp-client-name', 'Get-LapsAADPassword Windows LAPS Cmdlet')
    $headers.Add('ocp-client-version', '1.0')
    $headers.Add('client-request-id', $correlationID)

    try
    {
        Write-Verbose "Retrieving LAPS credentials for device id: '$DeviceId' with client-request-id:'$correlationID'"
        $queryResults = Invoke-MgGraphRequest -Method $httpMethod -Uri $URI -Headers $headers -OutputType Json
        Write-Verbose "Got LAPS credentials for device id: '$DeviceId':"
        Write-Verbose ""
        Write-Verbose $queryResults
        Write-Verbose ""
    }
    catch [Exception]
    {
        Write-Verbose "Failed trying to query LAPS credential for $DeviceId"
        Write-Verbose ""
        Write-Error $_
        Write-Verbose ""
        return
    }

    if ([string]::IsNullOrEmpty($queryResults))
    {
        Write-Verbose "Response was empty - device object does not have any persisted LAPS credentials"
        return
    }

    # Build custom PS output object
    Write-Verbose "Converting http response to json"
    $resultsJson = ConvertFrom-Json $queryResults
    Write-Verbose "Successfully converted http response to json:"
    Write-Verbose ""
    Write-Verbose $resultsJson
    Write-Verbose ""

    # Grab device name
    $lapsDeviceId = $resultsJson.deviceName

    # Grab device id
    $lapsDeviceId = New-Object([System.Guid])
    $lapsDeviceId = [System.Guid]::Parse($resultsJson.id)

    # Grab password expiration time (only applies to the latest password)
    $lapsPasswordExpirationTime = Get-Date $resultsJson.refreshDateTime

    if ($IncludePasswords)
    {
        # Copy the credentials array
        $credentials = $resultsJson.credentials

        # Sort the credentials array by backupDateTime.
        $credentials = $credentials | Sort-Object -Property backupDateTime -Descending

        # Note: current password (ie, the one most recently set) is now in the zero position of the array

        # If history was not requested, truncate the credential array down to just the latest one
        if (!$IncludeHistory)
        {
            $credentials = @($credentials[0])
        }

        foreach ($credential in $credentials)
        {
            $lapsDeviceCredential = New-Object PSObject

            Add-Member -InputObject $lapsDeviceCredential -MemberType NoteProperty -Name "DeviceName" -Value $resultsJson.deviceName

            Add-Member -InputObject $lapsDeviceCredential -MemberType NoteProperty -Name "DeviceId" -Value $lapsDeviceId

            Add-Member -InputObject $lapsDeviceCredential -MemberType NoteProperty -Name "Account" -Value $credential.accountName

            # Cloud returns passwords in base64, convert:

            if ($AsPlainText)
            {
                $password = ConvertBase64ToPlainText -base64 $credential.passwordBase64
            }
            else
            {
                $password = ConvertBase64ToSecureString -base64 $credential.passwordBase64
            }

            Add-Member -InputObject $lapsDeviceCredential -MemberType NoteProperty -Name "Password" -Value $password

            Add-Member -InputObject $lapsDeviceCredential -MemberType NoteProperty -Name "PasswordExpirationTime" -Value $lapsPasswordExpirationTime
            $lapsPasswordExpirationTime = $null

            $credentialUpdateTime = Get-Date $credential.backupDateTime
            Add-Member -InputObject $lapsDeviceCredential -MemberType NoteProperty -Name "PasswordUpdateTime" -Value $credentialUpdateTime

            # Note: cloud also returns an accountSid property - omitting it for now

            Write-Output $lapsDeviceCredential
        }
    }
    else
    {
        # Output a single object that just displays latest password expiration time
        # Note, $IncludeHistory is ignored even if specified in this case
        $lapsDeviceCredential = New-Object PSObject

        Add-Member -InputObject $lapsDeviceCredential -MemberType NoteProperty -Name "DeviceName" -Value $resultsJson.deviceName

        Add-Member -InputObject $lapsDeviceCredential -MemberType NoteProperty -Name "DeviceId" -Value $lapsDeviceId

        Add-Member -InputObject $lapsDeviceCredential -MemberType NoteProperty -Name "PasswordExpirationTime" -Value $lapsPasswordExpirationTime

        Write-Output $lapsDeviceCredential
    }
}

# This function is exported from the module
function DumpMSGraphContext
{
    Param (
        [object]$MsGraphContext
    )

    # Dump some of the MSGraph context details for diagnostics purposes
    Write-Verbose "Dumping MSGraph context details:"

    if ($mgContext.ClientId)
    {
        $verbOutput = [string]::Format('  ClientId: {0}', $mgContext.ClientId)
        Write-Verbose $verbOutput
    }
    if ($mgContext.TenantId)
    {
        $verbOutput = [string]::Format('  TenantId: {0}', $mgContext.TenantId)
        Write-Verbose $verbOutput
    }
    if ($mgContext.AuthType)
    {
       $verbOutput = [string]::Format('  AuthType: {0}', $mgContext.AuthType)
       Write-Verbose $verbOutput
    }
    if ($mgContext.AuthProviderType)
    {
        $verbOutput = [string]::Format('  AuthProviderType: {0}', $mgContext.AuthProviderType)
        Write-Verbose $verbOutput
    }
    if ($mgContext.Account)
    {
        $verbOutput = [string]::Format('  Account: {0}', $mgContext.Account)
        Write-Verbose $verbOutput
    }
    if ($mgContext.AppName)
    {
        $verbOutput = [string]::Format('  AppName: {0}', $mgContext.AppName)
        Write-Verbose $verbOutput
    }
    if ($mgContext.ContextScope)
    {
        $verbOutput = [string]::Format('  ContextScope: {0}', $mgContext.ContextScope)
        Write-Verbose $verbOutput
    }
    if ($mgContext.PSHostVersion)
    {
        $verbOutput = [string]::Format('  PSHostVersion: {0}', $mgContext.PSHostVersion)
        Write-Verbose $verbOutput
    }
    if ($mgContext.Scopes)
    {
        Write-Verbose "  Scopes:"
        foreach ($scope in $mgContext.Scopes)
        {
            $verbOutput = [string]::Format('    {0}', $scope)
            Write-Verbose $verbOutput
        }
    }
}

# This function is exported from the module
function Get-LapsAADPassword
{
    [CmdletBinding(DefaultParameterSetName = "DeviceSpecificQuery")]
    Param (
        [Parameter(
            ParameterSetName="DeviceSpecificQuery",
            Mandatory=$true,
            HelpMessage="Specifies the device ids to query LAPS credentials.")
        ]
        [string[]]$DeviceIds,

        [Parameter(
            HelpMessage="Specifies whether to return password information.")
        ]
        [Switch]$IncludePasswords,

        [Parameter(
            HelpMessage="Specifies whether to return older passwords.")
        ]
        [Switch]$IncludeHistory,

        [Parameter(
            HelpMessage="Specifies whether to display passwords in cleartext.")
        ]
        [Switch]$AsPlainText
    )

    Write-Verbose "Get-LapsAADPassword starting IncludePasswords:$IncludePasswords AsPlainText:$AsPlainText"

    $now = Get-Date
    $utcNow = $now.ToUniversalTime()
    Write-Verbose "Local now: '$now' (UTC now: '$utcNow')"

    $activityId = [System.Diagnostics.Trace]::CorrelationManager.ActivityId
    Write-Verbose "Current activityId: $activityId"

    if ($AsPlainText -and !$IncludePasswords)
    {
        Write-Warning "Note: specifying -AsPlainText has no effect unless -IncludePasswords is also specified"
        $AsPlainText = $false
    }

    # Validate that admin has logged into MSGraph already
    $msGraphAuthModule = Get-Module "Microsoft.Graph.Authentication"
    if (!$msGraphAuthModule)
    {
        throw "You must install the MSGraph PowerShell module before running this cmdlet, for example by running 'Install-Module Microsoft.Graph -Scope AllUsers'."
    }

    # Validate that admin has logged into MSGraph already
    $mgContext = Get-MgContext
    if (!$mgContext)
    {
        throw "You must first authenticate to MSGraph first running this cmdlet; see Connect-MgGraph cmdlet."
    }

    # Dump MS graph context details when Verbose is enabled
    if ($VerbosePreference -ne [System.Management.Automation.ActionPreference]::SilentlyContinue)
    {
       DumpMSGraphContext -MsGraphContext $mgContext
    }

    foreach ($DeviceId in $DeviceIds)
    {
        # Ignore empty strings
        if ([string]::IsNullOrEmpty($DeviceId))
        {
            continue
        }

        ProcessOneDevice -DeviceId $DeviceId -IncludePasswords $IncludePasswords -IncludeHistory $IncludeHistory -AsPlainText $AsPlainText
    }
}
