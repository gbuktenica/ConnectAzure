<#
    .SYNOPSIS
        Connect to an Azure tenant

    .PARAMETER Environment
        The Azure environment and subscription that is used to deploy artefacts to.

    .PARAMETER ApiId
        Used with ApiSecret for an non interactive logon to Azure.
        This is useful for pipeline logon to Azure when a Service Principal is not available.
        If no ApiId is present and a Service Principal is not available then the operator will be prompted for an interactive logon.

    .PARAMETER InvokeCommands
        Used with InvokeArguments to all another PowerShell script at the completion of this script but without ending the process.

    .PARAMETER Pipeline
        Used when this script is called by a pipeline and therefore interactive logon and switching of subscriptions is not possible.

    .EXAMPLE
        .\Connect-Azure.ps1 -Environment Prod
        Connect to the Azure Prod Environment, Prompt for interactive login if not already logged in and exit.

    .EXAMPLE
        .\Connect-Azure.ps1 -InvokeCommand "$(Build.SourcesDirectory)/AzMigrate_StartReplication.ps1" -InvokeArguments "$(Build.SourcesDirectory)/Example.CSV"
        Connect to the Azure Dev Environment, Prompt for interactive login if not already logged in and then run the PowerShell script:
            AzMigrate_StartReplication.ps1
            with arguments
            Example.CSV

    .EXAMPLE
        .\Connect-Azure.ps1 -ApiId $(ApiID) -ApiSecret $(ApiSecret)
        Connect to the Azure Dev Environment with an API ID and Secret that is stored in a pipeline group and then exit. There will be no interactive logon.

    .EXAMPLE
        .\Connect-Azure.ps1 -Pipeline
        Connect to the Azure Dev Environment with the existing Pipeline credentials. There will be no interactive logon or switching of the subscription ID.

    .NOTES
        License      : MIT License
        Copyright (c): 2021 Glen Buktenica
        Release      : v1.0.0 20210317
#>
[CmdletBinding()]
Param(
    [Parameter()]
    [ValidateSet('Dev', 'Prod')]
    [string]
    $Environment = "Dev",
    [String]
    $ApiId,
    [String]
    $ApiSecret,
    [String[]]
    $InvokeCommands,
    [String]
    $InvokeArguments,
    [switch]
    $Pipeline
)
function Get-SavedCredentials {
    <#
    .SYNOPSIS
        Returns a PSCredential from an encrypted file.
    .DESCRIPTION
        Returns a PSCredential from a file encrypted using Windows Data Protection API (DAPI).
        If the file does not exist the user will be prompted for the username and password the first time.
        The GPO setting Network Access: Do not allow storage of passwords and credentials for network authentication must be set to Disabled
        otherwise the password will only persist for the length of the user session.
    .PARAMETER Title
        The name of the username and password pair. This allows multiple accounts to be saved such as a normal account and an administrator account.
    .PARAMETER VaultPath
        The file path of the encrypted Json file for saving the username and password pair.
        Default value is c:\users\<USERNAME>\PowerShellHash.json"
    .PARAMETER Renew
        Prompts the user for a new password for an existing pair.
        To be used after a password change.
    .EXAMPLE
        Enter-PsSession -ComputerName Computer -Credential (Get-SavedCredentials)
    .EXAMPLE
        $Credential = Get-SavedCredentials -Title Normal -VaultPath c:\temp\myFile.json
    .LINK
        https://github.com/gbuktenica/GetSavedCredentials
    .NOTES
        License      : MIT License
        Copyright (c): 2020 Glen Buktenica
        Release      : v1.0.0 20200315
    #>
    [CmdletBinding()]
    Param(
        [string]$Title = "Default",
        [string]$VaultPath = "$env:USERPROFILE\PowerShellHash.json",
        [switch]$Renew
    )
    $JsonChanged = $false
    if (-not (Test-path -Path $VaultPath)) {
        # Create a new Json object if the file does not exist.
        $Json = "{`"$Title`": { `"username`": `"`", `"password`": `"`" }}" | ConvertFrom-Json
        $JsonChanged = $true
    } else {
        try {
            # Read the file if it already exists
            $Json = Get-Content -Raw -Path $VaultPath | ConvertFrom-Json -ErrorAction Stop
        } catch {
            # If the file is corrupt overwrite it.
            $Json = "{`"$Title`": { `"username`": `"`", `"password`": `"`" }}" | ConvertFrom-Json
            $JsonChanged = $true
        }
    }
    if ($Json.$Title.length -eq 0) {
        # Create a new Username \ Password key if it is new.
        $TitleContent = " { `"username`":`"`", `"password`":`"`" }"
        $Json | Add-Member -Name $Title -value (Convertfrom-Json $TitleContent) -MemberType NoteProperty
        $JsonChanged = $true
    }
    if ($Json.$Title.username.Length -eq 0) {
        #Prompt user for username if it is not saved.
        $Message = "Enter User name for> $Title"
        $Username = Read-Host $Message -ErrorAction Stop
        ($Json.$Title.username) = $Username
        $JsonChanged = $true
    }
    if ($Json.$Title.password.Length -eq 0 -or $Renew) {
        #Prompt user for Password if it is not saved.
        $Message = "Enter Password for> " + $Json.$Title.username
        $secureStringPwd = Read-Host $Message -AsSecureString -ErrorAction Stop
        $secureStringText = $secureStringPwd | ConvertFrom-SecureString
        $Json.$Title.password = $secureStringText
        $JsonChanged = $true
    }

    $Username = $Json.$Title.username
    Try {
        # Build the PSCredential object and export it.
        $SecurePassword = $Json.$Title.password | ConvertTo-SecureString -ErrorAction Stop
        New-Object System.Management.Automation.PSCredential -ArgumentList $Username, $SecurePassword -ErrorAction Stop
    } catch {
        # If building the credential failed for any reason delete it and run the function
        # again which will prompt the user for username and password.
        $TitleContent = " { `"username`":`"`", `"password`":`"`" }"
        $Json | Add-Member -Name $Title -value (Convertfrom-Json $TitleContent) -MemberType NoteProperty -Force
        $Json | ConvertTo-Json -depth 3 | Set-Content $VaultPath -ErrorAction Stop
        Get-SavedCredentials -Title $Title -VaultPath $VaultPath
    }
    if ($JsonChanged) {
        # Save the Json object to file if it has changed.
        $Json | ConvertTo-Json -depth 3 | Set-Content $VaultPath -ErrorAction Stop
    }
}
$SaveVerbosePreference = $global:VerbosePreference

# Install and import dependencies
$Modules = @("Az.Accounts", "Az.Migrate", "Az.Resources", "Az.Storage","Az.Network")
foreach ($Module in $Modules) {
    if (-not (Get-Module -ListAvailable -Name $Module -Verbose:$false)) {
        Write-Output "Installing module $Module"
        $global:VerbosePreference = 'SilentlyContinue'
        Install-Module -Name $Module -ErrorAction Stop -Verbose:$false -Scope CurrentUser -Force -AllowClobber | Out-Null
        $global:VerbosePreference = $SaveVerbosePreference
    } else {
        Write-Verbose "Module $Module already installed."
    }
}

foreach ($Module in $Modules) {
    if (-not (Get-Module -Name $Module -Verbose:$false)) {
        Write-Output "Importing $Module module"
        $global:VerbosePreference = 'SilentlyContinue'
        Import-Module -Name $Module -ErrorAction Stop -Verbose:$false | Out-Null
        $global:VerbosePreference = $SaveVerbosePreference
    } else {
        Write-Verbose "module $Module already imported."
    }
}
Write-Output "Finished Importing modules"

# Read the Azure subscription settings from the json.
if (Test-Path "$PsScriptRoot\Connect-Azure.json") {
    $JsonParameters = Get-Content "$PsScriptRoot\Connect-Azure.json" -Raw -ErrorAction Stop | ConvertFrom-Json
} else {
    Write-Error "File $PsScriptRoot\Connect-Azure.json not found"
    Exit
}
$TenantId = $JsonParameters.$Environment.TenantId
$SubscriptionId = $JsonParameters.$Environment.SubscriptionId

Write-Verbose "Azure Tenant Id: $TenantId"
Write-Verbose "Azure Subscription Id: $SubscriptionId"

if ($null -eq (Get-AzContext)) {
    # Log into Azure if no connection exists.
    Write-Output "Logging into Azure"
    if ($ApiSecret.length -eq 0) {
        if ($Pipeline) {
            Write-Error "No API secrets and no existing Azure connection with Pipeline switch. Cannot logon"
            Exit 1
        } else {
            # Obtain privileged credentials from an encrypted file or operator to use to connect to the remote computers.
            if ($null -eq $Credential) {
                if ($NoSave) {
                    $Credential = Get-Credential
                } else {
                    $Credential = Get-SavedCredentials -Title Azure -Renew:$Renew
                }
            }
            Connect-AzAccount -TenantId $TenantId -SubscriptionId $SubscriptionId -ErrorAction Stop -Credential $Credential
        }
    } else {
        Write-Output "Connect with API ID: $ApiId"
        $ApiSecureSecret = ConvertTo-SecureString $ApiSecret -AsPlainText -Force
        $Credential = New-Object System.Management.Automation.PSCredential($ApiId , $ApiSecureSecret)
        Connect-AzAccount -TenantId $TenantId -SubscriptionId $SubscriptionId -ErrorAction Stop -Credential $Credential
    }
} else {
    # Test if existing connection is correct or log off and back on.
    $ConnectedSubscription = (Get-AzContext).Subscription.Id
    If ($ConnectedSubscription -eq $SubscriptionId) {
        Write-Verbose "Already connected to Azure. Skipping login."
    } else {
        Write-Output "Requested Subscription ID: $SubscriptionId not equal to currently connected Subscription ID: $ConnectedSubscription"
        if ($Pipeline) {
            Write-Output "Pipeline Switch set. Continuing with current Subscription ID: $ConnectedSubscription"
        } else {
            Write-Output "Logging Out"
            Remove-AzAccount | Out-Null
            Write-Output "Logging back into Azure"
            if ($ApiSecret.length -eq 0) {
                # Obtain privileged credentials from an encrypted file or operator to use to connect to the remote computers.
                if ($null -eq $Credential) {
                    if ($NoSave) {
                        $Credential = Get-Credential
                    } else {
                        $Credential = Get-SavedCredentials -Title Azure -Renew:$Renew
                    }
                }
                Connect-AzAccount -TenantId $TenantId -SubscriptionId $SubscriptionId -ErrorAction Stop -Credential $Credential
            } else {
                $ApiSecureSecret = ConvertTo-SecureString $ApiSecret -AsPlainText -Force
                $Credential = New-Object System.Management.Automation.PSCredential($ApiId , $ApiSecureSecret)
                Connect-AzAccount -TenantId $TenantId -SubscriptionId $SubscriptionId -ErrorAction Stop -Credential $Credential
            }
        }
    }
}
Write-Output "Finished Logging on to Azure"
# Call the next PowerShell script(s) with arguments.
if ($null -ne $InvokeCommands) {
    # Split string into array in case it has been passed incorrectly via the pipeline
    If ($InvokeCommands -match ",") {
        Write-Output "Splitting String to array"
        $InvokeCommands = $InvokeCommands.Split(",")
    }
    foreach ($InvokeCommand in $InvokeCommands) {
        # Remove leading and trailing spaces if any
        $InvokeCommand = $InvokeCommand.trim()
        Write-Output "==========================================="
        Write-Output "Starting $InvokeCommand"
        Write-Output "With Arguments: $InvokeArguments"
        Get-Item InvokeCommand.log -ErrorAction SilentlyContinue | Remove-Item
        # Start next script with the call operator "&"
        & $InvokeCommand $InvokeArguments *> InvokeCommand.log

        # Display log out put that was redirected to the log file
        Get-Content InvokeCommand.log

        # Trap any errors in the log here and terminate the pipeline
        If (Select-String -Path InvokeCommand.log -Pattern 'ERROR') {
            # Highlight failing line on screen
            Write-Output "==========================================="
            Select-String -Path InvokeCommand.log -Pattern 'ERROR'
            Write-Output "==========================================="
            # Create terminating error to "fail" the pipeline.
            Write-Error "$InvokeCommand Failed" -ErrorAction Stop
            Exit 1
        }
        Get-Item InvokeCommand.log -ErrorAction SilentlyContinue | Remove-Item
    }
}
