<#
.SYNOPSIS
    Active Directory User Provisioning Script

.DESCRIPTION
    Automates the creation of standard user and administrator accounts in
    Active Directory from a CSV file. Includes pre-flight validation, duplicate
    detection, secure password handling, role-based OU placement, admin group
    membership, and full logging.

.PARAMETER CsvPath
    Path to the CSV file containing user records.

.PARAMETER LogPath
    Path to the output log file. Defaults to a timestamped file in the
    script's directory.

.PARAMETER AdminGroup
    Security group to which Admin-role users are added.
    Defaults to "IT Admins".

.PARAMETER DefaultPasswordPath
    Optional path to a file containing the default password (single line).
    If omitted, the operator is prompted securely at runtime.

.PARAMETER WhatIf
    Enables simulation mode -- logs intended actions without making AD changes.

.EXAMPLE
    .\New-ADUserProvisioning.ps1 -CsvPath ".\AD_Users.csv"
    .\New-ADUserProvisioning.ps1 -CsvPath ".\AD_Users.csv" -AdminGroup "Domain Admins" -WhatIf

.NOTES
    Author  : Systems Administration Team
    Version : 2.1
    Requires: ActiveDirectory PowerShell module, domain-joined machine,
              account with delegated OU + group-management rights.
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory = $true, HelpMessage = "Path to the CSV file with user data.")]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [string]$LogPath,

    [Parameter(Mandatory = $false)]
    [string]$AdminGroup = "IT Admins",

    [Parameter(Mandatory = $false)]
    [string]$DefaultPasswordPath
)

# ---------------------------------------------
# REGION: Initialisation & Helpers
# ---------------------------------------------

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Build a timestamped log path if the caller did not supply one.
if (-not $LogPath) {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $LogPath   = Join-Path $PSScriptRoot "AD_Provisioning_$timestamp.log"
}

function Write-Log {
    <#
    .SYNOPSIS
        Writes a message to both the console and the log file with a severity tag.
    #>
    param (
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )

    $entry = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message

    switch ($Level) {
        "ERROR"   { Write-Host $entry -ForegroundColor Red }
        "WARN"    { Write-Host $entry -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $entry -ForegroundColor Green }
        default   { Write-Host $entry -ForegroundColor Cyan }
    }

    # Append to log file (create if missing).
    Add-Content -Path $LogPath -Value $entry
}

# Counters for the summary report.
$script:Stats = @{
    Created  = 0
    Skipped  = 0
    Failed   = 0
    Admins   = 0
}

# ---------------------------------------------
# REGION: Pre-flight Checks
# ---------------------------------------------

Write-Log "===== AD User Provisioning Script Started =====" "INFO"
Write-Log "Log file  : $LogPath" "INFO"
Write-Log "CSV source: $CsvPath" "INFO"

# 1. ActiveDirectory module ----------------------------------------------------
Write-Log "Checking for the ActiveDirectory PowerShell module..." "INFO"

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Log "ActiveDirectory module is NOT installed. Install RSAT or the AD DS role tools, then retry." "ERROR"
    exit 1
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Log "ActiveDirectory module imported successfully." "SUCCESS"
}
catch {
    Write-Log "Failed to import ActiveDirectory module: $_" "ERROR"
    exit 1
}

# 2. CSV file exists -----------------------------------------------------------
if (-not (Test-Path -Path $CsvPath -PathType Leaf)) {
    Write-Log "CSV file not found at '$CsvPath'. Verify the path and retry." "ERROR"
    exit 1
}

Write-Log "CSV file found." "INFO"

# 3. Parse and validate CSV ----------------------------------------------------
try {
    $users = Import-Csv -Path $CsvPath -ErrorAction Stop
}
catch {
    Write-Log "Failed to parse CSV: $_" "ERROR"
    exit 1
}

$requiredColumns = @("FirstName", "LastName", "Username", "Department", "Title", "Role", "OU", "EmailDomain")
$csvColumns      = ($users | Get-Member -MemberType NoteProperty).Name

foreach ($col in $requiredColumns) {
    if ($col -notin $csvColumns) {
        Write-Log "CSV is missing required column: '$col'. Expected columns: $($requiredColumns -join ', ')" "ERROR"
        exit 1
    }
}

Write-Log "CSV validated -- $($users.Count) record(s) found." "INFO"

# 4. Obtain the default password securely --------------------------------------
if ($DefaultPasswordPath) {
    # Read from a protected file (ACL-restricted in production).
    if (-not (Test-Path $DefaultPasswordPath)) {
        Write-Log "Password file not found at '$DefaultPasswordPath'." "ERROR"
        exit 1
    }
    $securePassword = Get-Content $DefaultPasswordPath -Raw |
                      ForEach-Object { $_.Trim() } |
                      ConvertTo-SecureString -AsPlainText -Force
    Write-Log "Default password loaded from file." "INFO"
}
else {
    # Prompt the operator interactively -- nothing is echoed to screen.
    $securePassword = Read-Host -Prompt "Enter the default password for new accounts" -AsSecureString
    Write-Log "Default password obtained from operator prompt." "INFO"
}

# 5. Verify the admin security group exists ------------------------------------
try {
    Get-ADGroup -Identity $AdminGroup -ErrorAction Stop | Out-Null
    Write-Log "Admin security group '$AdminGroup' verified." "SUCCESS"
}
catch {
    Write-Log "Security group '$AdminGroup' not found in AD. Create it first or specify a different group with -AdminGroup." "ERROR"
    exit 1
}

# ---------------------------------------------
# REGION: User Creation Loop
# ---------------------------------------------

Write-Log "Beginning user provisioning..." "INFO"
Write-Log ("-" * 60) "INFO"

foreach ($user in $users) {
    $sam         = $user.Username.Trim()
    $first       = $user.FirstName.Trim()
    $last        = $user.LastName.Trim()
    $display     = "$first $last"
    $upn         = "$sam@$($user.EmailDomain.Trim())"
    $email       = $upn                                # UPN doubles as email
    $department  = $user.Department.Trim()
    $title       = $user.Title.Trim()
    $role        = $user.Role.Trim()
    $targetOU    = $user.OU.Trim()

    Write-Log "Processing: $display ($sam) | Role: $role | OU: $targetOU" "INFO"

    # -- Duplicate check -------------------------------------------------------
    try {
        $existingUser = Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction Stop
    }
    catch {
        # Filter query failed -- treat as non-blocking but log it.
        Write-Log "  Warning: could not query AD for '$sam': $_" "WARN"
        $existingUser = $null
    }

    if ($existingUser) {
        Write-Log "  SKIPPED: '$sam' already exists (DN: $($existingUser.DistinguishedName))." "WARN"
        $script:Stats.Skipped++
        continue
    }

    # -- Verify target OU exists -----------------------------------------------
    try {
        Get-ADOrganizationalUnit -Identity $targetOU -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Log "  FAILED: Target OU '$targetOU' does not exist. Skipping '$sam'." "ERROR"
        $script:Stats.Failed++
        continue
    }

    # -- Create the user account -----------------------------------------------
    $newUserParams = @{
        SamAccountName        = $sam
        UserPrincipalName     = $upn
        GivenName             = $first
        Surname               = $last
        Name                  = $display
        DisplayName           = $display
        EmailAddress          = $email
        Department            = $department
        Title                 = $title
        Path                  = $targetOU
        AccountPassword       = $securePassword
        Enabled               = $true
        ChangePasswordAtLogon = $true
        PassThru              = $true        # Returns the created object
    }

    # Description distinguishes admin accounts at a glance.
    if ($role -eq "Admin") {
        $newUserParams["Description"] = "Administrator account - $title"
    }
    else {
        $newUserParams["Description"] = "$title - $department"
    }

    try {
        if ($PSCmdlet.ShouldProcess($sam, "Create AD user in $targetOU")) {
            $createdUser = New-ADUser @newUserParams -ErrorAction Stop
            Write-Log "  CREATED: '$sam' provisioned in '$targetOU'." "SUCCESS"
            $script:Stats.Created++
        }
        else {
            # WhatIf mode -- count but don't execute.
            Write-Log "  WHATIF: Would create '$sam' in '$targetOU'." "INFO"
            $script:Stats.Created++
            continue   # Skip group logic when simulating.
        }
    }
    catch {
        Write-Log "  FAILED: Could not create '$sam': $_" "ERROR"
        $script:Stats.Failed++
        continue
    }

    # -- Admin group membership ------------------------------------------------
    if ($role -eq "Admin") {
        try {
            Add-ADGroupMember -Identity $AdminGroup -Members $sam -ErrorAction Stop
            Write-Log "  ADMIN: '$sam' added to '$AdminGroup'." "SUCCESS"
            $script:Stats.Admins++
        }
        catch {
            Write-Log "  WARNING: '$sam' created but could NOT be added to '$AdminGroup': $_" "WARN"
        }
    }
}

# ---------------------------------------------
# REGION: Summary Report
# ---------------------------------------------

Write-Log ("-" * 60) "INFO"
Write-Log "===== Provisioning Complete =====" "INFO"
Write-Log "  Accounts created : $($script:Stats.Created)" "INFO"
Write-Log "  Duplicates skipped: $($script:Stats.Skipped)" "WARN"
Write-Log "  Failures          : $($script:Stats.Failed)" $(if ($script:Stats.Failed -gt 0) { "ERROR" } else { "INFO" })
Write-Log "  Admin memberships : $($script:Stats.Admins)" "INFO"
Write-Log "Full log written to: $LogPath" "INFO"
