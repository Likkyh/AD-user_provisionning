<#
.SYNOPSIS
    Active Directory User Provisioning Script

.DESCRIPTION
    Automates the creation of standard user and administrator accounts in
    Active Directory from a CSV file. Features include:
      - Automatic OU creation when target OUs do not exist
      - Admin accounts are always placed in the "Administrateur" OU
      - Secure random password generation (12 chars for users, 18 for admins)
      - Per-user credentials export ([USERNAME]_login.txt) in a "Created logins" directory
      - Fine-Grained Password Policies for rotation (90 days users / 60 days admins)
      - Account expiration set to 1 year from creation date
      - Mandatory password change at first logon

.PARAMETER CsvPath
    Path to the CSV file containing user records.

.PARAMETER LogPath
    Path to the output log file. Defaults to a timestamped file in the
    script's directory.

.PARAMETER AdminGroup
    Security group to which Admin-role users are added.
    Defaults to "IT Admins".

.PARAMETER LoginsOutputDir
    Path to the directory where per-user credential files are written.
    Each file is named [USERNAME]_login.txt.
    Defaults to "Created logins" in the script's directory.
    The directory is created automatically if it does not exist.

.PARAMETER WhatIf
    Enables simulation mode -- logs intended actions without making AD changes.

.EXAMPLE
    .\New-ADUserProvisioning.ps1 -CsvPath ".\AD_Users.csv"
    .\New-ADUserProvisioning.ps1 -CsvPath ".\AD_Users.csv" -AdminGroup "Domain Admins" -WhatIf

.NOTES
    Author  : Systems Administration Team
    Version : 3.0
    Requires: ActiveDirectory PowerShell module, domain-joined machine,
              account with delegated OU + group-management rights.
              Domain functional level 2008+ for Fine-Grained Password Policies.
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
    [string]$LoginsOutputDir
)

# ---------------------------------------------
# REGION: Initialisation & Helpers
# ---------------------------------------------

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Build default paths if the caller did not supply them.
if (-not $LogPath) {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $LogPath   = Join-Path $PSScriptRoot "AD_Provisioning_$timestamp.log"
}
if (-not $LoginsOutputDir) {
    $LoginsOutputDir = Join-Path $PSScriptRoot "Created logins"
}

# Create the logins output directory if it does not exist.
if (-not (Test-Path -Path $LoginsOutputDir -PathType Container)) {
    New-Item -Path $LoginsOutputDir -ItemType Directory -Force | Out-Null
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

    Add-Content -Path $LogPath -Value $entry
}

function New-SecurePassword {
    <#
    .SYNOPSIS
        Generates a cryptographically random password that meets complexity
        requirements: at least 1 uppercase letter, 1 lowercase letter,
        1 digit, and 1 symbol.
    .PARAMETER Length
        Desired password length (minimum 8).
    #>
    param (
        [Parameter(Mandatory)]
        [ValidateRange(8, 128)]
        [int]$Length
    )

    $uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    $lowercase = "abcdefghijklmnopqrstuvwxyz"
    $digits    = "0123456789"
    $symbols   = "!@#$%^&*()-_=+[]{}|;:,.<>?"
    $allChars  = $uppercase + $lowercase + $digits + $symbols

    # Use .NET cryptographic RNG for secure randomness.
    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()

    # Helper: pick one random character from a given set.
    function Get-RandomChar([string]$CharSet) {
        $byte = [byte[]]::new(1)
        $rng.GetBytes($byte)
        return $CharSet[$byte[0] % $CharSet.Length]
    }

    # Guarantee at least one character from each required category.
    $mandatory = @(
        (Get-RandomChar $uppercase),
        (Get-RandomChar $lowercase),
        (Get-RandomChar $digits),
        (Get-RandomChar $symbols)
    )

    # Fill the remaining length with characters from the full set.
    $remaining = $Length - $mandatory.Count
    $filler = @()
    for ($i = 0; $i -lt $remaining; $i++) {
        $filler += (Get-RandomChar $allChars)
    }

    # Combine and shuffle (Fisher-Yates) so mandatory chars are not predictable.
    $password = $mandatory + $filler
    for ($i = $password.Count - 1; $i -gt 0; $i--) {
        $byte = [byte[]]::new(1)
        $rng.GetBytes($byte)
        $j = $byte[0] % ($i + 1)
        $temp = $password[$i]
        $password[$i] = $password[$j]
        $password[$j] = $temp
    }

    $rng.Dispose()
    return -join $password
}

function Ensure-OUPath {
    <#
    .SYNOPSIS
        Verifies that every OU level in a distinguished name path exists.
        Creates missing OUs from the top (closest to root) down.
    .PARAMETER DistinguishedName
        Full DN path, e.g. "OU=Engineering,OU=Users,DC=contoso,DC=com".
        Semicolons are accepted and converted to commas automatically.
    #>
    param (
        [Parameter(Mandatory)]
        [string]$DistinguishedName
    )

    # Normalise separator: the CSV uses semicolons for readability.
    $dn = $DistinguishedName.Replace(";", ",")

    # Split the DN into its RDN components.
    $parts = $dn -split "(?<!\\),"

    # Separate OU parts from DC parts.
    $ouParts = @($parts | Where-Object { $_ -match "^OU=" })
    $dcParts = @($parts | Where-Object { $_ -match "^DC=" })
    $domainBase = ($dcParts -join ",")

    if ($ouParts.Count -eq 0) {
        Write-Log "    No OU components in '$dn' -- nothing to create." "WARN"
        return $dn
    }

    # Build each OU level from the root upward.
    # OUs are listed left-to-right from deepest to shallowest in a DN,
    # so we reverse to create parents first.
    [array]::Reverse($ouParts)

    $currentBase = $domainBase

    foreach ($ouRDN in $ouParts) {
        $targetDN = "$ouRDN,$currentBase"
        $ouName   = ($ouRDN -split "=", 2)[1]

        try {
            Get-ADOrganizationalUnit -Identity $targetDN -ErrorAction Stop | Out-Null
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            # OU does not exist -- create it.
            try {
                New-ADOrganizationalUnit -Name $ouName -Path $currentBase `
                    -ProtectedFromAccidentalDeletion $true -ErrorAction Stop
                Write-Log "    OU CREATED: $targetDN" "SUCCESS"
                $script:Stats.OUCreated++
            }
            catch {
                Write-Log "    FAILED to create OU '$targetDN': $_" "ERROR"
                throw
            }
        }
        catch {
            Write-Log "    Could not verify OU '$targetDN': $_" "ERROR"
            throw
        }

        # Move down one level for the next iteration.
        $currentBase = $targetDN
    }

    # Return the full normalised DN (commas, not semicolons).
    return $dn
}

function Ensure-PasswordPolicy {
    <#
    .SYNOPSIS
        Creates a Fine-Grained Password Policy (PSO) if it does not already
        exist, and applies it to the specified group.
    .PARAMETER PolicyName
        Name of the PSO.
    .PARAMETER MaxAgeDays
        Maximum password age in days before the user must change it.
    .PARAMETER Precedence
        PSO precedence (lower = higher priority).
    .PARAMETER TargetGroup
        SamAccountName of the group the policy applies to.
    .PARAMETER MinLength
        Minimum password length enforced by the policy.
    #>
    param (
        [string]$PolicyName,
        [int]$MaxAgeDays,
        [int]$Precedence,
        [string]$TargetGroup,
        [int]$MinLength = 12
    )

    try {
        $existingPSO = Get-ADFineGrainedPasswordPolicy -Identity $PolicyName -ErrorAction Stop
        Write-Log "  Password policy '$PolicyName' already exists (MaxAge: $($existingPSO.MaxPasswordAge))." "INFO"
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Write-Log "  Creating password policy: '$PolicyName' (max age $MaxAgeDays days, min length $MinLength)..." "INFO"
        try {
            New-ADFineGrainedPasswordPolicy -Name $PolicyName `
                -DisplayName $PolicyName `
                -Precedence $Precedence `
                -MaxPasswordAge (New-TimeSpan -Days $MaxAgeDays) `
                -MinPasswordAge (New-TimeSpan -Days 1) `
                -MinPasswordLength $MinLength `
                -PasswordHistoryCount 12 `
                -ComplexityEnabled $true `
                -ReversibleEncryptionEnabled $false `
                -LockoutDuration (New-TimeSpan -Minutes 30) `
                -LockoutObservationWindow (New-TimeSpan -Minutes 30) `
                -LockoutThreshold 5 `
                -ErrorAction Stop
            Write-Log "  Password policy '$PolicyName' created." "SUCCESS"
        }
        catch {
            Write-Log "  FAILED to create password policy '$PolicyName': $_" "ERROR"
            Write-Log "  (Requires domain functional level 2008 or higher.)" "WARN"
            return
        }
    }
    catch {
        Write-Log "  Could not check password policy '$PolicyName': $_" "ERROR"
        return
    }

    # Link the PSO to the target group.
    try {
        Add-ADFineGrainedPasswordPolicySubject -Identity $PolicyName `
            -Subjects $TargetGroup -ErrorAction Stop
        Write-Log "  Policy '$PolicyName' linked to group '$TargetGroup'." "SUCCESS"
    }
    catch {
        # If already linked, AD throws a non-terminating error -- safe to continue.
        Write-Log "  Policy '$PolicyName' may already be linked to '$TargetGroup': $_" "WARN"
    }
}

# Counters for the summary report.
$script:Stats = @{
    Created   = 0
    Skipped   = 0
    Failed    = 0
    Admins    = 0
    OUCreated = 0
}

# Collects login records for the per-user credential files.
$script:LoginRecords = [System.Collections.ArrayList]::new()

# ---------------------------------------------
# REGION: Pre-flight Checks
# ---------------------------------------------

Write-Log "===== AD User Provisioning Script v3.0 Started =====" "INFO"
Write-Log "Log file      : $LogPath" "INFO"
Write-Log "CSV source    : $CsvPath" "INFO"
Write-Log "Logins dir    : $LoginsOutputDir" "INFO"

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

# 4. Retrieve domain DN from AD ------------------------------------------------
try {
    $domainDN = (Get-ADDomain -ErrorAction Stop).DistinguishedName
    Write-Log "Domain DN detected: $domainDN" "INFO"
}
catch {
    Write-Log "Failed to retrieve domain information: $_" "ERROR"
    exit 1
}

# 5. Ensure the Administrateur OU exists at domain root ------------------------
$adminOU = "OU=Administrateur,$domainDN"
Write-Log "Ensuring Administrateur OU exists..." "INFO"
try {
    Ensure-OUPath -DistinguishedName $adminOU
}
catch {
    Write-Log "FATAL: Could not create Administrateur OU: $_" "ERROR"
    exit 1
}

# 6. Ensure admin security group exists ----------------------------------------
try {
    Get-ADGroup -Identity $AdminGroup -ErrorAction Stop | Out-Null
    Write-Log "Admin security group '$AdminGroup' verified." "SUCCESS"
}
catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
    Write-Log "Admin group '$AdminGroup' not found -- creating it in '$adminOU'..." "WARN"
    try {
        New-ADGroup -Name $AdminGroup `
            -GroupScope Global `
            -GroupCategory Security `
            -Path $adminOU `
            -Description "Security group for IT administrators" `
            -ErrorAction Stop
        Write-Log "Admin group '$AdminGroup' created." "SUCCESS"
    }
    catch {
        Write-Log "FAILED to create admin group '$AdminGroup': $_" "ERROR"
        exit 1
    }
}
catch {
    Write-Log "Error checking admin group '$AdminGroup': $_" "ERROR"
    exit 1
}

# 7. Ensure standard users group exists ----------------------------------------
$standardUsersGroup = "Standard Users"
try {
    Get-ADGroup -Identity $standardUsersGroup -ErrorAction Stop | Out-Null
    Write-Log "Standard users group '$standardUsersGroup' verified." "INFO"
}
catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
    Write-Log "Group '$standardUsersGroup' not found -- creating it..." "WARN"
    try {
        New-ADGroup -Name $standardUsersGroup `
            -GroupScope Global `
            -GroupCategory Security `
            -Path $domainDN `
            -Description "Group for standard user password policy" `
            -ErrorAction Stop
        Write-Log "Group '$standardUsersGroup' created." "SUCCESS"
    }
    catch {
        Write-Log "FAILED to create group '$standardUsersGroup': $_" "ERROR"
        exit 1
    }
}

# 8. Setup Fine-Grained Password Policies -------------------------------------
Write-Log "Configuring password rotation policies..." "INFO"

# Users: password expires every 90 days, min length 12.
Ensure-PasswordPolicy -PolicyName "PSO-StandardUsers-90Days" `
    -MaxAgeDays 90 -Precedence 20 -TargetGroup $standardUsersGroup -MinLength 12

# Admins: password expires every 60 days, min length 18.
Ensure-PasswordPolicy -PolicyName "PSO-Admins-60Days" `
    -MaxAgeDays 60 -Precedence 10 -TargetGroup $AdminGroup -MinLength 18

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
    $email       = $upn
    $department  = $user.Department.Trim()
    $title       = $user.Title.Trim()
    $role        = $user.Role.Trim()
    $csvOU       = $user.OU.Trim()

    # -- Determine target OU and password length based on role -----------------
    $isAdmin = ($role -eq "Admin")

    if ($isAdmin) {
        # Admins ALWAYS go into the Administrateur OU regardless of CSV value.
        $targetOU   = $adminOU
        $pwdLength  = 18
        $roleLabel  = "ADMIN"
    }
    else {
        # Standard users go to the OU specified in the CSV.
        $targetOU   = $csvOU.Replace(";", ",")
        $pwdLength  = 12
        $roleLabel  = "USER"
    }

    Write-Log "Processing [$roleLabel]: $display ($sam) -> $targetOU" "INFO"

    # -- Duplicate check -------------------------------------------------------
    try {
        $existingUser = Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction Stop
    }
    catch {
        Write-Log "  Warning: could not query AD for '$sam': $_" "WARN"
        $existingUser = $null
    }

    if ($existingUser) {
        Write-Log "  SKIPPED: '$sam' already exists (DN: $($existingUser.DistinguishedName))." "WARN"
        $script:Stats.Skipped++
        continue
    }

    # -- Ensure the target OU tree exists (auto-create if needed) --------------
    try {
        $normalisedOU = Ensure-OUPath -DistinguishedName $targetOU
        $targetOU = $normalisedOU
    }
    catch {
        Write-Log "  FAILED: Could not create/verify OU path for '$sam': $_" "ERROR"
        $script:Stats.Failed++
        continue
    }

    # -- Generate a secure random password -------------------------------------
    $plainPassword  = New-SecurePassword -Length $pwdLength
    $securePassword = ConvertTo-SecureString -String $plainPassword -AsPlainText -Force

    # -- Compute account expiration (1 year from today) --------------------------
    $accountExpiration = (Get-Date).AddYears(1)

    # -- Build user creation parameters ----------------------------------------
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
        AccountExpirationDate = $accountExpiration    # Account disabled after 1 year
        Enabled               = $true
        ChangePasswordAtLogon = $true                 # Forces password change at first logon
        PassThru              = $true
    }

    if ($isAdmin) {
        $newUserParams["Description"] = "Administrator account - $title"
    }
    else {
        $newUserParams["Description"] = "$title - $department"
    }

    # -- Create the user account -----------------------------------------------
    try {
        if ($PSCmdlet.ShouldProcess($sam, "Create AD user in $targetOU")) {
            $createdUser = New-ADUser @newUserParams -ErrorAction Stop
            Write-Log "  CREATED: '$sam' provisioned in '$targetOU' (account expires $($accountExpiration.ToString('yyyy-MM-dd')))." "SUCCESS"
            $script:Stats.Created++

            # Record credentials for the logins export file.
            [void]$script:LoginRecords.Add([PSCustomObject]@{
                Username       = $sam
                DisplayName    = $display
                Role           = $role
                Password       = $plainPassword
                MustChange     = "Yes (first logon)"
                PwdRotation    = if ($isAdmin) { "60 days" } else { "90 days" }
                AccountExpires = $accountExpiration.ToString("yyyy-MM-dd")
            })
        }
        else {
            Write-Log "  WHATIF: Would create '$sam' in '$targetOU'." "INFO"
            $script:Stats.Created++
            continue
        }
    }
    catch {
        Write-Log "  FAILED: Could not create '$sam': $_" "ERROR"
        $script:Stats.Failed++
        continue
    }

    # -- Group membership (determines which password policy applies) -----------
    if ($isAdmin) {
        try {
            Add-ADGroupMember -Identity $AdminGroup -Members $sam -ErrorAction Stop
            Write-Log "  -> Added to admin group '$AdminGroup' (60-day password rotation)." "SUCCESS"
            $script:Stats.Admins++
        }
        catch {
            Write-Log "  WARNING: Could not add '$sam' to '$AdminGroup': $_" "WARN"
        }
    }
    else {
        try {
            Add-ADGroupMember -Identity $standardUsersGroup -Members $sam -ErrorAction Stop
            Write-Log "  -> Added to group '$standardUsersGroup' (90-day password rotation)." "INFO"
        }
        catch {
            Write-Log "  WARNING: Could not add '$sam' to '$standardUsersGroup': $_" "WARN"
        }
    }
}

# ---------------------------------------------
# REGION: Export Per-User Credentials Files
# ---------------------------------------------

if ($script:LoginRecords.Count -gt 0) {
    Write-Log "Writing per-user credential files to '$LoginsOutputDir'..." "INFO"

    # Ensure the output directory exists (may have been removed since pre-flight).
    if (-not (Test-Path -Path $LoginsOutputDir -PathType Container)) {
        New-Item -Path $LoginsOutputDir -ItemType Directory -Force | Out-Null
    }

    $separator = "=" * 56
    $thinSep   = "-" * 40
    $filesWritten = 0

    # Group records by DisplayName so that a person with both a User and
    # an Admin account gets a single file containing both sets of credentials.
    $grouped = $script:LoginRecords | Group-Object -Property DisplayName

    foreach ($group in $grouped) {
        # Use the first record's username for the file name.
        $primaryUsername = $group.Group[0].Username
        $fileName  = "${primaryUsername}_login.txt"
        $filePath  = Join-Path $LoginsOutputDir $fileName

        try {
            $lines = [System.Collections.ArrayList]::new()

            [void]$lines.Add($separator)
            [void]$lines.Add("  CONFIDENTIAL -- LOGIN CREDENTIALS")
            [void]$lines.Add("  For        : $($group.Name)")
            [void]$lines.Add("  Generated  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
            [void]$lines.Add($separator)
            [void]$lines.Add("  WARNING: This file contains plaintext passwords.")
            [void]$lines.Add("  Store securely, then DELETE after first use.")
            [void]$lines.Add($separator)
            [void]$lines.Add("")

            foreach ($record in $group.Group) {
                [void]$lines.Add("  Account Type     : $($record.Role)")
                [void]$lines.Add("  Username         : $($record.Username)")
                [void]$lines.Add("  Password         : $($record.Password)")
                [void]$lines.Add("  Must Change      : $($record.MustChange)")
                [void]$lines.Add("  Pwd Rotation     : $($record.PwdRotation)")
                [void]$lines.Add("  Account Expires  : $($record.AccountExpires)")
                [void]$lines.Add("  $thinSep")
            }

            Set-Content -Path $filePath -Value ($lines -join "`r`n") -Encoding UTF8 -ErrorAction Stop
            Write-Log "  File created: $fileName ($($group.Group.Count) account(s))" "SUCCESS"
            $filesWritten++
        }
        catch {
            Write-Log "  FAILED to write '$fileName': $_" "ERROR"
        }
    }

    Write-Log "$filesWritten credential file(s) written to '$LoginsOutputDir'." "SUCCESS"
    Write-Log ">> SECURITY: Distribute these files securely, then DELETE the entire directory. <<" "WARN"
}
else {
    Write-Log "No new accounts created -- no credential files generated." "WARN"
}

# Securely clear passwords from memory.
foreach ($record in $script:LoginRecords) {
    $record.Password = $null
}
$script:LoginRecords.Clear()

# ---------------------------------------------
# REGION: Summary Report
# ---------------------------------------------

Write-Log ("-" * 60) "INFO"
Write-Log "===== Provisioning Complete =====" "INFO"
Write-Log "  Accounts created  : $($script:Stats.Created)" "INFO"
Write-Log "  Duplicates skipped: $($script:Stats.Skipped)" $(if ($script:Stats.Skipped -gt 0) { "WARN" } else { "INFO" })
Write-Log "  Failures          : $($script:Stats.Failed)" $(if ($script:Stats.Failed -gt 0) { "ERROR" } else { "INFO" })
Write-Log "  OUs created       : $($script:Stats.OUCreated)" "INFO"
Write-Log "  Admin memberships : $($script:Stats.Admins)" "INFO"
Write-Log "  Credentials dir   : $LoginsOutputDir" "INFO"
Write-Log "  Log file          : $LogPath" "INFO"
Write-Log "===== End =====" "INFO"
