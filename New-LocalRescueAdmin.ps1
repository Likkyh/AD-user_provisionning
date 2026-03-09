<#
.SYNOPSIS
    Creates a local rescue administrator account with a secure,
    non-ambiguous 24-character password.

.DESCRIPTION
    Provisions a break-glass local administrator account intended for
    emergency access on MEMBER SERVERS and WORKSTATIONS only.
    This script refuses to run on Domain Controllers -- use
    Set-DSRMRescuePassword.ps1 for DCs instead.

    The password uses only non-ambiguous characters (no 0/O, 1/l/I,
    8/B, 5/S, 2/Z etc.) to eliminate transcription errors when reading
    from a sealed envelope under pressure.

    The account is created with:
      - No password expiration
      - No account expiration
      - Membership in the local Administrators group
      - A printable credential sheet for sealed-envelope storage

.PARAMETER Username
    SamAccountName for the rescue account. Defaults to "rescue.admin".

.PARAMETER FullName
    Display name for the account. Defaults to "Rescue Administrator".

.PARAMETER Description
    Account description. Defaults to "Break-glass emergency admin -- sealed envelope".

.PARAMETER OutputDir
    Directory where the credential sheet is written.
    Defaults to "Rescue credentials" in the script's directory.
    Created automatically if it does not exist.

.EXAMPLE
    .\New-LocalRescueAdmin.ps1
    .\New-LocalRescueAdmin.ps1 -Username "emergency.admin" -OutputDir "C:\Secure"

.NOTES
    Author  : Systems Administration Team
    Version : 1.0
    Requires: Local administrator privileges on the target machine.
              Run from an elevated PowerShell prompt.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$Username = "rescue.admin",

    [Parameter(Mandatory = $false)]
    [string]$FullName = "Rescue Administrator",

    [Parameter(Mandatory = $false)]
    [string]$Description = "Break-glass emergency admin -- sealed envelope",

    [Parameter(Mandatory = $false)]
    [string]$OutputDir
)

# ---------------------------------------------
# REGION: Initialisation
# ---------------------------------------------

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $OutputDir) {
    $OutputDir = Join-Path $PSScriptRoot "Rescue credentials"
}

function Write-Status {
    param (
        [string]$Message,
        [ValidateSet("INFO", "OK", "ERROR", "WARN")]
        [string]$Level = "INFO"
    )
    $tag = "[{0}] [{1}]" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level
    switch ($Level) {
        "ERROR" { Write-Host "$tag $Message" -ForegroundColor Red }
        "WARN"  { Write-Host "$tag $Message" -ForegroundColor Yellow }
        "OK"    { Write-Host "$tag $Message" -ForegroundColor Green }
        default { Write-Host "$tag $Message" -ForegroundColor Cyan }
    }
}

function New-NonAmbiguousPassword {
    <#
    .SYNOPSIS
        Generates a cryptographically random password using only characters
        that cannot be confused with one another when handwritten or printed.

    .DESCRIPTION
        Excluded ambiguous characters:
          Uppercase : O (vs 0), I (vs 1/l), B (vs 8), S (vs 5), Z (vs 2), G (vs 6), D (vs 0)
          Lowercase : o (vs 0), l (vs 1/I), b (vs 6), s (vs 5), z (vs 2), g (vs 9), q (vs 9)
          Digits    : 0 (vs O),  1 (vs l/I)

        Remaining safe character sets:
          Uppercase : A C E F H J K L M N P Q R T U V W X Y
          Lowercase : a c d e f h i j k m n p r t u v w x y
          Digits    : 2 3 4 5 6 7 8 9

        The password is guaranteed to contain at least one character from
        each of the three categories.

    .PARAMETER Length
        Desired password length (minimum 8).
    #>
    param (
        [Parameter(Mandatory)]
        [ValidateRange(8, 128)]
        [int]$Length
    )

    $uppercase = "ACEFHJKLMNPQRTUVWXY"
    $lowercase = "acdefhijkmnprtuvwxy"
    $digits    = "23456789"
    $allChars  = $uppercase + $lowercase + $digits

    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()

    function Get-RandomChar([string]$CharSet) {
        $byte = [byte[]]::new(1)
        $rng.GetBytes($byte)
        return $CharSet[$byte[0] % $CharSet.Length]
    }

    # Guarantee at least one from each category.
    $mandatory = @(
        (Get-RandomChar $uppercase),
        (Get-RandomChar $lowercase),
        (Get-RandomChar $digits)
    )

    # Fill the rest.
    $remaining = $Length - $mandatory.Count
    $filler = @()
    for ($i = 0; $i -lt $remaining; $i++) {
        $filler += (Get-RandomChar $allChars)
    }

    # Fisher-Yates shuffle.
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

# ---------------------------------------------
# REGION: Pre-flight Checks
# ---------------------------------------------

Write-Status "===== Local Rescue Administrator Setup =====" "INFO"
Write-Status "Target account: $Username" "INFO"

# 1. Verify we are running elevated.
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Status "This script must be run as Administrator (elevated prompt)." "ERROR"
    exit 1
}
Write-Status "Running with elevated privileges." "OK"

# 2. Refuse to run on a Domain Controller.
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
if ($osInfo.ProductType -eq 2) {
    Write-Status "This machine is a DOMAIN CONTROLLER." "ERROR"
    Write-Status "Use Set-DSRMRescuePassword.ps1 for DCs instead of creating a local account." "ERROR"
    exit 1
}
Write-Status "Machine type: $(if ($osInfo.ProductType -eq 3) { 'Server' } else { 'Workstation' }) -- OK." "INFO"

# 3. Check the account does not already exist.
try {
    $existing = Get-LocalUser -Name $Username -ErrorAction Stop
    Write-Status "Account '$Username' already exists (SID: $($existing.SID)). Aborting to prevent overwrite." "ERROR"
    Write-Status "To recreate, first remove the account: Remove-LocalUser -Name '$Username'" "WARN"
    exit 1
}
catch [Microsoft.PowerShell.Commands.UserNotFoundException] {
    Write-Status "Account '$Username' does not exist -- ready to create." "INFO"
}
catch {
    # On older PS versions the exception type may differ.
    if ($_.Exception.Message -match "not be found|was not found") {
        Write-Status "Account '$Username' does not exist -- ready to create." "INFO"
    }
    else {
        Write-Status "Error checking for existing account: $_" "ERROR"
        exit 1
    }
}

# ---------------------------------------------
# REGION: Generate Password & Create Account
# ---------------------------------------------

$plainPassword  = New-NonAmbiguousPassword -Length 24
$securePassword = ConvertTo-SecureString -String $plainPassword -AsPlainText -Force

Write-Status "24-character non-ambiguous password generated." "OK"

# 4. Create the local user.
try {
    New-LocalUser -Name $Username `
        -FullName $FullName `
        -Description $Description `
        -Password $securePassword `
        -PasswordNeverExpires `
        -AccountNeverExpires `
        -UserMayNotChangePassword `
        -ErrorAction Stop | Out-Null

    Write-Status "Local account '$Username' created." "OK"
}
catch {
    Write-Status "FAILED to create account '$Username': $_" "ERROR"
    exit 1
}

# 5. Add to local Administrators group.
# Use SID S-1-5-32-544 so it works regardless of OS language.
$adminGroupSID = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
$adminGroupObj = Get-LocalGroup | Where-Object { $_.SID -eq $adminGroupSID }
$adminGroupName = $adminGroupObj.Name

try {
    Add-LocalGroupMember -SID "S-1-5-32-544" -Member $Username -ErrorAction Stop
    Write-Status "Account added to local '$adminGroupName' group." "OK"
}
catch {
    Write-Status "FAILED to add '$Username' to '$adminGroupName': $_" "ERROR"
    Write-Status "The account exists but is NOT an administrator. Fix manually." "WARN"
}

# 6. Disable interactive logon denial if a GPO blocks local accounts (informational).
Write-Status "NOTE: If a GPO denies local logon for this account, you must add an exception." "WARN"

# ---------------------------------------------
# REGION: Export Credential Sheet
# ---------------------------------------------

Write-Status "Writing credential sheet..." "INFO"

if (-not (Test-Path -Path $OutputDir -PathType Container)) {
    New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
    Write-Status "Directory created: $OutputDir" "OK"
}

$hostname  = $env:COMPUTERNAME
$fileName  = "${Username}_${hostname}_rescue.txt"
$filePath  = Join-Path $OutputDir $fileName
$created   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$separator = "=" * 60
$thinSep   = "-" * 60

# Split the password into groups of 4 for easy reading.
$pwdGrouped = ($plainPassword -split '(.{4})' | Where-Object { $_ }) -join "  "

$sheet = @"
$separator

    RESCUE ADMINISTRATOR -- SEALED ENVELOPE

$separator

    CONFIDENTIAL -- EMERGENCY USE ONLY
    Print this page, place it in a sealed envelope,
    and store it in a secure physical location.

$separator

    Computer     :  $hostname
    Username     :  .\$Username
    Full Name    :  $FullName
    Password     :  $plainPassword
    Password     :  $pwdGrouped
    (grouped)       (read in groups of 4 for accuracy)

$thinSep

    Created      :  $created
    Expires      :  NEVER
    Pwd Expires  :  NEVER
    Pwd Change   :  Disabled (user may not change)
    Admin Group  :  $adminGroupName

$thinSep

    AFTER USE:
    1. Change the password immediately.
    2. Investigate why normal admin access was unavailable.
    3. Generate a new sealed envelope with a fresh password.
    4. Document the incident per your security policy.

$separator
"@

try {
    Set-Content -Path $filePath -Value $sheet -Encoding UTF8 -ErrorAction Stop
    Write-Status "Credential sheet written: $filePath" "OK"
}
catch {
    Write-Status "FAILED to write credential sheet: $_" "ERROR"
    Write-Status "Printing password to console as fallback." "WARN"
    Write-Host ""
    Write-Host "  PASSWORD: $plainPassword" -ForegroundColor Yellow
    Write-Host "  GROUPED : $pwdGrouped" -ForegroundColor Yellow
    Write-Host ""
}

# Clear sensitive data from memory.
$plainPassword  = $null
$pwdGrouped     = $null
$sheet          = $null
$securePassword.Dispose()

# ---------------------------------------------
# REGION: Summary
# ---------------------------------------------

Write-Status ("-" * 60) "INFO"
Write-Status "===== Rescue Account Setup Complete =====" "OK"
Write-Status "  Account         : .\$Username" "INFO"
Write-Status "  Admin group     : $adminGroupName" "INFO"
Write-Status "  Password expires: NEVER" "INFO"
Write-Status "  Account expires : NEVER" "INFO"
Write-Status "  Credential file : $filePath" "INFO"
Write-Status ("-" * 60) "INFO"
Write-Status ">> Print the credential sheet, seal it, then DELETE the file. <<" "WARN"
