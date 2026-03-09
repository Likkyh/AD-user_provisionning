<#
.SYNOPSIS
    Resets the DSRM (Directory Services Restore Mode) administrator password
    on a Domain Controller with a secure, non-ambiguous 24-character password.

.DESCRIPTION
    DSRM is a special boot mode available only on Active Directory Domain
    Controllers. It provides emergency access to the server when Active
    Directory is offline or corrupted. The DSRM account is the local
    .\Administrator that was configured during dcpromo (DC promotion).

    HOW DSRM WORKS
    ==============
    On a Domain Controller, there is no normal local Administrator account
    because AD DS replaces local SAM authentication. However, a hidden local
    Administrator account exists solely for DSRM. You can reach it in two ways:

      1. BOOT INTO DSRM
         - Restart the DC and press F8 (or use bcdedit /set safeboot dsrepair)
         - At the logon screen, authenticate as .\Administrator with the
           DSRM password
         - AD DS is completely offline in this mode -- only the local SAM
           is available
         - Used for: AD database repair, authoritative restore, offline
           ntds.dit maintenance

      2. STOP THE AD DS SERVICE (Server 2008 R2+)
         - Stop the "Active Directory Domain Services" service
         - Log in as .\Administrator with the DSRM password
         - Requires the DsrmAdminLogonBehavior registry value to be set
         - Used for: offline defragmentation, applying patches that require
           AD DS to be stopped

    This script:
      - Verifies it is running on a Domain Controller
      - Generates a 24-character non-ambiguous password
      - Resets the DSRM password via ntdsutil
      - Optionally configures DsrmAdminLogonBehavior for AD DS-stopped logon
      - Writes a printable credential sheet for sealed-envelope storage

    For member servers and workstations, use New-LocalRescueAdmin.ps1 instead.

.PARAMETER EnableStoppedServiceLogon
    If set, configures the registry so the DSRM account can also be used
    when the AD DS service is stopped (not just at boot in DSRM).
    Sets DsrmAdminLogonBehavior = 2 under
    HKLM:\System\CurrentControlSet\Control\Lsa

    Values:
      0 = DSRM account only usable in DSRM boot mode (default)
      1 = DSRM account usable when AD DS is stopped (if local console)
      2 = DSRM account usable when AD DS is stopped (any session)

.PARAMETER OutputDir
    Directory where the credential sheet is written.
    Defaults to "Rescue credentials" in the script's directory.
    Created automatically if it does not exist.

.EXAMPLE
    .\Set-DSRMRescuePassword.ps1
    .\Set-DSRMRescuePassword.ps1 -EnableStoppedServiceLogon
    .\Set-DSRMRescuePassword.ps1 -OutputDir "C:\Secure\Envelopes"

.NOTES
    Author  : Systems Administration Team
    Version : 1.0
    Requires: Domain Controller, elevated PowerShell prompt,
              ntdsutil.exe (present on all DCs).
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [switch]$EnableStoppedServiceLogon,

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

    $mandatory = @(
        (Get-RandomChar $uppercase),
        (Get-RandomChar $lowercase),
        (Get-RandomChar $digits)
    )

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

Write-Status "===== DSRM Rescue Password Setup =====" "INFO"

# 1. Verify elevated privileges.
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Status "This script must be run as Administrator (elevated prompt)." "ERROR"
    exit 1
}
Write-Status "Running with elevated privileges." "OK"

# 2. Verify this machine IS a Domain Controller.
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
if ($osInfo.ProductType -ne 2) {
    Write-Status "This machine is NOT a Domain Controller (ProductType: $($osInfo.ProductType))." "ERROR"
    Write-Status "Use New-LocalRescueAdmin.ps1 for member servers and workstations." "WARN"
    exit 1
}
Write-Status "Machine confirmed as Domain Controller." "OK"

# 3. Verify ntdsutil.exe is available.
$ntdsutil = Get-Command ntdsutil.exe -ErrorAction SilentlyContinue
if (-not $ntdsutil) {
    Write-Status "ntdsutil.exe not found. This should not happen on a DC." "ERROR"
    exit 1
}
Write-Status "ntdsutil.exe found: $($ntdsutil.Source)" "OK"

# ---------------------------------------------
# REGION: Generate Password
# ---------------------------------------------

$plainPassword = New-NonAmbiguousPassword -Length 24
Write-Status "24-character non-ambiguous password generated." "OK"

# ---------------------------------------------
# REGION: Reset DSRM Password via ntdsutil
# ---------------------------------------------

Write-Status "Resetting DSRM password via ntdsutil..." "INFO"

# ntdsutil is interactive. We write commands to a temp file and redirect it
# via cmd.exe so that:
#   - The password never appears in command-line arguments (audit-safe)
#   - Each line is consumed in order without race conditions
#   - It works regardless of OS language (commands are always English)

$tempFile = $null
try {
    # Build the ntdsutil command sequence in a temp file.
    $tempFile = [System.IO.Path]::GetTempFileName()
    $ntdsCommands = @(
        "set dsrm password"
        "reset password on server null"
        $plainPassword
        $plainPassword
        "q"
        "q"
    )
    # Write with ASCII encoding -- ntdsutil does not handle UTF-8 BOM.
    [System.IO.File]::WriteAllLines($tempFile, $ntdsCommands,
        [System.Text.Encoding]::ASCII)

    # Feed the file via cmd input redirection.
    $result = cmd.exe /c "ntdsutil.exe < `"$tempFile`" 2>&1"
    $exitCode = $LASTEXITCODE

    # Display ntdsutil output for diagnostics.
    $outputLines = @($result) | Where-Object { $_.Trim() -ne "" }
    foreach ($line in $outputLines) {
        Write-Status "  ntdsutil> $line" "INFO"
    }

    # Check for success in output (handles English, French, German).
    $fullOutput = ($result | Out-String)
    if ($fullOutput -match "successfully|correctement|erfolgreich|avec succ") {
        Write-Status "DSRM password reset successfully." "OK"
    }
    elseif ($fullOutput -match "echou|failed|error|erreur|fehlgeschlagen") {
        Write-Status "ntdsutil reported a failure. Review the output above." "ERROR"
        Write-Status "Common causes: password complexity not met, or AD DS issue." "WARN"
        exit 1
    }
    elseif ($exitCode -eq 0) {
        Write-Status "ntdsutil completed (exit code 0) -- verify output above." "WARN"
    }
    else {
        Write-Status "ntdsutil exited with code $exitCode." "ERROR"
        exit 1
    }
}
catch {
    Write-Status "FAILED to run ntdsutil: $_" "ERROR"
    exit 1
}
finally {
    # Overwrite the temp file with zeros before deleting (contains password).
    if ($tempFile -and (Test-Path $tempFile)) {
        $size = (Get-Item $tempFile).Length
        [System.IO.File]::WriteAllBytes($tempFile, [byte[]]::new($size))
        Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------
# REGION: Configure DsrmAdminLogonBehavior
# ---------------------------------------------

$regPath  = "HKLM:\System\CurrentControlSet\Control\Lsa"
$regName  = "DsrmAdminLogonBehavior"
$dsrmMode = "Boot into DSRM only (F8 / bcdedit)"

if ($EnableStoppedServiceLogon) {
    Write-Status "Configuring DsrmAdminLogonBehavior = 2 (allow logon when AD DS service is stopped)..." "INFO"
    try {
        Set-ItemProperty -Path $regPath -Name $regName -Value 2 -Type DWord -ErrorAction Stop
        Write-Status "Registry key set. DSRM logon is now allowed when AD DS service is stopped." "OK"
        $dsrmMode = "Boot into DSRM (F8)  OR  stop AD DS service"
    }
    catch {
        Write-Status "FAILED to set registry key: $_" "ERROR"
        Write-Status "You can set it manually: reg add `"$regPath`" /v $regName /t REG_DWORD /d 2 /f" "WARN"
    }
}
else {
    # Report current value if it exists.
    try {
        $currentVal = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop
        $val = $currentVal.$regName
        Write-Status "DsrmAdminLogonBehavior is currently set to $val." "INFO"
        if ($val -eq 2) {
            $dsrmMode = "Boot into DSRM (F8)  OR  stop AD DS service"
        }
        elseif ($val -eq 1) {
            $dsrmMode = "Boot into DSRM (F8)  OR  stop AD DS service (console only)"
        }
    }
    catch {
        Write-Status "DsrmAdminLogonBehavior not set -- DSRM logon only available in boot mode." "INFO"
        Write-Status "To enable logon when AD DS is stopped, re-run with -EnableStoppedServiceLogon." "INFO"
    }
}

# ---------------------------------------------
# REGION: Export Credential Sheet
# ---------------------------------------------

Write-Status "Writing credential sheet..." "INFO"

if (-not (Test-Path -Path $OutputDir -PathType Container)) {
    New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
    Write-Status "Directory created: $OutputDir" "OK"
}

$hostname  = $env:COMPUTERNAME
$domainDN  = ""
try {
    $domainDN = (Get-ADDomain -ErrorAction Stop).DistinguishedName
}
catch {
    $domainDN = "(could not retrieve)"
}

$fileName  = "DSRM_${hostname}_rescue.txt"
$filePath  = Join-Path $OutputDir $fileName
$created   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$separator = "=" * 60
$thinSep   = "-" * 60

# Split password into groups of 4 for readability.
$pwdGrouped = ($plainPassword -split '(.{4})' | Where-Object { $_ }) -join "  "

$sheet = @"
$separator

    DSRM RESCUE PASSWORD -- SEALED ENVELOPE

$separator

    CONFIDENTIAL -- EMERGENCY USE ONLY
    Print this page, place it in a sealed envelope,
    and store it in a secure physical location (safe).

$separator

    Domain Controller :  $hostname
    Domain            :  $domainDN
    DSRM Account      :  .\Administrator
    Password          :  $plainPassword
    Password          :  $pwdGrouped
    (grouped)            (read in groups of 4 for accuracy)

$thinSep

    HOW TO USE -- METHOD 1: DSRM Boot
    1. Restart the Domain Controller
    2. Press F8 during boot (or pre-configure with:
       bcdedit /set safeboot dsrepair)
    3. At the logon screen, enter:
       Username : .\Administrator
       Password : (from this sheet)
    4. After repair, reboot normally:
       bcdedit /deletevalue safeboot

    HOW TO USE -- METHOD 2: Stop AD DS Service
    (Requires DsrmAdminLogonBehavior = 2 in registry)
    1. Log in with a domain admin account
    2. Run: Stop-Service NTDS -Force
    3. Log in as .\Administrator with the DSRM password
    4. After repair: Start-Service NTDS

$thinSep

    Created           :  $created
    Password Expires  :  NEVER
    Account Expires   :  NEVER
    Access Mode       :  $dsrmMode

$thinSep

    AFTER USE:
    1. Re-run Set-DSRMRescuePassword.ps1 to generate a new password.
    2. Investigate why normal domain admin access was unavailable.
    3. Print and seal the new credential sheet.
    4. Destroy the old envelope.
    5. Document the incident per your security policy.

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
    Write-Host "  DSRM PASSWORD: $plainPassword" -ForegroundColor Yellow
    Write-Host "  GROUPED      : $pwdGrouped" -ForegroundColor Yellow
    Write-Host ""
}

# Clear sensitive data from memory.
$plainPassword  = $null
$pwdGrouped     = $null
$sheet          = $null

# ---------------------------------------------
# REGION: Summary
# ---------------------------------------------

Write-Status ("-" * 60) "INFO"
Write-Status "===== DSRM Password Reset Complete =====" "OK"
Write-Status "  Domain Controller : $hostname" "INFO"
Write-Status "  DSRM account      : .\Administrator" "INFO"
Write-Status "  Password expires  : NEVER" "INFO"
Write-Status "  Access mode       : $dsrmMode" "INFO"
Write-Status "  Credential file   : $filePath" "INFO"
Write-Status ("-" * 60) "INFO"
Write-Status ">> Print the credential sheet, seal it, then DELETE the file. <<" "WARN"
