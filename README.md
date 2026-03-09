# AD User Provisioning v3.0 -- Quick Start Guide

## Files Included

| File | Purpose |
|------|---------|
| `New-ADUserProvisioning.ps1` | Main AD provisioning script |
| `New-LocalRescueAdmin.ps1` | Local rescue admin for member servers and workstations |
| `Set-DSRMRescuePassword.ps1` | DSRM rescue password for Domain Controllers |
| `AD_Users_Sample.csv` | Sample CSV -- copy and edit with real data |
| `Created logins/` | Generated at runtime -- one `[USERNAME]_login.txt` per person |
| `Rescue credentials/` | Generated at runtime -- sealed-envelope credential sheets |

---

## What Changed in v3.0

| Feature | Details |
|---------|---------|
| Auto OU creation | Missing OUs are created automatically (full tree) |
| Admin OU override | All Admin-role users go to `OU=Administrateur` regardless of CSV |
| Password generation | 12-char for users, 18-char for admins (uppercase + symbol + digit) |
| Credentials files | One `[USERNAME]_login.txt` per person in `Created logins/` directory |
| Password rotation | Fine-Grained Password Policies: 90 days (users), 60 days (admins) |
| Account expiration | All accounts expire 1 year after creation |
| First-logon change | All accounts forced to change password at first connection |

---

## CSV Format

Required columns (order does not matter):

```
FirstName, LastName, Username, Department, Title, Role, OU, EmailDomain
```

- **Role** -- `User` or `Admin`.
  - `Admin` accounts ignore the OU column and are placed in `OU=Administrateur`.
  - `User` accounts are placed in the OU specified in the CSV.
- **OU** -- full distinguished-name path using semicolons:
  `OU=Engineering;OU=Users;DC=contoso;DC=com`
  Missing OUs are created automatically.
- **EmailDomain** -- used for UPN and email (`Username@EmailDomain`).

---

## Prerequisites

1. **Domain-joined machine** with RSAT or AD DS role tools installed.
2. **ActiveDirectory PowerShell module** available.
3. **Domain functional level 2008+** (required for Fine-Grained Password Policies).
4. **Permissions** -- the running account needs rights to:
   - Create OUs and user objects.
   - Create and link Password Settings Objects (PSOs).
   - Create and modify security groups.

---

## Running the Script

### 1. Dry-Run (WhatIf)

```powershell
.\New-ADUserProvisioning.ps1 -CsvPath ".\AD_Users_Sample.csv" -WhatIf
```

### 2. Standard Run

```powershell
.\New-ADUserProvisioning.ps1 -CsvPath ".\AD_Users_Sample.csv"
```

### 3. Custom Admin Group

```powershell
.\New-ADUserProvisioning.ps1 -CsvPath ".\AD_Users.csv" -AdminGroup "Domain Admins"
```

### 4. Custom Output Paths

```powershell
.\New-ADUserProvisioning.ps1 -CsvPath ".\AD_Users.csv" `
    -LogPath "C:\Logs\provisioning.log" `
    -LoginsOutputDir "C:\Secure\Created logins"
```

---

## What the Script Does (Step by Step)

```
1. Import & validate   -- Checks AD module, CSV structure, domain DN
2. Create infra        -- Ensures "Administrateur" OU, admin group,
                          standard users group all exist
3. Password policies   -- Creates two Fine-Grained Password Policies:
                            PSO-StandardUsers-90Days   (90 days,  min 12 chars)
                            PSO-Admins-60Days          (60 days,  min 18 chars)
4. Per-user loop:
     a. Duplicate check (skip if exists)
     b. Auto-create OU tree if missing
     c. Generate secure random password (12 or 18 chars)
     d. Create AD user (enabled, must change password, expires in 1 year)
     e. Add to role-appropriate group (triggers password policy)
5. Export              -- Writes one [USERNAME]_login.txt per person
                          in the "Created logins" directory
6. Cleanup             -- Clears passwords from memory, prints summary
```

---

## Password Policy Details

The script creates two Password Settings Objects (PSOs):

| Policy Name | Applies To | Max Age | Min Length | Precedence |
|-------------|-----------|---------|------------|------------|
| PSO-StandardUsers-90Days | Standard Users group | 90 days | 12 chars | 20 |
| PSO-Admins-60Days | IT Admins group | 60 days | 18 chars | 10 |

Both policies also enforce:
- Complexity enabled (uppercase, lowercase, digit, symbol)
- 12 passwords remembered (history)
- Lockout after 5 failed attempts (30 min)
- Minimum password age of 1 day (prevents rapid cycling)

Additionally, all accounts (both users and admins) have their
`AccountExpirationDate` set to **1 year** from the creation date.
After that date the account is automatically disabled by AD.

---

## Credentials File Structure

The script creates a `Created logins/` directory containing one file per
person. Each file is named after their primary username:

```
Created logins/
    ajohnson_login.txt
    bmartinez_login.txt
    dchen_login.txt
    ...
```

If a person has both a User and an Admin account in the CSV (same full
name), both sets of credentials appear in a single file. This makes it
easy to hand each person one file containing everything they need.

---

## Security Reminders

- The `Created logins/` directory contains **plaintext passwords** -- distribute
  each file individually to the corresponding person via a secure channel
  (encrypted email, sealed envelope), then **delete the entire directory**.
- Restrict NTFS ACLs on the `Created logins/` directory to administrators only.
- All accounts are forced to change their password at first logon.
- Passwords are cleared from script memory after the file is written.
- Run the script from a privileged admin workstation, not a shared machine.

---

## Test Environment Tips

- Create a dedicated test OU and point all CSV rows there.
- Always run `-WhatIf` first.
- Set execution policy if needed:
  `Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned`
- Clean up test accounts:
  `Get-ADUser -SearchBase "OU=TestOU,DC=contoso,DC=com" -Filter * | Remove-ADUser -Confirm:$false`
- Check both the log file and the `Created logins/` directory after each run.

---
---

# Emergency / Break-Glass Accounts

Two separate scripts handle rescue access depending on the machine role:

| Machine type | Script | Account |
|-------------|--------|---------|
| Domain Controller | `Set-DSRMRescuePassword.ps1` | `.\Administrator` (DSRM) |
| Member server / Workstation | `New-LocalRescueAdmin.ps1` | `.\rescue.admin` (local) |

Each script detects the machine type and **refuses to run** on the wrong one,
so there is no risk of accidentally creating a local account on a DC or
resetting DSRM on a workstation.

---

## What is DSRM?

DSRM (Directory Services Restore Mode) is a special boot mode that exists
only on Active Directory Domain Controllers. On a DC, the normal local
Administrator account is disabled because all authentication goes through
AD. However, a hidden local `.\Administrator` account still exists in the
local SAM database specifically for DSRM emergencies.

**When do you need it?**

- The Active Directory database (`ntds.dit`) is corrupted
- You need to perform an authoritative restore of AD objects
- AD DS will not start and you cannot log in with any domain account
- You need to perform offline maintenance on the AD database

**Two ways to access DSRM:**

```
METHOD 1: Boot into DSRM
  1. Restart the DC
  2. Press F8 at boot -> select "Directory Services Restore Mode"
     (or pre-configure: bcdedit /set safeboot dsrepair)
  3. Log in as .\Administrator with the DSRM password
  4. AD DS is completely offline -- only local SAM works
  5. After repair, reboot: bcdedit /deletevalue safeboot

METHOD 2: Stop the AD DS service (Server 2008 R2+)
  Requires: DsrmAdminLogonBehavior = 2 in registry
  1. Log in with a domain admin account
  2. Stop-Service NTDS -Force
  3. Now .\Administrator works with the DSRM password
  4. After repair: Start-Service NTDS
```

The DSRM password is set once during DC promotion (`dcpromo`) and is often
forgotten. The `Set-DSRMRescuePassword.ps1` script resets it to a fresh
secure password, writes a printable credential sheet, and optionally
configures the registry for Method 2 access.

---

## Shared Password Design

Both scripts use the same non-ambiguous 24-character password generator.
Characters that can be confused when handwritten or read from a printout
under pressure are excluded:

| Category | Included | Excluded (ambiguous) |
|----------|----------|----------------------|
| Uppercase | A C E F H J K L M N P Q R T U V W X Y | O (vs 0), I (vs 1/l), B (vs 8), S (vs 5), Z (vs 2), G (vs 6), D (vs 0) |
| Lowercase | a c d e f h i j k m n p r t u v w x y | o (vs 0), l (vs 1/I), b (vs 6), s (vs 5), z (vs 2), g (vs 9), q (vs 9) |
| Digits | 2 3 4 5 6 7 8 9 | 0 (vs O), 1 (vs l/I) |

The credential sheet prints the password twice: once as a raw string,
once split into **groups of 4** for easier reading.

---

## Script 1: Set-DSRMRescuePassword.ps1 (Domain Controllers)

### What It Does

1. Verifies the machine is a DC and the prompt is elevated
2. Generates a 24-character non-ambiguous password
3. Resets the DSRM password via `ntdsutil` (stdin redirect -- password
   never appears in command-line arguments or process audit logs)
4. Optionally sets `DsrmAdminLogonBehavior = 2` so DSRM logon also
   works when the AD DS service is stopped (not just at boot)
5. Writes `DSRM_[HOSTNAME]_rescue.txt` in `Rescue credentials/`

### Usage

```powershell
# Basic -- reset DSRM password, boot-mode access only
.\Set-DSRMRescuePassword.ps1

# Also enable DSRM logon when AD DS service is stopped
.\Set-DSRMRescuePassword.ps1 -EnableStoppedServiceLogon

# Custom output directory
.\Set-DSRMRescuePassword.ps1 -OutputDir "C:\Secure\Envelopes"
```

### Account Properties

| Property | Value |
|----------|-------|
| Account | `.\Administrator` (built-in DSRM) |
| Password expires | NEVER |
| Account expires | NEVER |
| Access mode | DSRM boot, or AD DS stopped (if registry configured) |

---

## Script 2: New-LocalRescueAdmin.ps1 (Servers & Workstations)

### What It Does

1. Verifies the machine is NOT a DC and the prompt is elevated
2. Creates a local `rescue.admin` account (customisable name)
3. Generates a 24-character non-ambiguous password
4. Adds the account to local Administrators (via SID, language-independent)
5. Writes `[USERNAME]_[HOSTNAME]_rescue.txt` in `Rescue credentials/`

### Usage

```powershell
# Default settings (account: rescue.admin)
.\New-LocalRescueAdmin.ps1

# Custom account name
.\New-LocalRescueAdmin.ps1 -Username "emergency.admin"

# Custom output location
.\New-LocalRescueAdmin.ps1 -OutputDir "C:\Secure\Envelopes"
```

### Account Properties

| Property | Value |
|----------|-------|
| Account | `.\rescue.admin` (or custom) |
| Password expires | NEVER |
| Account expires | NEVER |
| User may change password | NO |
| Local Administrators group | YES |

---

## Sealed-Envelope Procedure (Both Scripts)

### After Running

1. Print the credential sheet from `Rescue credentials/`.
2. Place the printout in a **sealed envelope**.
3. Sign across the seal (detects tampering).
4. Store in a physical safe or locked cabinet.
5. **Delete the credential file and the directory.**
6. Record the envelope location in your asset register.

### After Emergency Use

1. Reset the password immediately (re-run the script).
2. Investigate why normal admin/domain access was unavailable.
3. Print and seal a new envelope with the fresh password.
4. Destroy the old envelope.
5. Document the incident per your security policy.
