# AD User Provisioning v3.0 -- Quick Start Guide

## Files Included

| File | Purpose |
|------|---------|
| `New-ADUserProvisioning.ps1` | Main provisioning script |
| `AD_Users_Sample.csv` | Sample CSV -- copy and edit with real data |
| `USER_logins.txt` | Generated at runtime -- contains initial credentials |

---

## What Changed in v3.0

| Feature | Details |
|---------|---------|
| Auto OU creation | Missing OUs are created automatically (full tree) |
| Admin OU override | All Admin-role users go to `OU=Administrateur` regardless of CSV |
| Password generation | 12-char for users, 18-char for admins (uppercase + symbol + digit) |
| Credentials file | `USER_logins.txt` created with all initial passwords |
| Password rotation | Fine-Grained Password Policies: 12 months (users), 6 months (admins) |
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
    -LoginsOutputPath "C:\Secure\USER_logins.txt"
```

---

## What the Script Does (Step by Step)

```
1. Import & validate   -- Checks AD module, CSV structure, domain DN
2. Create infra        -- Ensures "Administrateur" OU, admin group,
                          standard users group all exist
3. Password policies   -- Creates two Fine-Grained Password Policies:
                            PSO-StandardUsers-365Days  (12 months, min 12 chars)
                            PSO-Admins-182Days         (6 months,  min 18 chars)
4. Per-user loop:
     a. Duplicate check (skip if exists)
     b. Auto-create OU tree if missing
     c. Generate secure random password (12 or 18 chars)
     d. Create AD user (enabled, must change password at first logon)
     e. Add to role-appropriate group (triggers password policy)
5. Export              -- Writes USER_logins.txt with all credentials
6. Cleanup             -- Clears passwords from memory, prints summary
```

---

## Password Policy Details

The script creates two Password Settings Objects (PSOs):

| Policy Name | Applies To | Max Age | Min Length | Precedence |
|-------------|-----------|---------|------------|------------|
| PSO-StandardUsers-365Days | Standard Users group | 365 days | 12 chars | 20 |
| PSO-Admins-182Days | IT Admins group | 182 days | 18 chars | 10 |

Both policies also enforce:
- Complexity enabled (uppercase, lowercase, digit, symbol)
- 12 passwords remembered (history)
- Lockout after 5 failed attempts (30 min)
- Minimum password age of 1 day (prevents rapid cycling)

---

## Security Reminders

- `USER_logins.txt` contains **plaintext passwords** -- distribute it through
  a secure channel (encrypted email, sealed envelope), then **delete the file**.
- Restrict NTFS ACLs on the output directory to administrators only.
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
- Check both the log file and USER_logins.txt after each run.
