# AD User Provisioning — Quick Start Guide

## Files Included

| File | Purpose |
|------|---------|
| `New-ADUserProvisioning.ps1` | Main provisioning script |
| `AD_Users_Sample.csv` | Sample CSV — copy and edit with real data |

---

## CSV Format

The CSV must include **all** of these columns (order doesn't matter):

```
FirstName, LastName, Username, Department, Title, Role, OU, EmailDomain
```

- **Role** — set to `User` or `Admin`. Admin-role accounts are automatically added to the security group.
- **OU** — full distinguished-name path using semicolons as separators:
  `OU=Engineering;OU=Users;DC=contoso;DC=com`
- **EmailDomain** — used to build the UPN and email address (`Username@EmailDomain`).

---

## Prerequisites

1. **Domain-joined machine** running Windows Server or a workstation with RSAT installed.
2. **ActiveDirectory PowerShell module** — comes with RSAT or the AD DS server role.
3. **Permissions** — the executing account needs delegated rights to:
   - Create user objects in every OU referenced in the CSV.
   - Modify membership of the target admin security group.
4. **Admin security group** — the group specified by `-AdminGroup` (default `IT Admins`) must already exist in AD.
5. **Target OUs** — every OU path in the CSV must already exist. The script validates each one and skips the row if missing.

---

## Running the Script

### 1. Dry-Run First (WhatIf Mode)

Always start with a simulation. Nothing is created; the script only logs what *would* happen:

```powershell
.\New-ADUserProvisioning.ps1 -CsvPath ".\AD_Users_Sample.csv" -WhatIf
```

### 2. Interactive Run (Prompted for Password)

You'll be prompted to type the default password securely (nothing echoes):

```powershell
.\New-ADUserProvisioning.ps1 -CsvPath ".\AD_Users_Sample.csv"
```

### 3. Non-Interactive / Automated Run

Supply the password in a file (restrict NTFS ACLs on this file to admins only):

```powershell
.\New-ADUserProvisioning.ps1 -CsvPath ".\AD_Users.csv" `
    -DefaultPasswordPath "C:\Secure\default_pw.txt"
```

### 4. Custom Admin Group

```powershell
.\New-ADUserProvisioning.ps1 -CsvPath ".\AD_Users.csv" `
    -AdminGroup "Domain Admins"
```

### 5. Custom Log Location

```powershell
.\New-ADUserProvisioning.ps1 -CsvPath ".\AD_Users.csv" `
    -LogPath "C:\Logs\provisioning.log"
```

---

## What the Script Does (Step by Step)

1. Checks that the `ActiveDirectory` module is available and imports it.
2. Validates the CSV file exists and contains all required columns.
3. Obtains the default password — either from a file or via secure prompt.
4. Verifies the admin security group exists in AD.
5. For **each row** in the CSV:
   - Checks if `SamAccountName` already exists → skips duplicates.
   - Validates the target OU exists → skips if missing.
   - Creates the user with all standard attributes.
   - Enables the account with **"change password at next logon"** enforced.
   - If role is `Admin`, adds the user to the admin security group.
6. Prints a summary (created / skipped / failed / admin memberships).
7. Writes everything to a timestamped log file.

---

## Test Environment Tips

- **Use a lab domain or isolated OU** — create a test OU like `OU=ProvisioningTest;DC=contoso;DC=com` and point all CSV rows there.
- **Always run `-WhatIf` first** to verify behaviour before committing changes.
- **Set execution policy** if needed: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned`
- **Clean up** test accounts afterwards: `Get-ADUser -SearchBase "OU=ProvisioningTest,DC=contoso,DC=com" -Filter * | Remove-ADUser -Confirm:$false`
- **Check the log file** — every action (success, skip, failure) is recorded with timestamps.

---

## Security Notes

- Passwords are never stored in plain text inside the script.
- The `-DefaultPasswordPath` option is intended for locked-down files with restrictive ACLs.
- All new accounts are forced to change their password at first logon.
- Admin accounts receive a descriptive tag so they're identifiable during audits.
