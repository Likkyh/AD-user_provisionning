# 1. Define the non-ambiguous character set (A-Z, a-z excluding l, I, O)
$chars = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ'

# 2. Generate a random 24-character string from the character set
$passStr = -join ((1..24) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })

# 3. Output the generated password so you can record it securely
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "YOUR NEW RESCUE ADMIN PASSWORD IS:"
Write-Host $passStr -ForegroundColor Green
Write-Host "Please save this securely before closing!"
Write-Host "========================================" -ForegroundColor Cyan

# 4. Convert the plain text password to a SecureString
$SecurePassword = ConvertTo-SecureString $passStr -AsPlainText -Force

# 5. Create the local user account
New-LocalUser -Name "RescueAdmin" -Password $SecurePassword -FullName "Rescue SuperAdmin" -Description "Emergency local administrator account" -PasswordNeverExpires $true

# 6. Add the new user to the local Administrators group
Add-LocalGroupMember -Group "Administrators" -Member "RescueAdmin"

Write-Host "RescueAdmin account successfully created and added to Administrators group." -ForegroundColor Yellow
