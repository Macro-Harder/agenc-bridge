# AgenC Bridge — set up the encrypted secret on a Windows desktop.
# Usage (PowerShell): .\setup-secret-windows.ps1
# Asks for the bridge secret and the passphrase (both in BRIDGE-PASSPHRASE.txt),
# writes $env:USERPROFILE\.config\agenc-bridge\secret.enc, and deletes any
# plaintext secret. Needs openssl (ships with Git for Windows; otherwise
# install it or use the Linux script under WSL).
# If you want the worker to run unattended, answer yes to storing the
# passphrase in a file; otherwise you will be asked for it each time.
$cfg = "$env:USERPROFILE\.config\agenc-bridge"
New-Item -ItemType Directory -Force $cfg | Out-Null
$secret = Read-Host "Bridge secret" -AsSecureString
$pass = Read-Host "Passphrase" -AsSecureString
$secretPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
  [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret))
$passPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
  [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass))
$secretPlain | openssl enc -aes-256-cbc -pbkdf2 -salt -pass "pass:$passPlain" -out "$cfg\secret.enc"
Remove-Item "$cfg\secret" -ErrorAction SilentlyContinue
$store = Read-Host "Store the passphrase in $cfg\passphrase so the worker can run unattended? [y/N]"
if ($store -eq "y" -or $store -eq "Y") {
  $passPlain | Out-File "$cfg\passphrase" -NoNewline -Encoding ascii
  Write-Host "Passphrase stored."
}
Write-Host "Done. Secret is encrypted at $cfg\secret.enc."
