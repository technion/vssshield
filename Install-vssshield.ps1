Set-StrictMode -Version 2

# Check for elevation

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Output "This application must be run as an elevated admin"
    exit
}

$installpath = 'C:\Program Files\vssshield'
If (-not (Test-Path $installpath)) {
    New-Item -Path $installpath -ItemType Directory
}

try {
    Invoke-WebRequest "https://github.com/technion/vssshield/releases/latest/download/vssshield.exe" -OutFile "$($installpath)\vssshield.exe"
} catch {
    Write-Output "Failed to download installer"
    exit
}

$key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\vssadmin.exe'
If (-Not (Test-Path $key))
{
    New-Item $key -Force | Out-Null
}

New-ItemProperty -Path $key -Name "Debugger" -Value "$($installpath)\vssshield.exe" -Force | Out-Null

$key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wmic.exe'
If (-Not (Test-Path $key))
{
    New-Item $key -Force | Out-Null
}

New-ItemProperty -Path $key -Name "Debugger" -Value "$($installpath)\vssshield.exe" -Force | Out-Null

Write-Host -ForegroundColor Cyan "Vssshield has been installed"
