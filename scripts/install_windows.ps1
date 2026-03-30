Param(
    [switch]$SkipNmap,
    [switch]$SkipPythonDeps,
    [switch]$SkipUpdate
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

Write-Host "[N-VIEW] Windows installer starting..." -ForegroundColor Cyan

if (-not (Get-Command python -ErrorAction SilentlyContinue) -and -not (Get-Command py -ErrorAction SilentlyContinue)) {
    Write-Host "Python is not installed. Install Python 3.11+ and rerun this script." -ForegroundColor Red
    exit 1
}

if (-not $SkipNmap) {
    if (-not (Get-Command nmap -ErrorAction SilentlyContinue) -and -not (Test-Path "C:\Program Files (x86)\Nmap\nmap.exe") -and -not (Test-Path "C:\Program Files\Nmap\nmap.exe")) {
        Write-Host "Nmap not found. Attempting installation..." -ForegroundColor Yellow
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            winget install -e --id Insecure.Nmap --accept-package-agreements --accept-source-agreements
        } elseif (Get-Command choco -ErrorAction SilentlyContinue) {
            choco install nmap -y
        } elseif (Get-Command scoop -ErrorAction SilentlyContinue) {
            scoop install nmap
        } else {
            Write-Host "Auto-install unavailable. Install Nmap manually: https://nmap.org/download.html" -ForegroundColor Yellow
        }
    }
}

if (-not $SkipPythonDeps) {
    if (Get-Command py -ErrorAction SilentlyContinue) {
        py -m pip install --upgrade pip
        py -m pip install -r requirements.txt
        py -m pip install -e .
    } else {
        python -m pip install --upgrade pip
        python -m pip install -r requirements.txt
        python -m pip install -e .
    }
}

if (Get-Command py -ErrorAction SilentlyContinue) {
    py -m nview.cli bootstrap
    if (-not $SkipUpdate) { py -m nview.cli update }
} else {
    python -m nview.cli bootstrap
    if (-not $SkipUpdate) { python -m nview.cli update }
}

$bin = "$HOME\AppData\Local\nview\bin"
$pyScripts = ""
if (Get-Command py -ErrorAction SilentlyContinue) {
    $pyScripts = py -c "import site; print(site.USER_BASE + '\\Scripts')"
} else {
    $pyScripts = python -c "import site; print(site.USER_BASE + '\\Scripts')"
}
$userPath = [Environment]::GetEnvironmentVariable('Path','User')
foreach ($item in @($bin, $pyScripts)) {
    if (Test-Path $item) {
        if (-not ($userPath -split ';' | Where-Object { $_ -eq $item })) {
            $userPath = (($userPath.TrimEnd(';') + ';' + $item).Trim(';'))
            [Environment]::SetEnvironmentVariable('Path', $userPath, 'User')
        }
    }
}

Write-Host "[N-VIEW] Verifying command wiring..." -ForegroundColor Cyan
$env:Path = [Environment]::GetEnvironmentVariable('Path','User') + ';' + [Environment]::GetEnvironmentVariable('Path','Machine')
Get-Command nview -ErrorAction SilentlyContinue | Out-Null
Get-Command n-view -ErrorAction SilentlyContinue | Out-Null

Write-Host "[N-VIEW] Installation complete." -ForegroundColor Green
Write-Host "Open a new terminal and run: nview" -ForegroundColor Green
Write-Host "Or run: n-view" -ForegroundColor Green
