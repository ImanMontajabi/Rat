param([switch]$IncludeGeoIP)
$ErrorActionPreference = 'Stop'
Push-Location (Join-Path $PSScriptRoot '..')
try {
    cargo build --locked --release -p rat-desktop
    if ($LASTEXITCODE -ne 0) { throw 'Rust build failed' }
    New-Item -ItemType Directory -Force -Path 'dist\Rat' | Out-Null
    Copy-Item -LiteralPath 'target\release\rat-desktop.exe' -Destination 'dist\Rat\Rat.exe'
    Copy-Item -LiteralPath 'LICENSE' -Destination 'dist\Rat\LICENSE.txt'
    Copy-Item -LiteralPath 'docs\RUST_REWRITE.md' -Destination 'dist\Rat\README.md'
    if ($IncludeGeoIP) {
        if (!(Test-Path -LiteralPath 'geoip\dbip-city-lite.mmdb')) { throw 'Run scripts/fetch-geoip.ps1 first' }
        New-Item -ItemType Directory -Force -Path 'dist\Rat\geoip' | Out-Null
        Copy-Item -LiteralPath 'geoip\dbip-city-lite.mmdb' -Destination 'dist\Rat\geoip\dbip-city-lite.mmdb'
    }
    Write-Output 'Portable app ready in dist\Rat. Run Rat.exe; use Run as administrator for IP blocking.'
} finally { Pop-Location }
