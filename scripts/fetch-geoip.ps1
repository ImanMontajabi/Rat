param([string]$Month = (Get-Date -Format 'yyyy-MM'))
$ErrorActionPreference = 'Stop'
$destination = Join-Path $PSScriptRoot '..\geoip'
New-Item -ItemType Directory -Force -Path $destination | Out-Null
$archive = Join-Path $destination 'dbip-city-lite.mmdb.gz'
$database = Join-Path $destination 'dbip-city-lite.mmdb'
if (Test-Path -LiteralPath $database) { Write-Output "Already present: $database"; exit 0 }
if ($Month -notmatch '^\d{4}-\d{2}$') { throw 'Month must be yyyy-MM' }
Write-Output "Downloading DB-IP City Lite $Month (CC BY 4.0)..."
Invoke-WebRequest "https://download.db-ip.com/free/dbip-city-lite-$Month.mmdb.gz" -OutFile $archive
$inputStream = [IO.File]::OpenRead($archive)
$gzipStream = [IO.Compression.GZipStream]::new($inputStream, [IO.Compression.CompressionMode]::Decompress)
$outputStream = [IO.File]::Create("$database.partial")
try { $gzipStream.CopyTo($outputStream) } finally { $outputStream.Dispose(); $gzipStream.Dispose(); $inputStream.Dispose() }
Move-Item -LiteralPath "$database.partial" -Destination $database
Remove-Item -LiteralPath $archive
Write-Output "Ready: $database"
Write-Output 'IP geolocation by DB-IP: https://db-ip.com (CC BY 4.0)'
