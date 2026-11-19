# Installs Roro for Windows, then offers to protect the MCP servers your AI
# tools already use.
#
#   irm https://www.roro.im/install.ps1 | iex
#
# It downloads the latest release from GitHub, checks its SHA-256 against the
# release's checksums.txt, and puts roro.exe in %LOCALAPPDATA%\Programs\roro.
# Nothing needs administrator rights.
#
# Settings (environment variables):
#   RORO_INSTALL_DIR   where to put roro.exe
#   RORO_VERSION       a release tag such as v0.3.0 (default: the latest)
#   RORO_NO_PROTECT=1  install only; do not run "roro protect"
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$repo = 'timeomy/roro'
$dest = if ($env:RORO_INSTALL_DIR) { $env:RORO_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\roro' }
$arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }

$tag = $env:RORO_VERSION
if (-not $tag) {
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" -Headers @{ 'User-Agent' = 'roro-installer' }
    $tag = $release.tag_name
}
if ($tag -notmatch '^v\d') { throw "roro install: could not work out the latest version (got '$tag')" }

$name = "roro_$($tag.Substring(1))_windows_$arch"
$base = "https://github.com/$repo/releases/download/$tag"
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("roro-install-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Write-Host "Downloading Roro $tag for windows/$arch..."
    $zip = Join-Path $tmp "$name.zip"
    $sums = Join-Path $tmp 'checksums.txt'
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$name.zip" -OutFile $zip
    Invoke-WebRequest -UseBasicParsing -Uri "$base/checksums.txt" -OutFile $sums

    $want = $null
    foreach ($line in Get-Content $sums) {
        $parts = $line -split '\s+'
        if ($parts.Length -ge 2 -and $parts[1] -eq "$name.zip") { $want = $parts[0] }
    }
    if (-not $want) { throw "roro install: no checksum listed for $name.zip" }
    $got = (Get-FileHash -Algorithm SHA256 -Path $zip).Hash.ToLowerInvariant()
    if ($got -ne $want.ToLowerInvariant()) { throw 'roro install: checksum mismatch: the download is damaged or was tampered with' }

    Expand-Archive -Path $zip -DestinationPath $tmp -Force
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    Copy-Item -Path (Join-Path $tmp "$name\roro.exe") -Destination (Join-Path $dest 'roro.exe') -Force
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

$exe = Join-Path $dest 'roro.exe'
Write-Host "Installed $(& $exe version) to $exe"

# Make "roro" available in new terminal windows.
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not (($userPath -split ';') -contains $dest)) {
    [Environment]::SetEnvironmentVariable('Path', (($userPath.TrimEnd(';') + ';' + $dest).TrimStart(';')), 'User')
    Write-Host "Added $dest to your PATH. Open a new terminal window to use the roro command."
}

if ($env:RORO_NO_PROTECT -ne '1') {
    Write-Host ''
    & $exe protect
}
