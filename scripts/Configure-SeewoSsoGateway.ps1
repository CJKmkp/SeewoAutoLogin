#requires -RunAsAdministrator
[CmdletBinding()]
param(
    # Optional DOMAIN\User or COMPUTER\User. Defaults to the identity running this elevated script.
    [string]$UserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
)

$ErrorActionPreference = 'Stop'
$hostName = 'local.id.seewo.com'
$loopback = '127.0.0.1'
$marker = '# SeewoAutoLogin'
$hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$backupPath = "$hostsPath.seewoautologin.bak"
$prefixes = @(
    'http://localhost:24300/',
    'http://127.0.0.1:24300/',
    'http://local.id.seewo.com:24300/'
)

function Invoke-Netsh([string[]]$Arguments) {
    $output = & netsh.exe @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ("netsh {0} failed: {1}" -f ($Arguments -join ' '), ($output -join ' '))
    }
    return ($output -join "`n")
}

Write-Host "Configuring Seewo SSO gateway for Windows user: $UserName" -ForegroundColor Cyan

# Do not remove or overwrite existing reservations: they may belong to another service.
foreach ($prefix in $prefixes) {
    $shown = & netsh.exe http show urlacl "url=$prefix" 2>&1
    $showExitCode = $LASTEXITCODE
    if ($showExitCode -eq 0 -and (($shown -join "`n") -match [regex]::Escape($UserName))) {
        Write-Host "URL ACL already includes this user: $prefix"
        continue
    }
    if ($showExitCode -eq 0) {
        throw ("URL prefix already has a reservation that does not visibly include '{0}': {1}{2}{3}{4}" -f $UserName, $prefix, [Environment]::NewLine, ($shown -join [Environment]::NewLine), ([Environment]::NewLine + 'Inspect it manually; this script will not replace another reservation.'))
    }
    $null = Invoke-Netsh @('http', 'add', 'urlacl', "url=$prefix", "user=$UserName", 'listen=yes', 'delegate=no')
    Write-Host "Added URL ACL: $prefix"
}

# Inspect hosts without changing any existing entry for this name.
$bytes = [System.IO.File]::ReadAllBytes($hostsPath)
$encoding = [System.Text.Encoding]::ASCII
$offset = 0
if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
    $encoding = [System.Text.Encoding]::UTF8; $offset = 3
} elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
    $encoding = [System.Text.Encoding]::Unicode; $offset = 2
} elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
    $encoding = [System.Text.Encoding]::BigEndianUnicode; $offset = 2
} else {
    try {
        $utf8Strict = New-Object System.Text.UTF8Encoding($false, $true)
        $null = $utf8Strict.GetString($bytes)
        $encoding = New-Object System.Text.UTF8Encoding($false)
    } catch { $encoding = [System.Text.Encoding]::ASCII }
}
$text = $encoding.GetString($bytes, $offset, $bytes.Length - $offset)
$active = $false
$conflict = $false
foreach ($line in ($text -split "`r?`n")) {
    $trimmed = $line.Trim()
    if (-not $trimmed -or $trimmed.StartsWith('#')) { continue }
    $effective = ($trimmed -split '#', 2)[0].Trim()
    $tokens = @($effective -split '\s+' | Where-Object { $_ })
    if ($tokens.Count -lt 2 -or $tokens[1..($tokens.Count - 1)] -notcontains $hostName) { continue }
    if ($tokens[0] -eq $loopback) { $active = $true } else { $conflict = $true }
}
if ($conflict -and -not $active) {
    throw "hosts already contains '$hostName' pointing to a non-loopback IP. No hosts changes were made; inspect $hostsPath manually."
}
if (-not $active) {
    if (-not (Test-Path -LiteralPath $backupPath)) {
        Copy-Item -LiteralPath $hostsPath -Destination $backupPath
        Write-Host "Backed up hosts to: $backupPath"
    }
    $line = "`r`n$loopback $hostName $marker`r`n"
    $appendBytes = [System.Text.Encoding]::ASCII.GetBytes($line)
    $stream = [System.IO.File]::Open($hostsPath, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
    try { $stream.Write($appendBytes, 0, $appendBytes.Length) } finally { $stream.Dispose() }
    Write-Host "Added hosts mapping: $hostName -> $loopback"
} else {
    Write-Host "hosts mapping already points to $loopback; leaving existing hosts content unchanged."
}

Write-Host ''
Write-Host 'Configuration completed. Close this elevated shell and run ICC-CE normally.' -ForegroundColor Green
