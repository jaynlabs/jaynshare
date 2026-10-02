[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidatePattern('^jsi1_')]
    [string]$Invite,

    [ValidatePattern('^[0-9A-Za-z][0-9A-Za-z.+-]*$')]
    [string]$Version,

    [ValidatePattern('^https://')]
    [string]$ReleaseOrigin = 'https://github.com/jaynlabs/jaynshare/releases/download'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'install.ps1 supports Windows only'
}
if ($env:PROCESSOR_ARCHITECTURE -notin @('AMD64', 'x86_64')) {
    throw "unsupported Windows architecture: $env:PROCESSOR_ARCHITECTURE"
}

$origin = $ReleaseOrigin.TrimEnd('/')
$uri = [Uri]$origin
if (-not $uri.IsAbsoluteUri -or $uri.Scheme -ne 'https' -or -not $uri.Host -or $uri.UserInfo -or $uri.Query -or $uri.Fragment) {
    throw '--ReleaseOrigin must be an HTTPS origin with a plain host'
}

if (-not $Version) {
    $latest = if ($origin.EndsWith('/download')) {
        $origin.Substring(0, $origin.Length - '/download'.Length) + '/latest'
    } else {
        "$origin/latest"
    }
    $response = Invoke-WebRequest -Uri $latest -Method Head -UseBasicParsing
    $responseUri = $response.BaseResponse.PSObject.Properties['ResponseUri']
    $effective = if ($null -ne $responseUri) {
        $response.BaseResponse.ResponseUri.AbsoluteUri
    } else {
        $response.BaseResponse.RequestMessage.RequestUri.AbsoluteUri
    }
    $tag = ([Uri]$effective).Segments[-1].TrimEnd('/')
    if (-not $tag.StartsWith('v')) { throw 'the latest release URL names no version' }
    $Version = $tag.Substring(1)
}
if ($Version -notmatch '^[0-9A-Za-z][0-9A-Za-z.+-]*$') {
    throw "invalid release version: $Version"
}

$target = 'x86_64-pc-windows-msvc'
$archive = "jaynshare-$Version-$target.zip"
$base = "$origin/v$Version"
$work = Join-Path ([IO.Path]::GetTempPath()) ("jaynshare-install-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null

try {
    $sums = Join-Path $work 'SHA256SUMS'
    $archivePath = Join-Path $work $archive
    Invoke-WebRequest -Uri "$base/SHA256SUMS" -OutFile $sums -UseBasicParsing
    Invoke-WebRequest -Uri "$base/$archive" -OutFile $archivePath -UseBasicParsing

    $digests = Get-Content $sums | ForEach-Object {
        $parts = $_ -split '  ', 2
        if ($parts.Count -eq 2 -and $parts[1] -eq $archive) { $parts[0] }
    }
    if (@($digests).Count -ne 1) { throw "SHA256SUMS does not name $archive exactly once" }
    $actual = (Get-FileHash -Algorithm SHA256 $archivePath).Hash.ToLowerInvariant()
    if ($actual -ne $digests[0]) { throw "$archive failed its SHA-256 check" }

    Expand-Archive -Path $archivePath -DestinationPath $work
    $binary = Join-Path $work "jaynshare-$Version-$target/jaynshare.exe"
    if (-not (Test-Path -PathType Leaf $binary)) { throw "$archive contains no jaynshare.exe" }
    & $binary join $Invite
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
