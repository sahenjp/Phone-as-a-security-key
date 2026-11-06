# build-msix.ps1 - build Phone FIDO Key for Windows and pack a signed MSIX.
#
# Pipeline (each step can be skipped while iterating):
#   1. cargo build --release --target x86_64-pc-windows-msvc
#      -> target\x86_64-pc-windows-msvc\release\iphone_fido.lib
#   2. MSBuild PhoneFidoKey.sln (Release|x64)
#      -> windows\build\x64\Release\{PhoneFidoKey.exe, PhoneFidoKeySetup.exe}
#   3. Stage the package layout (exes + Assets + Package.appxmanifest)
#   4. makeappx pack -> windows\dist\PhoneFidoKey.msix
#   5. signtool sign with a self-signed code-signing certificate
#      (created in Cert:\CurrentUser\My on first run) and export the
#      public certificate to windows\dist\PhoneFidoKey.cer - users must
#      trust that .cer before Windows will install the .msix.
#
# The manifest's Publisher MUST equal the certificate subject; the
# default pair is CN=PhoneFidoKey on both sides. If you override
# -CertSubject, also update Package.appxmanifest's Identity Publisher.
#
# Usage:
#   .\build-msix.ps1                 full build + pack + sign
#   .\build-msix.ps1 -SkipRustBuild  reuse the existing iphone_fido.lib
#   .\build-msix.ps1 -SkipCppBuild   reuse the existing .exe files
#   .\build-msix.ps1 -Version 1.0.1.0

#requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',
    [string]$CertSubject = 'CN=PhoneFidoKey',
    [string]$Version,
    [switch]$SkipRustBuild,
    [switch]$SkipCppBuild
)

$ErrorActionPreference = 'Stop'

$winDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $winDir
$distDir  = Join-Path $winDir 'dist'
$layoutDir = Join-Path $winDir 'build\package-layout'
$exeDir   = Join-Path $winDir "build\x64\$Configuration"

New-Item -ItemType Directory -Force -Path $distDir | Out-Null

function Step($text) { Write-Host "`n=== $text ===" -ForegroundColor Cyan }

# ---------------------------------------------------------------- Rust lib
if (-not $SkipRustBuild) {
    Step 'Building the Rust static library (x86_64-pc-windows-msvc)'
    $installed = & rustup target list --installed
    if ($installed -notcontains 'x86_64-pc-windows-msvc') {
        throw "Rust target x86_64-pc-windows-msvc is not installed. Run: rustup target add x86_64-pc-windows-msvc"
    }
    Push-Location $repoRoot
    try {
        & cargo build --release --target x86_64-pc-windows-msvc
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed ($LASTEXITCODE)" }
    } finally {
        Pop-Location
    }
}
$rustLib = Join-Path $repoRoot 'target\x86_64-pc-windows-msvc\release\iphone_fido.lib'
if (-not (Test-Path $rustLib)) {
    throw "Rust static library not found: $rustLib`n(The C ABI crate must produce iphone_fido.lib - see windows/include/phone_fido.h.)"
}

# ---------------------------------------------------------------- C++ build
if (-not $SkipCppBuild) {
    Step 'Building the C++ shim (MSBuild)'
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswhere)) { throw "vswhere.exe not found: $vswhere" }
    $msbuild = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild `
        -find 'MSBuild\**\Bin\MSBuild.exe' | Select-Object -First 1
    if (-not $msbuild) { throw 'MSBuild not found via vswhere.' }
    & $msbuild (Join-Path $winDir 'PhoneFidoKey.sln') `
        /p:Configuration=$Configuration /p:Platform=x64 /m /nologo /v:minimal
    if ($LASTEXITCODE -ne 0) { throw "MSBuild failed ($LASTEXITCODE)" }
}
foreach ($exe in 'PhoneFidoKey.exe', 'PhoneFidoKeySetup.exe') {
    if (-not (Test-Path (Join-Path $exeDir $exe))) {
        throw "Expected build output missing: $(Join-Path $exeDir $exe)"
    }
}

# ---------------------------------------------------------------- Certificate
Step 'Locating or creating the self-signed code-signing certificate'
$cert = Get-ChildItem Cert:\CurrentUser\My |
    Where-Object { $_.Subject -eq $CertSubject } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1
if (-not $cert) {
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $CertSubject `
        -CertStoreLocation Cert:\CurrentUser\My -HashAlgorithm SHA256 `
        -KeyUsage DigitalSignature -FriendlyName 'Phone FIDO Key (self-signed)'
    Write-Host "Created certificate $($cert.Thumbprint)"
} else {
    Write-Host "Using existing certificate $($cert.Thumbprint)"
}
$cerPath = Join-Path $distDir 'PhoneFidoKey.cer'
Export-Certificate -Cert $cert -FilePath $cerPath -Force | Out-Null
Write-Host "Exported public certificate: $cerPath"

# ---------------------------------------------------------------- Layout
Step 'Staging the package layout'
if (Test-Path $layoutDir) { Remove-Item $layoutDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path $layoutDir | Out-Null
Copy-Item (Join-Path $exeDir 'PhoneFidoKey.exe') $layoutDir
Copy-Item (Join-Path $exeDir 'PhoneFidoKeySetup.exe') $layoutDir
Copy-Item (Join-Path $winDir 'Assets') $layoutDir -Recurse
Copy-Item (Join-Path $winDir 'Package.appxmanifest') (Join-Path $layoutDir 'AppxManifest.xml')

if ($Version) {
    $manifestPath = Join-Path $layoutDir 'AppxManifest.xml'
    [xml]$manifest = Get-Content $manifestPath
    $manifest.Package.Identity.Version = $Version
    $manifest.Save($manifestPath)
    Write-Host "Manifest version set to $Version"
}

# ---------------------------------------------------------------- Pack + sign
Step 'Packing and signing the MSIX'
function Find-SdkTool($name) {
    $binRoot = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
    $candidate = Get-ChildItem $binRoot -Directory |
        Sort-Object Name -Descending |
        ForEach-Object { Join-Path $_.FullName "x64\$name" } |
        Where-Object { Test-Path $_ } |
        Select-Object -First 1
    if (-not $candidate) { throw "$name not found under $binRoot" }
    return $candidate
}
$makeappx = Find-SdkTool 'makeappx.exe'
$signtool = Find-SdkTool 'signtool.exe'

$msixPath = Join-Path $distDir 'PhoneFidoKey.msix'
& $makeappx pack /d $layoutDir /p $msixPath /o
if ($LASTEXITCODE -ne 0) { throw "makeappx failed ($LASTEXITCODE)" }

& $signtool sign /fd SHA256 /s My /sha1 $cert.Thumbprint $msixPath
if ($LASTEXITCODE -ne 0) { throw "signtool failed ($LASTEXITCODE)" }

Write-Host "`nDone:" -ForegroundColor Green
Write-Host "  MSIX:        $msixPath"
Write-Host "  Certificate: $cerPath"
Write-Host ''
Write-Host 'Install on the target machine:'
Write-Host '  1. Install PhoneFidoKey.cer into "Trusted People" (Local Machine).'
Write-Host '  2. Double-click PhoneFidoKey.msix and install.'
Write-Host '  3. From a terminal run:  PhoneFidoKeySetup'
Write-Host '  4. Enable the provider: Settings > Accounts > Passkeys.'
Write-Host '  See windows\README.md for the full walkthrough.'
