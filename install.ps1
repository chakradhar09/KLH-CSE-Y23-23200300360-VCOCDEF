# Installs the `vcoc` command for the current user (Windows PowerShell 5.1 or later). Needs nothing installed first:
# it gets uv if missing, uv downloads Python 3.12 if missing, and vcoc's packages go into vcoc's own environment.
#   From a clone:      .\install.ps1
#   Without a clone:   irm https://raw.githubusercontent.com/chakradhar09/KLH-CSE-Y23-23200300360-VCOCDEF/main/install.ps1 | iex
# Run it again to update. Remove vcoc with `vcoc uninstall`.
$archive = "https://github.com/chakradhar09/KLH-CSE-Y23-23200300360-VCOCDEF/archive/refs/heads/main.zip"
$python = "3.12"

# throw, not exit: under `irm ... | iex` this runs in the caller's session, and exit would close their window.
function Fail($message) { throw "vcoc install failed: $message" }

if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Write-Host "Installing uv (Python and package manager, https://docs.astral.sh/uv/) ..."
    powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://astral.sh/uv/install.ps1 | iex"
    $env:Path = "$env:USERPROFILE\.local\bin;$env:Path"
    if (-not (Get-Command uv -ErrorAction SilentlyContinue)) { Fail "uv did not install. Check your internet connection and run this again." }
}

# Install the checkout this script sits in only if it really is vcoc; otherwise (and under iex) the published archive.
$source = $archive
if ($PSScriptRoot) {
    $pyproject = Join-Path $PSScriptRoot "pyproject.toml"
    if ((Test-Path $pyproject) -and (Select-String -Path $pyproject -Pattern '^name = "vcoc"$' -Quiet)) { $source = $PSScriptRoot }
}
Write-Host "Installing vcoc from $source with Python $python ..."
uv tool install --force --python $python $source
if ($LASTEXITCODE -ne 0) { Fail "uv could not install vcoc." }
uv tool update-shell *> $null

Write-Host ""
Write-Host "Done. Open a new terminal and run:  vcoc help"
