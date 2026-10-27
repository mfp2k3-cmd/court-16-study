param(
    [string]$ShadPS4Root = 'third_party\shadPS4',
    [string]$CorePatch = 'patches\shadps4\nba16-reusable-core.patch'
)

$ErrorActionPreference = 'Stop'

$repoRoot = if ([System.IO.Path]::IsPathRooted($ShadPS4Root)) {
    $ShadPS4Root
} else {
    Join-Path $PSScriptRoot $ShadPS4Root
}
$corePatchPath = if ([System.IO.Path]::IsPathRooted($CorePatch)) {
    $CorePatch
} else {
    Join-Path $PSScriptRoot $CorePatch
}

$patches = @(
    @{ Repo = ''; Patch = $corePatchPath },
    @{ Repo = ''; Patch = 'patches\shadps4\nba16-runtime-customizations.patch' },
    @{ Repo = 'externals\sirit'; Patch = 'patches\shadps4\sirit-clang64.patch' },
    @{ Repo = 'externals\aacdec\fdk-aac'; Patch = 'patches\shadps4\fdk-aac-windows-x64.patch' },
    @{ Repo = 'externals\openal-soft'; Patch = 'patches\shadps4\openal-clang-libcpp.patch' }
)

foreach ($item in $patches) {
    $repo = if ($item.Repo) { Join-Path $repoRoot $item.Repo } else { $repoRoot }
    $patch = if ([System.IO.Path]::IsPathRooted($item.Patch)) { $item.Patch } else { Join-Path $PSScriptRoot $item.Patch }
    if (-not (Test-Path -LiteralPath (Join-Path $repo '.git'))) {
        throw "Submódulo necessário não encontrado: $repo. Execute git submodule update --init --recursive primeiro."
    }

    & git -C $repo apply --reverse --check $patch 2>$null
    if ($LASTEXITCODE -eq 0) {
        continue
    }

    & git -C $repo apply --check $patch
    if ($LASTEXITCODE -ne 0) {
        throw "O patch não corresponde à versão do submódulo: $patch"
    }
    & git -C $repo apply $patch
    if ($LASTEXITCODE -ne 0) {
        throw "Não foi possível aplicar o patch: $patch"
    }
}
