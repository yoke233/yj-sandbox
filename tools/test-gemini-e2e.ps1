param(
    [string]$SandboxExe = (Join-Path $PSScriptRoot '..\target\release\yj-sandbox-run.exe'),
    [switch]$KeepArtifacts
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) {
        throw "Gemini E2E assertion failed: $Message"
    }
}

if (-not $IsWindows) {
    throw 'Gemini E2E is Windows-only'
}

$sandbox = (Resolve-Path -LiteralPath $SandboxExe).Path
$workspaceBase = Join-Path $env:APPDATA 'yongjian-ai-client\workspaces'
New-Item -ItemType Directory -Path $workspaceBase -Force | Out-Null
$runId = [guid]::NewGuid().ToString('N')
$workspace = Join-Path $workspaceBase "yj-sandbox-gemini-e2e-$runId"
$extraRoot = Join-Path $workspaceBase "yj-sandbox-gemini-extra-$runId"
$outsideRoot = Join-Path $workspaceBase "yj-sandbox-gemini-outside-$runId"
$codexHome = Join-Path $workspaceBase "yj-sandbox-gemini-home-$runId"
$tempFile = Join-Path ([IO.Path]::GetTempPath()) "yj-sandbox-gemini-temp-$runId.txt"
$artifactRoots = @($workspace, $extraRoot, $outsideRoot, $codexHome)
New-Item -ItemType Directory -Path $artifactRoots | Out-Null

$oldCodexHome = $env:CODEX_HOME
$oldNpmCache = $env:NPM_CONFIG_CACHE

try {
    $env:CODEX_HOME = $codexHome
    $env:NPM_CONFIG_CACHE = Join-Path $workspace '.npm-cache'

    # No windows.sandbox override: this verifies that Gemini is the default.
    $zip = Join-Path $workspace 'human-writing.zip'
    & $sandbox -P ':workspace' -C $workspace -- curl.exe -L -sS --max-time 30 `
        -o $zip --insecure --ssl-no-revoke `
        'https://github.com/KKKKhazix/human-writing/archive/refs/heads/main.zip'
    Assert-True ($LASTEXITCODE -eq 0) 'Schannel curl must exit 0'
    Assert-True ((Test-Path -LiteralPath $zip) -and ((Get-Item -LiteralPath $zip).Length -gt 0)) `
        'Schannel curl must create a non-empty ZIP'

    $groups = & $sandbox -P ':workspace' -C $workspace -- whoami.exe /groups 2>&1
    Assert-True ($LASTEXITCODE -eq 0) 'whoami /groups must exit 0'
    Assert-True (($groups -join "`n") -match 'S-1-16-4096') 'child token must be Low Integrity'

    $state = @{
        sandboxCwd = $workspace
        permissionProfile = @{
            type = 'managed'
            file_system = @{
                type = 'restricted'
                entries = @(
                    @{ path = @{ type = 'special'; value = @{ kind = 'root' } }; access = 'read' }
                    @{ path = @{ type = 'special'; value = @{ kind = 'project_roots' } }; access = 'write' }
                    @{ path = @{ type = 'path'; path = $extraRoot }; access = 'write' }
                    @{ path = @{ type = 'special'; value = @{ kind = 'tmpdir' } }; access = 'write' }
                )
            }
            network = 'enabled'
        }
        codexLinuxSandboxExe = $null
        useLegacyLandlock = $false
    } | ConvertTo-Json -Compress -Depth 10

    $env:YJ_GEMINI_WORKSPACE_FILE = Join-Path $workspace 'powershell-write.txt'
    $env:YJ_GEMINI_EXTRA_FILE = Join-Path $extraRoot 'extra-write.txt'
    $env:YJ_GEMINI_TEMP_FILE = $tempFile
    & $sandbox --sandbox-state-json $state -- powershell.exe -NoProfile -Command `
        'Set-Content -LiteralPath $env:YJ_GEMINI_WORKSPACE_FILE -Value workspace; Set-Content -LiteralPath $env:YJ_GEMINI_EXTRA_FILE -Value extra; Set-Content -LiteralPath $env:YJ_GEMINI_TEMP_FILE -Value temp'
    Assert-True ($LASTEXITCODE -eq 0) 'PowerShell must write all resolved writable roots'
    Assert-True ((Get-Content -LiteralPath $env:YJ_GEMINI_WORKSPACE_FILE) -eq 'workspace') `
        'workspace write must persist'
    Assert-True ((Get-Content -LiteralPath $env:YJ_GEMINI_EXTRA_FILE) -eq 'extra') `
        'extra-root write must persist'
    Assert-True ((Get-Content -LiteralPath $env:YJ_GEMINI_TEMP_FILE) -eq 'temp') `
        'configured TEMP write must persist'

    $env:YJ_GEMINI_OUTSIDE_FILE = Join-Path $outsideRoot 'should-not-exist.txt'
    & $sandbox --sandbox-state-json $state -- powershell.exe -NoProfile -Command `
        'Set-Content -LiteralPath $env:YJ_GEMINI_OUTSIDE_FILE -Value outside' 2>$null
    Assert-True ($LASTEXITCODE -ne 0) 'write outside resolved roots must fail'
    Assert-True (-not (Test-Path -LiteralPath $env:YJ_GEMINI_OUTSIDE_FILE)) `
        'outside file must not be created'

    & $sandbox -P ':workspace' -C $workspace -- git.exe init | Out-Null
    Assert-True ($LASTEXITCODE -eq 0) 'git init must succeed'
    $gitFile = Join-Path $workspace 'git-e2e.txt'
    Set-Content -LiteralPath $gitFile -Value 'git'
    & $sandbox -P ':workspace' -C $workspace -- git.exe -C $workspace add git-e2e.txt
    Assert-True ($LASTEXITCODE -eq 0) 'git add must succeed'
    & $sandbox -P ':workspace' -C $workspace -- git.exe ls-remote `
        'https://github.com/KKKKhazix/human-writing.git' HEAD | Out-Null
    Assert-True ($LASTEXITCODE -eq 0) 'Git HTTPS must succeed'

    $npmVersion = & $sandbox -P ':workspace' -C $workspace -- npm.cmd --version 2>&1
    Assert-True (($LASTEXITCODE -eq 0) -and -not [string]::IsNullOrWhiteSpace(($npmVersion -join ''))) `
        'npm --version must succeed'
    $npmView = & $sandbox -P ':workspace' -C $workspace -- npm.cmd view is-number version `
        --fetch-timeout=30000 2>&1
    Assert-True (($LASTEXITCODE -eq 0) -and -not [string]::IsNullOrWhiteSpace(($npmView -join ''))) `
        'npm registry HTTPS must succeed'

    $env:YJ_GEMINI_CHILD_FILE = Join-Path $workspace 'child-process.txt'
    & $sandbox -P ':workspace' -C $workspace -- powershell.exe -NoProfile -Command `
        '& cmd.exe /d /c "echo child-process>$env:YJ_GEMINI_CHILD_FILE"'
    Assert-True ($LASTEXITCODE -eq 0) 'nested child process must succeed'
    Assert-True ((Get-Content -LiteralPath $env:YJ_GEMINI_CHILD_FILE) -eq 'child-process') `
        'nested child process output must persist'

    & $sandbox -P ':workspace' -C $workspace -- cmd.exe /d /c 'exit 37'
    Assert-True ($LASTEXITCODE -eq 37) 'target exit code must be preserved'

}
finally {
    foreach ($name in @(
        'YJ_GEMINI_WORKSPACE_FILE',
        'YJ_GEMINI_EXTRA_FILE',
        'YJ_GEMINI_TEMP_FILE',
        'YJ_GEMINI_OUTSIDE_FILE',
        'YJ_GEMINI_CHILD_FILE'
    )) {
        Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
    }
    if ($null -eq $oldCodexHome) { Remove-Item Env:CODEX_HOME -ErrorAction SilentlyContinue }
    else { $env:CODEX_HOME = $oldCodexHome }
    if ($null -eq $oldNpmCache) { Remove-Item Env:NPM_CONFIG_CACHE -ErrorAction SilentlyContinue }
    else { $env:NPM_CONFIG_CACHE = $oldNpmCache }

    if (Test-Path -LiteralPath $tempFile) {
        Remove-Item -LiteralPath $tempFile -Force
    }

    if (-not $KeepArtifacts) {
        $safeBase = [IO.Path]::GetFullPath($workspaceBase).TrimEnd('\') + '\'
        foreach ($path in $artifactRoots) {
            $fullPath = [IO.Path]::GetFullPath($path)
            if (-not $fullPath.StartsWith($safeBase, [StringComparison]::OrdinalIgnoreCase)) {
                throw "refusing to remove E2E path outside workspace base: $fullPath"
            }
            if (Test-Path -LiteralPath $fullPath) {
                Remove-Item -LiteralPath $fullPath -Recurse -Force
            }
        }
    }
}

Write-Output 'GEMINI_E2E_PASS'
$global:LASTEXITCODE = 0
