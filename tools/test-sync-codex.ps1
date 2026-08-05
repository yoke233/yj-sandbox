#requires -Version 7.0
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$sourceTools = Split-Path -Parent $MyInvocation.MyCommand.Path
$tempParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/')
$testRoot = Join-Path $tempParent ("test-sync-codex-" + [guid]::NewGuid().ToString("N"))
$failures = [Collections.Generic.List[string]]::new()

function Invoke-CheckedGit {
    param([string]$Repository, [string[]]$Arguments)
    $output = & git -C $Repository @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw "git $($Arguments -join ' ') failed: $($output -join "`n")" }
    return @($output)
}

function Invoke-Sync {
    param([string]$Project, [string]$Upstream, [string]$Target, [switch]$Apply)
    $arguments = @("-NoProfile", "-File", (Join-Path $Project "tools/sync-codex.ps1"),
        "-CodexPath", $Upstream, "-TargetRef", $Target, "-Json")
    if ($Apply) { $arguments += "-ApplyVerbatim" }
    $output = & pwsh @arguments 2>&1
    return [pscustomobject]@{ Code = $LASTEXITCODE; Output = ($output -join "`n") }
}

function Assert-Equal {
    param($Expected, $Actual, [string]$Label)
    if ($Expected -ne $Actual) { $failures.Add("$Label expected '$Expected', got '$Actual'") }
}

function Set-Baseline {
    param([string]$ManifestPath, [string]$Sha)
    $manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
    $manifest.upstream.baselineSha = $Sha
    $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ManifestPath -Encoding UTF8
    $projectRoot = Split-Path -Parent (Split-Path -Parent $ManifestPath)
    foreach ($mirror in @($manifest.upstream.baselineMirrors)) {
        $value = if ([string]$mirror.path -eq "SYNCING.md") {
            "| Vendored/reviewed at commit | ``$Sha`` |"
        } else {
            "Vendored from openai/codex at commit`n$Sha."
        }
        Set-Content -LiteralPath (Join-Path $projectRoot ([string]$mirror.path)) -Value $value -Encoding UTF8
    }
}

try {
    New-Item -ItemType Directory -Path $testRoot | Out-Null
    $project = Join-Path $testRoot "project"
    $upstream = Join-Path $testRoot "upstream"
    New-Item -ItemType Directory -Path (Join-Path $project "tools") -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $project "src") -Force | Out-Null
    New-Item -ItemType Directory -Path $upstream | Out-Null
    Copy-Item -LiteralPath (Join-Path $sourceTools "sync-codex.ps1") -Destination (Join-Path $project "tools/sync-codex.ps1")
    Copy-Item -LiteralPath (Join-Path $sourceTools "codex-vendor.json") -Destination (Join-Path $project "tools/codex-vendor.json")

    $testManifestPath = Join-Path $project "tools/codex-vendor.json"
    $testManifest = Get-Content -LiteralPath $testManifestPath -Raw | ConvertFrom-Json
    foreach ($entry in $testManifest.files) {
        if ($entry.localPath) {
            $path = Join-Path $project ([string]$entry.localPath)
            New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force | Out-Null
            Set-Content -LiteralPath $path -Value "local-$($entry.localPath)" -Encoding UTF8
        }
    }

    Invoke-CheckedGit $upstream @("init", "-q")
    Invoke-CheckedGit $upstream @("config", "user.email", "sync-test@example.invalid")
    Invoke-CheckedGit $upstream @("config", "user.name", "Sync Test")
    foreach ($entry in $testManifest.files) {
        if ($entry.upstreamPath -and ([string]$entry.upstreamPath -notmatch '[*?]')) {
            $upstreamPath = [string]$entry.upstreamPath
            $fixturePath = if ($upstreamPath -match '/(conpty|unified_exec)$') {
                "$upstreamPath/probe.rs"
            } else {
                $upstreamPath
            }
            $path = Join-Path $upstream $fixturePath
            if (-not (Test-Path -LiteralPath $path)) {
                New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force | Out-Null
                Set-Content -LiteralPath $path -Value "baseline-$fixturePath" -Encoding UTF8
            }
        }
    }
    $wildcardFixture = Join-Path $upstream "codex-rs/windows-sandbox-rs/src/wrapper_probe.rs"
    New-Item -ItemType Directory -Path (Split-Path -Parent $wildcardFixture) -Force | Out-Null
    Set-Content -LiteralPath $wildcardFixture -Value "baseline-wildcard" -Encoding UTF8
    Invoke-CheckedGit $upstream @("add", ".")
    Invoke-CheckedGit $upstream @("commit", "-q", "-m", "baseline")
    $baseline = (Invoke-CheckedGit $upstream @("rev-parse", "HEAD") | Select-Object -First 1).Trim()
    Set-Baseline $testManifestPath $baseline
    foreach ($entry in $testManifest.files | Where-Object {
        $_.classification -eq "verbatim" -and $_.syncStrategy -eq "overwrite"
    }) {
        Copy-Item `
            -LiteralPath (Join-Path $upstream ([string]$entry.upstreamPath)) `
            -Destination (Join-Path $project ([string]$entry.localPath)) `
            -Force
    }

    $clean = Invoke-Sync $project $upstream "HEAD"
    Assert-Equal 0 $clean.Code "clean exit"

    $exactFixture = Join-Path $upstream "codex-rs/windows-sandbox-rs/src/cap.rs"
    $directoryFixture = Join-Path $upstream "codex-rs/windows-sandbox-rs/src/unified_exec/probe.rs"
    Set-Content -LiteralPath $exactFixture -Value "pathspec-exact" -Encoding UTF8
    Set-Content -LiteralPath $directoryFixture -Value "pathspec-directory" -Encoding UTF8
    Set-Content -LiteralPath $wildcardFixture -Value "pathspec-wildcard" -Encoding UTF8
    Invoke-CheckedGit $upstream @("add", ".")
    Invoke-CheckedGit $upstream @("commit", "-q", "-m", "pathspec changes")
    $pathspecTarget = (Invoke-CheckedGit $upstream @("rev-parse", "HEAD") | Select-Object -First 1).Trim()
    $pathspecResult = Invoke-Sync $project $upstream $pathspecTarget
    Assert-Equal 1 $pathspecResult.Code "exact directory wildcard pathspec exit"
    $pathspecReport = $pathspecResult.Output | ConvertFrom-Json
    $reportedSpecs = @($pathspecReport.changed | ForEach-Object { $_.upstreamPath })
    Assert-Equal $true ($reportedSpecs -contains "codex-rs/windows-sandbox-rs/src/cap.rs") "exact pathspec reported"
    Assert-Equal $true ($reportedSpecs -contains "codex-rs/windows-sandbox-rs/src/unified_exec") "directory pathspec reported"
    Assert-Equal $true ($reportedSpecs -contains "codex-rs/windows-sandbox-rs/src/wrapper*") "wildcard pathspec reported"

    $manifestBeforeOverlapTest = Get-Content -LiteralPath $testManifestPath -Raw
    $overlapManifest = $manifestBeforeOverlapTest | ConvertFrom-Json
    ($overlapManifest.files |
        Where-Object { $_.upstreamPath -eq "codex-rs/windows-sandbox-rs/src/wrapper*" }
    ).upstreamPath = "codex-rs/windows-sandbox-rs/src/cap*"
    $overlapManifest | ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath $testManifestPath -Encoding UTF8
    $overlap = Invoke-Sync $project $upstream $pathspecTarget -Apply
    Assert-Equal 2 $overlap.Code "overlapping upstream pathspec refusal"
    Set-Content -LiteralPath $testManifestPath -Value $manifestBeforeOverlapTest -NoNewline -Encoding UTF8
    Invoke-CheckedGit $upstream @("revert", "--no-edit", "HEAD") | Out-Null

    $manifestBeforeDuplicateTest = Get-Content -LiteralPath $testManifestPath -Raw
    $duplicateManifest = $manifestBeforeDuplicateTest | ConvertFrom-Json
    ($duplicateManifest.files | Where-Object { $_.localPath -eq "src/env.rs" }).localPath = "src/../src/cap.rs"
    $duplicateManifest | ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath $testManifestPath -Encoding UTF8
    $beforeDuplicate = Get-Content -LiteralPath (Join-Path $project "src/cap.rs") -Raw
    $duplicate = Invoke-Sync $project $upstream "HEAD" -Apply
    Assert-Equal 2 $duplicate.Code "duplicate manifest path refusal"
    Assert-Equal $beforeDuplicate (Get-Content -LiteralPath (Join-Path $project "src/cap.rs") -Raw) "duplicate mapping copied nothing"
    Set-Content -LiteralPath $testManifestPath -Value $manifestBeforeDuplicateTest -NoNewline -Encoding UTF8

    $syncingMirror = Join-Path $project "SYNCING.md"
    Set-Content `
        -LiteralPath $syncingMirror `
        -Value "| Vendored/reviewed at commit | ``0000000000000000000000000000000000000000`` |`n$baseline" `
        -Encoding UTF8
    $falseMirror = Invoke-Sync $project $upstream "HEAD"
    Assert-Equal 2 $falseMirror.Code "baseline mirror false-positive refusal"
    Set-Baseline $testManifestPath $baseline

    $manifestBeforeLinkTest = Get-Content -LiteralPath $testManifestPath -Raw
    $linkTarget = Join-Path $testRoot "outside"
    $linkPath = Join-Path $project "linked"
    New-Item -ItemType Directory -Path $linkTarget | Out-Null
    Copy-Item `
        -LiteralPath (Join-Path $upstream "codex-rs/windows-sandbox-rs/src/cap.rs") `
        -Destination (Join-Path $linkTarget "cap.rs")
    New-Item -ItemType Junction -Path $linkPath -Target $linkTarget | Out-Null
    $linkManifest = $manifestBeforeLinkTest | ConvertFrom-Json
    ($linkManifest.files | Where-Object { $_.localPath -eq "src/cap.rs" }).localPath = "linked/cap.rs"
    $linkManifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $testManifestPath -Encoding UTF8
    $linkedPath = Invoke-Sync $project $upstream "HEAD"
    Assert-Equal 2 $linkedPath.Code "junction path refusal"
    Remove-Item -LiteralPath $linkPath -Force
    Set-Content -LiteralPath $testManifestPath -Value $manifestBeforeLinkTest -NoNewline -Encoding UTF8

    $driftLocal = Join-Path $project "src/cap.rs"
    $beforeDrift = Get-Content -LiteralPath $driftLocal -Raw
    Set-Content -LiteralPath $driftLocal -Value "untracked-local-drift" -Encoding UTF8
    $drift = Invoke-Sync $project $upstream "HEAD" -Apply
    Assert-Equal 2 $drift.Code "verbatim local drift exit"
    Assert-Equal "untracked-local-drift" (Get-Content -LiteralPath $driftLocal -Raw).Trim() "verbatim drift not overwritten"
    Set-Content -LiteralPath $driftLocal -Value $beforeDrift -NoNewline -Encoding UTF8

    $verbatimUpstream = Join-Path $upstream "codex-rs/windows-sandbox-rs/src/cap.rs"
    $secondVerbatimUpstream = Join-Path $upstream "codex-rs/windows-sandbox-rs/src/env.rs"
    Set-Content -LiteralPath $verbatimUpstream -Value "target-verbatim" -Encoding UTF8
    Set-Content -LiteralPath $secondVerbatimUpstream -Value "target-verbatim-second" -Encoding UTF8
    Invoke-CheckedGit $upstream @("add", ".")
    Invoke-CheckedGit $upstream @("commit", "-q", "-m", "verbatim change")
    $verbatimTarget = (Invoke-CheckedGit $upstream @("rev-parse", "HEAD") | Select-Object -First 1).Trim()
    Set-Content -LiteralPath $verbatimUpstream -Value "dirty-working-tree" -Encoding UTF8
    $verbatimLocal = Join-Path $project "src/cap.rs"
    $secondVerbatimLocal = Join-Path $project "src/env.rs"
    $beforeCheckOnly = Get-Content -LiteralPath $verbatimLocal -Raw
    $beforeSecondVerbatim = Get-Content -LiteralPath $secondVerbatimLocal -Raw
    $checkOnly = Invoke-Sync $project $upstream $verbatimTarget
    Assert-Equal 1 $checkOnly.Code "verbatim check-only exit"
    Assert-Equal $beforeCheckOnly (Get-Content -LiteralPath $verbatimLocal -Raw) "check-only copied nothing"

    $testSyncScript = Join-Path $project "tools/sync-codex.ps1"
    $syncScriptText = Get-Content -LiteralPath $testSyncScript -Raw
    $copyVerificationLine = '                        $copiedHash = Invoke-LocalGitCapture @('
    $injectedCopyVerification = @'
                        $script:testCopyCount = 1 + [int]$script:testCopyCount
                        if ($script:testCopyCount -eq 2) { throw "injected second-copy failure" }
                        $copiedHash = Invoke-LocalGitCapture @(
'@
    $injectedScriptText = $syncScriptText.Replace(
        $copyVerificationLine,
        $injectedCopyVerification.TrimEnd("`r", "`n")
    )
    Assert-Equal $false ($injectedScriptText -eq $syncScriptText) "rollback fault injection seam found"
    Set-Content -LiteralPath $testSyncScript -Value $injectedScriptText -NoNewline -Encoding UTF8
    $rollback = Invoke-Sync $project $upstream $verbatimTarget -Apply
    Assert-Equal 3 $rollback.Code "injected batch failure exit"
    Assert-Equal $beforeCheckOnly (Get-Content -LiteralPath $verbatimLocal -Raw) "first verbatim restored"
    Assert-Equal $beforeSecondVerbatim (Get-Content -LiteralPath $secondVerbatimLocal -Raw) "second verbatim restored"
    Copy-Item -LiteralPath (Join-Path $sourceTools "sync-codex.ps1") -Destination $testSyncScript -Force

    $verbatim = Invoke-Sync $project $upstream $verbatimTarget -Apply
    Assert-Equal 1 $verbatim.Code "verbatim changed exit; output=$($verbatim.Output)"
    $copied = (Get-Content -LiteralPath $verbatimLocal -Raw).Trim()
    Assert-Equal "target-verbatim" $copied "verbatim copied from commit"
    $copiedSecond = (Get-Content -LiteralPath $secondVerbatimLocal -Raw).Trim()
    Assert-Equal "target-verbatim-second" $copiedSecond "second verbatim copied from commit"
    Invoke-CheckedGit $upstream @(
        "restore",
        "codex-rs/windows-sandbox-rs/src/cap.rs",
        "codex-rs/windows-sandbox-rs/src/env.rs"
    )

    $modifiedUpstream = Join-Path $upstream "codex-rs/windows-sandbox-rs/src/allow.rs"
    Set-Content -LiteralPath $modifiedUpstream -Value "target-modified" -Encoding UTF8
    Invoke-CheckedGit $upstream @("add", ".")
    Invoke-CheckedGit $upstream @("commit", "-q", "-m", "modified change")
    $modifiedTarget = (Invoke-CheckedGit $upstream @("rev-parse", "HEAD") | Select-Object -First 1).Trim()
    $modifiedLocal = Join-Path $project "src/allow.rs"
    $beforeModified = Get-Content -LiteralPath $modifiedLocal -Raw
    $modified = Invoke-Sync $project $upstream $modifiedTarget -Apply
    Assert-Equal 1 $modified.Code "modified changed exit; output=$($modified.Output)"
    Assert-Equal $beforeModified (Get-Content -LiteralPath $modifiedLocal -Raw) "modified not overwritten"

    Invoke-CheckedGit $upstream @("checkout", "-q", "--orphan", "unrelated")
    Invoke-CheckedGit $upstream @("rm", "-q", "-r", "-f", ".")
    Set-Content -LiteralPath (Join-Path $upstream "unrelated.txt") -Value "unrelated" -Encoding UTF8
    Invoke-CheckedGit $upstream @("add", ".")
    Invoke-CheckedGit $upstream @("commit", "-q", "-m", "unrelated")
    $unrelated = (Invoke-CheckedGit $upstream @("rev-parse", "HEAD") | Select-Object -First 1).Trim()
    $beforeNonAncestor = Get-Content -LiteralPath (Join-Path $project "src/token.rs") -Raw
    $nonAncestor = Invoke-Sync $project $upstream $unrelated -Apply
    Assert-Equal 2 $nonAncestor.Code "non-ancestor exit"
    Assert-Equal $beforeNonAncestor (Get-Content -LiteralPath (Join-Path $project "src/token.rs") -Raw) "non-ancestor copied nothing"

    if ($failures.Count -gt 0) {
        foreach ($failure in $failures) { Write-Error $failure -ErrorAction Continue }
        exit 1
    }
    Write-Output "PASS clean, exact/directory/wildcard pathspecs, unique manifest, exact mirror, junction refusal, local drift, check-only, batch rollback/apply, modified no-overwrite, non-ancestor/no-copy"
    exit 0
} finally {
    $resolvedTestRoot = [IO.Path]::GetFullPath($testRoot)
    $safePrefix = $tempParent + [IO.Path]::DirectorySeparatorChar + "test-sync-codex-"
    if ($resolvedTestRoot.StartsWith($safePrefix, [StringComparison]::OrdinalIgnoreCase) -and
        (Test-Path -LiteralPath $resolvedTestRoot -PathType Container)) {
        Remove-Item -LiteralPath $resolvedTestRoot -Recurse -Force
    }
}
