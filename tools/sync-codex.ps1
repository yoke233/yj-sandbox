#requires -Version 7.0
<#
.SYNOPSIS
Checks this repository's vendored Codex files against an upstream checkout.

.DESCRIPTION
Exit codes:
  0  No tracked upstream path changed.
  1  Changes were found. This remains 1 after verbatim files are applied because
     review and/or advancing the recorded baseline is still required.
  2  A manifest, path, ancestry, or decoupling invariant failed. No files are
     copied when preflight invariants fail.
  3  Git, archive, filesystem, or other tooling failed.

.PARAMETER CodexPath
Path to a local openai/codex Git checkout.

.PARAMETER TargetRef
Commit/ref to compare. Defaults to origin/main.

.PARAMETER Fetch
Run "git fetch origin" before resolving refs. Fetching never occurs implicitly.

.PARAMETER ApplyVerbatim
Copy changed verbatim/overwrite entries from the exact target commit.

.PARAMETER Json
Emit a single JSON report instead of human-readable output.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CodexPath,
    [string]$TargetRef = "origin/main",
    [switch]$Fetch,
    [switch]$ApplyVerbatim,
    [switch]$Json
)

$ErrorActionPreference = "Stop"
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $scriptRoot ".."))
$manifestPath = Join-Path $scriptRoot "codex-vendor.json"
$temporaryDirectory = $null
$exitCode = 3
$report = [ordered]@{
    schemaVersion = 1
    baseline = $null
    target = $null
    targetRef = $TargetRef
    changed = @()
    applied = @()
    warnings = @()
    errors = @()
}

function Invoke-GitCapture {
    param([string[]]$Arguments)
    $previousErrorAction = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $output = & git -C $CodexPath @Arguments 2>&1
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorAction
    }
    return [pscustomobject]@{ Code = $code; Output = @($output) }
}

function Invoke-LocalGitCapture {
    param([string[]]$Arguments)
    $previousErrorAction = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $output = & git -C $repositoryRoot @Arguments 2>&1
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorAction
    }
    return [pscustomobject]@{ Code = $code; Output = @($output) }
}

function Add-InvariantError {
    param([string]$Message)
    $script:report.errors += $Message
    $script:exitCode = 2
}

function Assert-LocalPathInsideRepository {
    param([string]$RelativePath)
    if ([IO.Path]::IsPathRooted($RelativePath)) {
        throw "Manifest localPath must be relative: $RelativePath"
    }
    $full = [IO.Path]::GetFullPath((Join-Path $repositoryRoot $RelativePath))
    $prefix = $repositoryRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Manifest localPath escapes the repository: $RelativePath"
    }
    $relative = [IO.Path]::GetRelativePath($repositoryRoot, $full)
    $current = $repositoryRoot
    foreach ($segment in $relative.Split(
        [IO.Path]::DirectorySeparatorChar,
        [StringSplitOptions]::RemoveEmptyEntries
    )) {
        $current = Join-Path $current $segment
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Manifest localPath crosses a symlink or junction: $RelativePath"
            }
        }
    }
    return $full
}

function Get-CodeWithoutCommentsOrStrings {
    param([string]$Text)
    # Two large upstream test modules are retained as sync context but disabled
    # because their fixtures construct Codex workspace types. They are not part
    # of any compiled target and therefore do not violate the dependency seam.
    $withoutDisabledFixtures = [regex]::Replace(
        $Text,
        '(?s)#\[cfg\(all\(test,\s*any\(\)\)\)\]\s*mod\s+tests\s*\{.*\z',
        ''
    )
    $withoutBlocks = [regex]::Replace($withoutDisabledFixtures, '(?s)/\*.*?\*/', '')
    $withoutLines = [regex]::Replace($withoutBlocks, '(?m)//.*$', '')
    return [regex]::Replace($withoutLines, '"(?:\\.|[^"\\])*"', '""')
}

function Test-UpstreamEntryChanged {
    param(
        [string]$PathSpec,
        [string[]]$ChangedPaths
    )
    if ($PathSpec.IndexOfAny([char[]]"*?") -ge 0) {
        $pattern = [Management.Automation.WildcardPattern]::new(
            $PathSpec,
            [Management.Automation.WildcardOptions]::CultureInvariant
        )
        return @($ChangedPaths | Where-Object { $pattern.IsMatch($_) }).Count -gt 0
    }
    $directoryPrefix = $PathSpec.TrimEnd('/') + "/"
    return @($ChangedPaths | Where-Object {
        $_ -eq $PathSpec -or $_.StartsWith($directoryPrefix, [StringComparison]::Ordinal)
    }).Count -gt 0
}

try {
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        Add-InvariantError "Manifest not found: $manifestPath"
        throw [IO.InvalidDataException]::new("preflight")
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ($manifest.schemaVersion -ne 1 -or -not $manifest.upstream.baselineSha -or -not $manifest.files) {
        Add-InvariantError "Manifest schemaVersion 1, upstream baselineSha, and files are required."
        throw [IO.InvalidDataException]::new("preflight")
    }
    $report.baseline = [string]$manifest.upstream.baselineSha
    foreach ($mirror in @($manifest.upstream.baselineMirrors)) {
        try {
            if (-not $mirror.path -or -not $mirror.pattern) {
                Add-InvariantError "Baseline mirror requires path and pattern."
                continue
            }
            $mirrorPath = Assert-LocalPathInsideRepository ([string]$mirror.path)
            if (-not (Test-Path -LiteralPath $mirrorPath -PathType Leaf)) {
                Add-InvariantError "Baseline mirror does not exist: $($mirror.path)"
                continue
            }
            $mirrorText = Get-Content -LiteralPath $mirrorPath -Raw
            $matches = [regex]::Matches($mirrorText, [string]$mirror.pattern)
            if ($matches.Count -ne 1 -or
                $matches[0].Groups["sha"].Value -ne [string]$manifest.upstream.baselineSha) {
                Add-InvariantError "Baseline mirror $($mirror.path) does not uniquely record $($manifest.upstream.baselineSha)."
            }
        } catch {
            Add-InvariantError $_.Exception.Message
        }
    }

    $allowedClassifications = @("verbatim", "modified", "rewritten", "local", "omitted")
    $allowedStrategies = @("overwrite", "review", "semantic", "never")
    $requiredStrategies = @{
        verbatim = "overwrite"
        modified = "review"
        rewritten = "semantic"
        local = "never"
        omitted = "never"
    }
    $localPaths = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    $upstreamPaths = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    foreach ($entry in $manifest.files) {
        if ($allowedClassifications -notcontains [string]$entry.classification -or
            $allowedStrategies -notcontains [string]$entry.syncStrategy -or
            -not $entry.platform -or -not $entry.notes) {
            Add-InvariantError "Malformed manifest entry: $($entry | ConvertTo-Json -Compress)"
            continue
        }
        if ($entry.upstreamPath -and -not $upstreamPaths.Add([string]$entry.upstreamPath)) {
            Add-InvariantError "Duplicate manifest upstreamPath: $($entry.upstreamPath)"
            continue
        }
        if ([string]$entry.syncStrategy -ne $requiredStrategies[[string]$entry.classification]) {
            Add-InvariantError "Invalid classification/strategy pair: $($entry.classification)/$($entry.syncStrategy)"
            continue
        }
        if ($entry.classification -eq "omitted") {
            if ($entry.localPath) { Add-InvariantError "Omitted entry must not have localPath: $($entry.localPath)" }
            if (-not $entry.upstreamPath) { Add-InvariantError "Omitted entry requires upstreamPath." }
            continue
        }
        if (-not $entry.localPath) {
            Add-InvariantError "Non-omitted entry requires localPath."
            continue
        }
        try {
            $localFullPath = Assert-LocalPathInsideRepository ([string]$entry.localPath)
            if (-not $localPaths.Add($localFullPath)) {
                Add-InvariantError "Duplicate normalized manifest localPath: $($entry.localPath)"
                continue
            }
            if (-not (Test-Path -LiteralPath $localFullPath -PathType Leaf)) {
                Add-InvariantError "Manifest localPath does not exist: $($entry.localPath)"
            }
        } catch {
            Add-InvariantError $_.Exception.Message
        }
    }

    $forbidden = @(
        "codex_protocol", "codex_otel", "codex_utils_pty",
        "codex_utils_absolute_path", "codex_utils_string",
        "codex_network_proxy", "codex_core"
    )
    $sourceFiles = Get-ChildItem -LiteralPath (Join-Path $repositoryRoot "src") -Recurse -File
    foreach ($sourceFile in $sourceFiles) {
        $code = Get-CodeWithoutCommentsOrStrings (Get-Content -LiteralPath $sourceFile.FullName -Raw)
        foreach ($name in $forbidden) {
            $pattern = "(?m)^\s*(?:(?:pub\s+)?use\s+(?:::)?$([regex]::Escape($name))\b|extern\s+crate\s+$([regex]::Escape($name))\b)|\b$([regex]::Escape($name))::"
            if ($code -match $pattern) {
                $relative = [IO.Path]::GetRelativePath($repositoryRoot, $sourceFile.FullName).Replace('\', '/')
                Add-InvariantError "Forbidden Codex dependency reference '$name' in $relative."
            }
        }
    }
    if ($report.errors.Count -gt 0) { throw [IO.InvalidDataException]::new("preflight") }

    $checkout = Invoke-GitCapture @("rev-parse", "--is-inside-work-tree")
    if ($checkout.Code -ne 0 -or (($checkout.Output -join "").Trim() -ne "true")) {
        Add-InvariantError "CodexPath is not a Git checkout: $CodexPath"
        throw [IO.InvalidDataException]::new("preflight")
    }
    if ($Fetch) {
        $fetchResult = Invoke-GitCapture @("fetch", "origin")
        if ($fetchResult.Code -ne 0) {
            $report.errors += "git fetch origin failed: $($fetchResult.Output -join "`n")"
            $exitCode = 3
            throw [Exception]::new("tool")
        }
    }

    $baselineResult = Invoke-GitCapture @("rev-parse", "--verify", "$($manifest.upstream.baselineSha)^{commit}")
    $targetResult = Invoke-GitCapture @("rev-parse", "--verify", "$TargetRef^{commit}")
    if ($baselineResult.Code -ne 0) {
        Add-InvariantError "Baseline commit does not exist: $($manifest.upstream.baselineSha)"
    }
    if ($targetResult.Code -ne 0) {
        Add-InvariantError "Target commit does not exist: $TargetRef"
    }
    if ($report.errors.Count -gt 0) { throw [IO.InvalidDataException]::new("preflight") }
    $baselineCommit = ($baselineResult.Output -join "").Trim()
    $targetCommit = ($targetResult.Output -join "").Trim()
    $report.baseline = $baselineCommit
    $report.target = $targetCommit

    $ancestorResult = Invoke-GitCapture @("merge-base", "--is-ancestor", $baselineCommit, $targetCommit)
    if ($ancestorResult.Code -eq 1) {
        Add-InvariantError "Baseline $baselineCommit is not an ancestor of target $targetCommit."
        throw [IO.InvalidDataException]::new("preflight")
    }
    if ($ancestorResult.Code -ne 0) {
        $report.errors += "git merge-base failed: $($ancestorResult.Output -join "`n")"
        $exitCode = 3
        throw [Exception]::new("tool")
    }

    $verbatimStates = @{}
    foreach ($entry in $manifest.files | Where-Object {
        $_.classification -eq "verbatim" -and $_.syncStrategy -eq "overwrite"
    }) {
        $baselineBlobResult = Invoke-GitCapture @(
            "rev-parse", "--verify", "$baselineCommit`:$($entry.upstreamPath)"
        )
        if ($baselineBlobResult.Code -ne 0) {
            Add-InvariantError "Verbatim upstream file is absent at baseline: $($entry.upstreamPath)"
            continue
        }
        $targetBlobResult = Invoke-GitCapture @(
            "rev-parse", "--verify", "$targetCommit`:$($entry.upstreamPath)"
        )
        $localHashResult = Invoke-LocalGitCapture @(
            "hash-object", "--path=$($entry.localPath)", [string]$entry.localPath
        )
        if ($localHashResult.Code -ne 0) {
            Add-InvariantError "Could not hash verbatim local file: $($entry.localPath)"
            continue
        }

        $baselineBlob = ($baselineBlobResult.Output -join "").Trim()
        $targetBlob = if ($targetBlobResult.Code -eq 0) {
            ($targetBlobResult.Output -join "").Trim()
        } else {
            $null
        }
        $localBlob = ($localHashResult.Output -join "").Trim()
        $state = if ($localBlob -eq $baselineBlob) {
            "baseline"
        } elseif ($targetBlob -and $localBlob -eq $targetBlob) {
            "target"
        } else {
            "drift"
        }
        $verbatimStates[[string]$entry.upstreamPath] = [ordered]@{
            state = $state
            baselineBlob = $baselineBlob
            targetBlob = $targetBlob
            localBlob = $localBlob
        }
        if ($state -eq "drift") {
            Add-InvariantError "Verbatim local file has untracked drift: $($entry.localPath)"
        }
    }
    if ($report.errors.Count -gt 0) { throw [IO.InvalidDataException]::new("preflight") }

    $mappedUpstreamPaths = @($manifest.files | Where-Object { $_.upstreamPath } |
        ForEach-Object { [string]$_.upstreamPath })
    $diffArguments = @("diff", "--name-only", "--no-renames", $baselineCommit, $targetCommit, "--")
    $diffArguments += $mappedUpstreamPaths
    $diffResult = Invoke-GitCapture $diffArguments
    if ($diffResult.Code -ne 0) {
        $report.errors += "git diff failed: $($diffResult.Output -join "`n")"
        $exitCode = 3
        throw [Exception]::new("tool")
    }
    $changedUpstreamPaths = @($diffResult.Output | ForEach-Object { ([string]$_).Trim() } |
        Where-Object { $_ })

    foreach ($changedPath in $changedUpstreamPaths) {
        $owners = @($manifest.files | Where-Object {
            $_.upstreamPath -and
            (Test-UpstreamEntryChanged ([string]$_.upstreamPath) @($changedPath))
        })
        if ($owners.Count -gt 1) {
            Add-InvariantError "Upstream path matches multiple manifest entries: $changedPath"
        }
    }
    if ($report.errors.Count -gt 0) { throw [IO.InvalidDataException]::new("preflight") }

    foreach ($entry in $manifest.files) {
        if (-not $entry.upstreamPath -or
            -not (Test-UpstreamEntryChanged ([string]$entry.upstreamPath) $changedUpstreamPaths)) {
            continue
        }
        $report.changed += [ordered]@{
            localPath = $entry.localPath
            upstreamPath = $entry.upstreamPath
            platform = $entry.platform
            classification = $entry.classification
            syncStrategy = $entry.syncStrategy
            notes = $entry.notes
            localState = if ($verbatimStates.ContainsKey([string]$entry.upstreamPath)) {
                $verbatimStates[[string]$entry.upstreamPath].state
            } else {
                $null
            }
        }
    }

    if ($report.changed.Count -eq 0) {
        $exitCode = 0
    } else {
        $exitCode = 1
    }

    if ($ApplyVerbatim -and $report.changed.Count -gt 0) {
        $eligible = @($report.changed | Where-Object {
            $_.classification -eq "verbatim" -and
            $_.syncStrategy -eq "overwrite" -and
            $_.localState -eq "baseline"
        })
        foreach ($alreadyApplied in @($report.changed | Where-Object {
            $_.classification -eq "verbatim" -and
            $_.syncStrategy -eq "overwrite" -and
            $_.localState -eq "target"
        })) {
            $report.warnings += "Local file already matches target: $($alreadyApplied.localPath)"
        }
        if ($eligible.Count -gt 0) {
            $tempParent = [IO.Path]::GetTempPath().TrimEnd('\', '/')
            $temporaryDirectory = Join-Path $tempParent ("sync-codex-" + [guid]::NewGuid().ToString("N"))
            New-Item -ItemType Directory -Path $temporaryDirectory | Out-Null
            $archivePath = Join-Path $temporaryDirectory "target.tar"
            $extractPath = Join-Path $temporaryDirectory "extract"
            New-Item -ItemType Directory -Path $extractPath | Out-Null

            $available = @()
            foreach ($item in $eligible) {
                $existsResult = Invoke-GitCapture @("cat-file", "-e", "$targetCommit`:$($item.upstreamPath)")
                if ($existsResult.Code -eq 0) {
                    $available += $item
                } else {
                    $report.warnings += "Target removed $($item.upstreamPath); it was not copied."
                }
            }
            if ($available.Count -gt 0) {
                $archiveArguments = @("archive", "--format=tar", "--output=$archivePath", $targetCommit, "--")
                $archiveArguments += @($available | ForEach-Object { $_.upstreamPath })
                $archiveResult = Invoke-GitCapture $archiveArguments
                if ($archiveResult.Code -ne 0) {
                    $report.errors += "git archive failed: $($archiveResult.Output -join "`n")"
                    $exitCode = 3
                    throw [Exception]::new("tool")
                }
                & tar -xf $archivePath -C $extractPath
                if ($LASTEXITCODE -ne 0) {
                    $report.errors += "tar extraction failed."
                    $exitCode = 3
                    throw [Exception]::new("tool")
                }

                $prepared = @()
                foreach ($item in $available) {
                    $destination = Assert-LocalPathInsideRepository ([string]$item.localPath)
                    $source = Join-Path $extractPath ([string]$item.upstreamPath)
                    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
                        throw "Archived source missing: $($item.upstreamPath)"
                    }
                    $sourceItem = Get-Item -LiteralPath $source -Force
                    if (($sourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                        throw "Archived source is a symlink: $($item.upstreamPath)"
                    }
                    $sourceHash = Invoke-LocalGitCapture @(
                        "hash-object", "--path=$($item.localPath)", $source
                    )
                    $expectedHash = $verbatimStates[[string]$item.upstreamPath].targetBlob
                    if ($sourceHash.Code -ne 0 -or
                        (($sourceHash.Output -join "").Trim() -ne $expectedHash)) {
                        throw "Archived source does not match target blob: $($item.upstreamPath)"
                    }
                    $currentHash = Invoke-LocalGitCapture @(
                        "hash-object", "--path=$($item.localPath)", [string]$item.localPath
                    )
                    if ($currentHash.Code -ne 0 -or
                        (($currentHash.Output -join "").Trim() -ne
                            $verbatimStates[[string]$item.upstreamPath].baselineBlob)) {
                        throw "Verbatim local file changed during sync: $($item.localPath)"
                    }
                    $prepared += [pscustomobject]@{
                        Item = $item
                        Source = $source
                        Destination = $destination
                        ExpectedHash = $expectedHash
                    }
                }

                $backupPath = Join-Path $temporaryDirectory "backup"
                New-Item -ItemType Directory -Path $backupPath | Out-Null
                for ($index = 0; $index -lt $prepared.Count; $index++) {
                    Copy-Item `
                        -LiteralPath $prepared[$index].Destination `
                        -Destination (Join-Path $backupPath "$index.bin")
                }

                try {
                    foreach ($preparedItem in $prepared) {
                        Copy-Item `
                            -LiteralPath $preparedItem.Source `
                            -Destination $preparedItem.Destination `
                            -Force
                        $copiedHash = Invoke-LocalGitCapture @(
                            "hash-object",
                            "--path=$($preparedItem.Item.localPath)",
                            [string]$preparedItem.Item.localPath
                        )
                        if ($copiedHash.Code -ne 0 -or
                            (($copiedHash.Output -join "").Trim() -ne $preparedItem.ExpectedHash)) {
                            throw "Copied file does not match target blob: $($preparedItem.Item.localPath)"
                        }
                    }
                } catch {
                    $applyError = $_.Exception.Message
                    $rollbackErrors = @()
                    for ($index = 0; $index -lt $prepared.Count; $index++) {
                        try {
                            Copy-Item `
                                -LiteralPath (Join-Path $backupPath "$index.bin") `
                                -Destination $prepared[$index].Destination `
                                -Force
                        } catch {
                            $rollbackErrors += "$($prepared[$index].Item.localPath): $($_.Exception.Message)"
                        }
                    }
                    if ($rollbackErrors.Count -gt 0) {
                        throw "Apply failed: $applyError. Rollback also failed: $($rollbackErrors -join '; ')"
                    }
                    throw "Apply failed and all copied files were restored: $applyError"
                }
                $report.applied += @($prepared | ForEach-Object { $_.Item.localPath })
            }
        }
    }
} catch {
    if ($exitCode -notin @(2, 3)) {
        $exitCode = 3
        $report.errors += $_.Exception.Message
    } elseif ($_.Exception.Message -notin @("preflight", "tool") -and
              $report.errors -notcontains $_.Exception.Message) {
        $report.errors += $_.Exception.Message
    }
} finally {
    if ($temporaryDirectory) {
        $resolvedTempParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/')
        $resolvedTemporary = [IO.Path]::GetFullPath($temporaryDirectory)
        $safePrefix = $resolvedTempParent + [IO.Path]::DirectorySeparatorChar + "sync-codex-"
        if ($resolvedTemporary.StartsWith($safePrefix, [StringComparison]::OrdinalIgnoreCase) -and
            (Test-Path -LiteralPath $resolvedTemporary -PathType Container)) {
            Remove-Item -LiteralPath $resolvedTemporary -Recurse -Force
        }
    }
}

if ($Json) {
    $report.exitCode = $exitCode
    $report | ConvertTo-Json -Depth 8
} else {
    if ($report.target) { Write-Output "Codex vendor check: $($report.baseline) -> $($report.target)" }
    foreach ($item in $report.changed) {
        Write-Output "CHANGED [$($item.classification)/$($item.syncStrategy)] $($item.upstreamPath)"
    }
    foreach ($path in $report.applied) { Write-Output "APPLIED $path" }
    foreach ($warning in $report.warnings) { Write-Warning $warning }
    foreach ($errorMessage in $report.errors) { Write-Error $errorMessage -ErrorAction Continue }
    if ($exitCode -eq 0) { Write-Output "No tracked upstream changes." }
}
exit $exitCode
