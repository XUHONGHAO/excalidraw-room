param(
  [string]$EnvFile = "C:\AI\excalidraw\scripts\vault\remote.local.env"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$roomRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$mainRepoRoot = "C:\AI\excalidraw"
$cliWorkdir = Join-Path `
  ([IO.Path]::GetTempPath()) `
  ("excalidraw-vault-room-" + [Guid]::NewGuid().ToString("N"))
$commonScript = Join-Path $mainRepoRoot "scripts\vault\common.ps1"
if (-not (Test-Path -LiteralPath $commonScript -PathType Leaf)) {
  throw "Vault environment helpers are unavailable"
}

. $commonScript
Import-VaultEnvironment $EnvFile

$projectRef = $env:VAULT_SUPABASE_PROJECT_REF
$accessToken = $env:SUPABASE_ACCESS_TOKEN
if ($projectRef -notmatch "^[a-z0-9]{20}$") {
  throw "VAULT_SUPABASE_PROJECT_REF must be a 20-character hosted Supabase project ref"
}
Assert-VaultRemoteConfirmation `
  $projectRef `
  $env:VAULT_REMOTE_CONFIRM_PROJECT_REF `
  $env:VAULT_REMOTE_CONFIRM_DISPOSABLE
if ([string]::IsNullOrWhiteSpace($accessToken)) {
  throw "SUPABASE_ACCESS_TOKEN is required for in-memory API key discovery"
}

Assert-VaultCommand "supabase"
Assert-VaultCommand "node"
Assert-VaultCommand "yarn"
$null = New-Item -ItemType Directory -Path $cliWorkdir

$previousValues = @{}
$gateEnvironmentNames = @(
  "VAULT_ROOM_GATE_TARGET",
  "VAULT_ROOM_GATE_PROJECT_REF",
  "VAULT_ROOM_GATE_API_URL",
  "VAULT_ROOM_GATE_ANON_KEY",
  "VAULT_ROOM_GATE_SERVICE_ROLE_KEY"
)
$scrubbedEnvironmentNames = @(
  "SUPABASE_ACCESS_TOKEN",
  "VAULT_SUPABASE_DB_URL",
  "VAULT_SUPABASE_SSLROOTCERT_PATH"
)
foreach ($name in $gateEnvironmentNames) {
  $previousValues[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}
foreach ($name in $scrubbedEnvironmentNames) {
  $previousValues[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}

try {
  $previousErrorActionPreference = $ErrorActionPreference
  try {
    # Keep revealed API keys in memory. Never forward CLI output or errors,
    # because provider output formats may include credentials.
    $ErrorActionPreference = "Continue"
    $apiKeyJson = & supabase projects api-keys `
      --project-ref $projectRef `
      --reveal `
      --output json `
      --workdir $cliWorkdir 2>$null
    $apiKeyExitCode = $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $previousErrorActionPreference
  }
  if ($apiKeyExitCode -ne 0) {
    throw "Supabase API key discovery failed"
  }

  try {
    $apiKeyTable = $apiKeyJson | ConvertFrom-Json
  } catch {
    throw "Supabase API key discovery returned invalid JSON"
  }
  $apiKeyNames = @($apiKeyTable.name)
  $apiKeyTypes = @($apiKeyTable.type)
  $apiKeyValues = @($apiKeyTable.api_key)
  if (
    $apiKeyNames.Count -eq 0 -or
    $apiKeyTypes.Count -ne $apiKeyNames.Count -or
    $apiKeyValues.Count -ne $apiKeyNames.Count
  ) {
    throw "Supabase API key discovery returned an unsupported table shape"
  }
  $apiKeys = @(for ($index = 0; $index -lt $apiKeyNames.Count; $index++) {
      [pscustomobject]@{
        name = [string]$apiKeyNames[$index]
        type = [string]$apiKeyTypes[$index]
        api_key = [string]$apiKeyValues[$index]
      }
    })
  $anonEntry = @($apiKeys | Where-Object {
      $_.name -ceq "anon" -and $_.type -ceq "legacy"
    })
  $serviceRoleEntry = @($apiKeys | Where-Object {
      $_.name -ceq "service_role" -and $_.type -ceq "legacy"
    })
  if (
    $anonEntry.Count -ne 1 -or
    $serviceRoleEntry.Count -ne 1 -or
    [string]::IsNullOrWhiteSpace([string]$anonEntry[0].api_key) -or
    [string]::IsNullOrWhiteSpace([string]$serviceRoleEntry[0].api_key)
  ) {
    throw "Supabase project does not expose exactly one legacy anon and service-role key"
  }

  $env:VAULT_ROOM_GATE_TARGET = "remote"
  $env:VAULT_ROOM_GATE_PROJECT_REF = $projectRef
  $env:VAULT_ROOM_GATE_API_URL = "https://$projectRef.supabase.co"
  $env:VAULT_ROOM_GATE_ANON_KEY = [string]$anonEntry[0].api_key
  $env:VAULT_ROOM_GATE_SERVICE_ROLE_KEY = [string]$serviceRoleEntry[0].api_key
  foreach ($name in $scrubbedEnvironmentNames) {
    [Environment]::SetEnvironmentVariable($name, $null, "Process")
  }

  Push-Location $roomRoot
  try {
    Invoke-VaultExternalCommand "yarn" @("build")
    Invoke-VaultExternalCommand "node" @("scripts/vault-room-real-gate.cjs")

    try {
      $cleanupResponse = Invoke-RestMethod `
        -Method Get `
        -Uri "https://$projectRef.supabase.co/auth/v1/admin/users?page=1&per_page=1000" `
        -Headers @{
          apikey = [string]$serviceRoleEntry[0].api_key
          Authorization = "Bearer $([string]$serviceRoleEntry[0].api_key)"
        } `
        -TimeoutSec 20
    } catch {
      throw "Remote room gate fixture cleanup verification failed"
    }
    $remainingGateUsers = @($cleanupResponse.users | Where-Object {
        $_.email -like "vault-room-gate-*@example.invalid"
      }).Count
    if ($remainingGateUsers -ne 0) {
      throw "Remote room gate left isolated auth fixtures behind"
    }
    Write-Output "Vault room remote fixture cleanup verified."
  } finally {
    Pop-Location
  }
} finally {
  $apiKeyJson = $null
  $apiKeyTable = $null
  $apiKeyNames = $null
  $apiKeyTypes = $null
  $apiKeyValues = $null
  $apiKeys = $null
  $anonEntry = $null
  $serviceRoleEntry = $null
  $cleanupResponse = $null
  foreach ($name in @($gateEnvironmentNames + $scrubbedEnvironmentNames)) {
    [Environment]::SetEnvironmentVariable(
      $name,
      $previousValues[$name],
      "Process"
    )
  }
  $temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd("\") + "\"
  $resolvedCliWorkdir = [IO.Path]::GetFullPath($cliWorkdir)
  if (
    $resolvedCliWorkdir.StartsWith(
      $temporaryRoot,
      [StringComparison]::OrdinalIgnoreCase
    ) -and
    (Split-Path -Leaf $resolvedCliWorkdir).StartsWith(
      "excalidraw-vault-room-",
      [StringComparison]::Ordinal
    ) -and
    (Test-Path -LiteralPath $resolvedCliWorkdir)
  ) {
    Remove-Item -LiteralPath $resolvedCliWorkdir -Recurse -Force
  }
}
