param(
    [switch]$AllowSchemaErrors
)

$ErrorActionPreference = "Stop"
$env:PYTHONPATH = (Get-Location).Path

if ($AllowSchemaErrors) {
    python -m test.run --allow-schema-errors
} else {
    python -m test.run
}
