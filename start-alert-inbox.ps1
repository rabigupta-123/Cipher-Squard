param([switch]$Once)

$ErrorActionPreference = 'Stop'

# Cipher Squad outbound-alert receiver (self-contained alert inbox).
# Listens on 127.0.0.1:9290/alert/ and appends every `cipher_squad_alert`
# webhook POST to <project>\data\alert_inbox.ndjson, replying 200.
#
# This gives the alert system a real, verified delivery target out of the box.
# To alert a real SOC instead, add a channel in the console (Integrations ->
# Alert channels) pointing at your Slack incoming-webhook URL, a generic
# webhook URL, or SMTP settings -- the same pipeline delivers to those.
#
# Run directly for a foreground test:
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\start-alert-inbox.ps1 -Once

$port = 9290
$prefix = "http://127.0.0.1:$port/alert/"
$inbox = Join-Path $PSScriptRoot 'data\alert_inbox.ndjson'
New-Item -ItemType Directory -Force -Path (Split-Path $inbox) | Out-Null

# If already served by a detached instance, nothing to do (also covers `run.ps1` path).
if (-not $Once) {
  $l = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($l) { Write-Host "Alert inbox already listening on 127.0.0.1:$port (pid $($l.OwningProcess))."; exit 0 }
}

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add($prefix)
try {
  $listener.Start()
} catch {
  Write-Host "Cannot bind $prefix - try: netsh http add urlacl url=$prefix user=Users"
  exit 1
}
Write-Host "Alert inbox listening on $prefix -> $inbox"

while ($true) {
  try {
    $ctx = $listener.GetContext()
    $reader = New-Object System.IO.StreamReader($ctx.Request.InputStream)
    $json = $reader.ReadToEnd()
    $reader.Close()
    $stamp = [DateTime]::UtcNow.ToString('o')
    Add-Content -LiteralPath $inbox -Value ("{{`"received_at`":`"{0}`",`"content_type`":`"{1}`",`"payload`":{2}}}" -f $stamp, $ctx.Request.ContentType, $json) -Encoding UTF8
    $bytes = [System.Text.Encoding]::UTF8.GetBytes('{"received":true,"stored_at":"' + $stamp + '"}')
    $ctx.Response.StatusCode = 200
    $ctx.Response.ContentType = 'application/json'
    $ctx.Response.ContentLength64 = $bytes.Length
    $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $ctx.Response.Close()
  } catch {
    try { $ctx.Response.StatusCode = 500; $ctx.Response.Close() } catch { }
  }
}