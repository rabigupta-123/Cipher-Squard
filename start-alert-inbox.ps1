param([switch]$Once)

$ErrorActionPreference = 'Stop'

# Cipher Squad outbound-alert receiver (self-contained alert inbox).
# Listens on 127.0.0.1:9290/alert/ and appends every `cipher_squad_alert`
# webhook POST to <project>\data\alert_inbox.ndjson, replying 200.
#
# Uses a TcpListener-based HTTP/1.1 mini-server so it binds WITHOUT elevation
# (HttpListener requires an http.sys URL ACL that a non-admin shell cannot add).
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

function Read-Headers {
  param($S)
  $bytes = New-Object System.Collections.Generic.List[byte]
  $one = New-Object byte[] 1
  $pattern = @(13,10,13,10)
  while ($bytes.Count -lt 65536) {
    $n = $S.Read($one, 0, 1)
    if ($n -le 0) { break }
    $bytes.Add($one[0])
    $c = $bytes.Count
    if ($c -ge 4 -and $bytes[$c-4] -eq $pattern[0] -and $bytes[$c-3] -eq $pattern[1] -and $bytes[$c-2] -eq $pattern[2] -and $bytes[$c-1] -eq $pattern[3]) { break }
  }
  return ,([System.Text.Encoding]::ASCII.GetString($bytes.ToArray()))
}

$listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $port)
$listener.Start()
Write-Host "Alert inbox listening on $prefix -> $inbox"

function Write-InboxLog {
  param($Msg)
  try { Add-Content -LiteralPath (Join-Path $PSScriptRoot 'data\alert_inbox.log') -Value ('{0} {1}' -f ([DateTime]::UtcNow.ToString('o'), $Msg)) -Encoding UTF8 } catch { }
}

$mutex = New-Object System.Threading.Mutex($false, 'cipher-alert-inbox-write')
Write-InboxLog 'inbox starting'
while ($true) {
  $client = $null
  $stream = $null
  try {
    $client = $listener.AcceptTcpClient()
    $stream = $client.GetStream()
    $hdr = Read-Headers -S $stream
    if ($hdr.Length -eq 0) { continue }
    $len = 0
    if ($hdr -match '(?im)^Content-Length:\s*(\d+)') { $len = [int]$Matches[1] }
    $body = ''
    if ($len -gt 0) {
      $buf = New-Object byte[] $len
      $got = 0
      while ($got -lt $len) {
        $nr = $stream.Read($buf, $got, $len - $got)
        if ($nr -le 0) { break }
        $got += $nr
      }
      if ($got -gt 0) { $body = [System.Text.Encoding]::UTF8.GetString($buf, 0, $got) }
    }
    if ($body.Length -gt 0) {
      $stamp = [DateTime]::UtcNow.ToString('o')
      $parsed = $body
      try { $null = $body | ConvertFrom-Json -ErrorAction Stop } catch { $esc = ($body -replace '\\','\\\\' -replace '"','\"' -replace "`r",'' -replace "`n",''); $parsed = '{"raw":"' + $esc + '"}' }
      $line2write = '{{"received_at":"{0}","content_type":"application/json","payload":{1}}}' -f $stamp, $parsed
      $mutex.WaitOne() | Out-Null
      try { Add-Content -LiteralPath $inbox -Value $line2write -Encoding UTF8 } finally { $mutex.ReleaseMutex() }
    }
    $resp = '{"received":true,"stored_at":"' + ([DateTime]::UtcNow.ToString('o')) + '"}'
    $respBytes = [System.Text.Encoding]::UTF8.GetBytes($resp)
    $head = [System.Text.Encoding]::ASCII.GetBytes('HTTP/1.1 200 OK' + "`r`n" + 'Content-Type: application/json' + "`r`n" + 'Content-Length: ' + $respBytes.Length + "`r`n`r`n")
    $stream.Write($head, 0, $head.Length)
    $stream.Write($respBytes, 0, $respBytes.Length)
    $stream.Flush()
  } catch {
    Write-InboxLog ('ERR ' + $_.Exception.Message)
    try {
      if ($stream) {
        $head2 = [System.Text.Encoding]::ASCII.GetBytes('HTTP/1.1 500 Error' + "`r`n" + 'Content-Length: 0' + "`r`n`r`n")
        $stream.Write($head2, 0, $head2.Length); $stream.Flush()
      }
    } catch { }
  } finally {
    if ($client) { try { $client.Close() } catch { } }
  }
}