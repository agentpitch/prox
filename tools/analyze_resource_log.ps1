param(
    [Parameter(Mandatory = $true)]
    [string]$Path
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Path)) {
    throw "Log not found: $Path"
}

$samples = Get-Content -LiteralPath $Path | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json }
if (-not $samples -or $samples.Count -lt 2) {
    throw "Need at least two samples"
}

function MB($bytes) {
    [math]::Round(([double]$bytes / 1MB), 2)
}

function Num($value) {
    if ($null -eq $value) { return 0.0 }
    [double]$value
}

function Delta($first, $last, $selector) {
    (Num (& $selector $last)) - (Num (& $selector $first))
}

function MaxValue($items, $selector) {
    $max = $null
    foreach ($item in $items) {
        $value = Num (& $selector $item)
        if ($null -eq $max -or $value -gt $max) {
            $max = $value
        }
    }
    if ($null -eq $max) { return 0 }
    return $max
}

$first = $samples[0]
$last = $samples[-1]
$duration = ([datetime]$last.time - [datetime]$first.time).TotalSeconds
$cpuMs = (Delta $first $last { param($x) $x.os.user_time_ms }) + (Delta $first $last { param($x) $x.os.kernel_time_ms })
$cpuPctOneCore = if ($duration -gt 0) { [math]::Round(($cpuMs / 1000.0) / $duration * 100.0, 3) } else { 0 }
$logFile = Get-Item -LiteralPath $Path
$profiles = @($samples | ForEach-Object { if ($_.profiles) { $_.profiles } })
$handleTypeSamples = @($samples | Where-Object { $_.os.handle_types })
$latestHandleTypes = if ($handleTypeSamples.Count -gt 0) { $handleTypeSamples[-1].os.handle_types } else { $null }
$latestHandleTypesText = if ($latestHandleTypes) {
    @($latestHandleTypes.PSObject.Properties |
        Sort-Object Name |
        ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ', '
} else {
    $null
}

$rows = [ordered]@{
    samples = $samples.Count
    duration_seconds = [math]::Round($duration, 1)
    log_mb = MB $logFile.Length
    avg_sample_bytes = [math]::Round($logFile.Length / [double]$samples.Count, 1)
    private_mb_start = MB $first.os.private_bytes
    private_mb_end = MB $last.os.private_bytes
    private_mb_delta = MB (Delta $first $last { param($x) $x.os.private_bytes })
    working_set_mb_start = MB $first.os.working_set_bytes
    working_set_mb_end = MB $last.os.working_set_bytes
    working_set_mb_delta = MB (Delta $first $last { param($x) $x.os.working_set_bytes })
    handles_start = $first.os.handle_count
    handles_end = $last.os.handle_count
    handles_delta = Delta $first $last { param($x) $x.os.handle_count }
    gdi_handles_delta = Delta $first $last { param($x) $x.os.gdi_handle_count }
    user_handles_delta = Delta $first $last { param($x) $x.os.user_handle_count }
    heap_alloc_mb_start = MB $first.go.heap_alloc_bytes
    heap_alloc_mb_end = MB $last.go.heap_alloc_bytes
    heap_alloc_mb_delta = MB (Delta $first $last { param($x) $x.go.heap_alloc_bytes })
    heap_released_mb_delta = MB (Delta $first $last { param($x) $x.go.heap_released_bytes })
    heap_objects_delta = Delta $first $last { param($x) $x.go.heap_objects }
    goroutines_start = $first.goroutines
    goroutines_end = $last.goroutines
    goroutines_delta = Delta $first $last { param($x) $x.goroutines }
    gc_count_delta = Delta $first $last { param($x) $x.go.num_gc }
    cpu_pct_one_core_avg = $cpuPctOneCore
    write_mb_delta = MB (Delta $first $last { param($x) $x.os.write_transfer_bytes })
    read_mb_delta = MB (Delta $first $last { param($x) $x.os.read_transfer_bytes })
    handle_type_samples = $handleTypeSamples.Count
    latest_handle_types = $latestHandleTypesText
    interception_enabled = $last.app.interception_enabled
    flow_table_len_start = Num $first.app.flow_table_len
    flow_table_len_end = Num $last.app.flow_table_len
    flow_table_len_delta = Delta $first $last { param($x) $x.app.flow_table_len }
    flow_table_len_max = MaxValue $samples { param($x) $x.app.flow_table_len }
    monitor_active_start = Num $first.app.monitor.active_connections
    monitor_active_end = Num $last.app.monitor.active_connections
    monitor_active_delta = Delta $first $last { param($x) $x.app.monitor.active_connections }
    monitor_active_max = MaxValue $samples { param($x) $x.app.monitor.active_connections }
    monitor_traffic_buckets_end = Num $last.app.monitor.traffic_live_buckets
    monitor_traffic_buckets_max = MaxValue $samples { param($x) $x.app.monitor.traffic_live_buckets }
    monitor_subscribers_end = Num $last.app.monitor.subscribers
    monitor_subscribers_max = MaxValue $samples { param($x) $x.app.monitor.subscribers }
    history_pending_logs_max = MaxValue $samples { param($x) $x.app.monitor.history.pending_logs }
    history_pending_connections_max = MaxValue $samples { param($x) $x.app.monitor.history.pending_connections }
    history_pending_traffic_buckets_max = MaxValue $samples { param($x) $x.app.monitor.history.pending_traffic_buckets }
    history_pending_rule_buckets_max = MaxValue $samples { param($x) $x.app.monitor.history.pending_rule_buckets }
    profiles_written = $profiles.Count
    latest_profile = if ($profiles.Count -gt 0) { $profiles[-1] } else { $null }
}

[pscustomobject]$rows | Format-List

$tail = $samples | Select-Object -Last ([math]::Min(10, $samples.Count))
$tail | Select-Object time,
    @{Name='private_mb';Expression={MB $_.os.private_bytes}},
    @{Name='working_set_mb';Expression={MB $_.os.working_set_bytes}},
    @{Name='handles';Expression={$_.os.handle_count}},
    @{Name='heap_alloc_mb';Expression={MB $_.go.heap_alloc_bytes}},
    @{Name='heap_objects';Expression={$_.go.heap_objects}},
    goroutines,
    @{Name='num_gc';Expression={$_.go.num_gc}},
    @{Name='flows';Expression={$_.app.flow_table_len}},
    @{Name='active';Expression={$_.app.monitor.active_connections}},
    @{Name='traffic_buckets';Expression={$_.app.monitor.traffic_live_buckets}},
    @{Name='hist_pending';Expression={(Num $_.app.monitor.history.pending_logs) + (Num $_.app.monitor.history.pending_connections) + (Num $_.app.monitor.history.pending_traffic_buckets) + (Num $_.app.monitor.history.pending_rule_buckets)}},
    @{Name='profiles';Expression={if ($_.profiles) { $_.profiles.Count } else { 0 }}} |
    Format-Table -AutoSize
