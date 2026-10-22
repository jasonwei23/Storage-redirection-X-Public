sync_monitor_collector() {
  # FileMonitorOp 由 srx_daemon 中的私有 socket 接收器写入。
  stop_collector_by_pid_file "$MONITOR_COLLECTOR_PID_FILE"
}

# sync 看门狗：周期性把 debug 采集器收敛到当前 verbose 判定。
#
# 背景：sync 的驱动源只有 boot 与 config 事件两处，而反馈设备实测「boot 首个 sync
# 判定 verbose=off 后，配置翻转再无事件到达」——采集器整个 boot 静默。sync 已
# 幂等化（状态一致且存活即跳过），这里周期兜底不会有重启抖动；顺带自愈采集器
# 意外死亡。间隔 60 秒：一轮判定只是读一个文件 + 一次 kill -0，开销可忽略。
start_sync_watchdog() {
  if is_process_alive "$(cat "$SYNC_WATCHDOG_PID_FILE" 2>/dev/null)"; then
    return 0
  fi
  rm -f "$SYNC_WATCHDOG_PID_FILE"
  (
    while true; do
      sleep 60
      if command -v sync_debug_collectors >/dev/null 2>&1; then
        sync_debug_collectors
      fi
    done
  ) &
  echo "$!" > "$SYNC_WATCHDOG_PID_FILE"
  chmod 644 "$SYNC_WATCHDOG_PID_FILE" 2>/dev/null || true
}

start_log_collectors() {
  ensure_log_files
  stop_collector_by_pid_file "$MONITOR_COLLECTOR_PID_FILE"
  stop_collector_by_pid_file "$CONFIG_EVENT_COLLECTOR_PID_FILE"
  stop_collector_by_pid_file "$PACKAGE_EVENT_COLLECTOR_PID_FILE"
  start_config_event_collector
  start_package_event_collector
  if command -v sync_debug_collectors >/dev/null 2>&1; then
    sync_debug_collectors
  fi
  if command -v start_app_error_ring_collector >/dev/null 2>&1; then
    start_app_error_ring_collector
  fi
  start_sync_watchdog
}
