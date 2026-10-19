use super::companion_mount::execute_companion_mount_request;
use super::companion_request::{CompanionMountRequest, parse_companion_mount_request};
use crate::logging::Logger;
use crate::platform::fs;
use libc::{SIG_IGN, SIGPIPE, c_int, signal};
use std::time::Duration;

const MAX_PAYLOAD_BYTES: u32 = 1024 * 1024;
// 伴生进程单次请求的读取超时：对端异常挂起时不能让伴生进程被永久占用
const READ_TIMEOUT: Duration = Duration::from_secs(10);

// 伴生进程主流程：读取请求、解析、执行挂载、返回状态
pub fn run_companion_pipeline(client_fd: c_int) {
    Logger::init(Some("zygisk_companion"));

    unsafe {
        signal(SIGPIPE, SIG_IGN);
    }

    // 协议 v2：首字节为请求类型；'M' 为挂载请求（其后为旧的长度+JSON 负载），
    // 'F' 为 fchown 请求（fd 经 SCM_RIGHTS 传递）。与挂载请求合并连接后按
    // 类型分发，两端同仓库同版本升级，无兼容包袱。
    let mut request_type = [0u8; 1];
    if !fs::read_all_timeout(client_fd, &mut request_type, READ_TIMEOUT) {
        log::error!("request type read failed");
        return;
    }
    match request_type[0] {
        b'F' => {
            handle_fchown_request(client_fd);
        }
        b'M' => {
            handle_mount_request(client_fd);
        }
        other => {
            log::error!("unknown request type 0x{:02x}", other);
            write_status(client_fd, 0);
        }
    }
}

/// 处理 fchown 请求：recvmsg 收 4 字节 uid 与 SCM_RIGHTS 携带的 fd，以 root
/// 身份 fchown 后回写状态。fd 由 MP hook 在 open:create 应答前传递，文件在
/// 应用拿到 fd 之前即为正确属主。
fn handle_fchown_request(client_fd: c_int) {
    let mut uid_buffer = [0u8; 4];
    let mut fd_buffer = [-1i32; 1];
    // SAFETY: uid_buffer/fd_buffer 为栈上有效缓冲；msg 名称为空，iovec 指向
    // uid_buffer；control 缓冲用于内核写入 SCM_RIGHTS。
    let received = unsafe {
        let iov = libc::iovec {
            iov_base: uid_buffer.as_mut_ptr() as *mut libc::c_void,
            iov_len: uid_buffer.len(),
        };
        // SAFETY: CMSG_SPACE 为纯常量计算，无运行时副作用。
        let mut cmsg_buffer =
            [0u8; unsafe { libc::CMSG_SPACE(std::mem::size_of::<c_int>() as u32) } as usize];
        let mut msg: libc::msghdr = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &iov as *const libc::iovec as *mut libc::iovec,
            msg_iovlen: 1,
            msg_control: cmsg_buffer.as_mut_ptr() as *mut libc::c_void,
            msg_controllen: cmsg_buffer.len(),
            msg_flags: 0,
        };
        let received = libc::recvmsg(client_fd, &mut msg, 0);
        if received < 0 {
            false
        } else {
            let mut received_fd = -1i32;
            let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
            while !cmsg.is_null() {
                if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                    let available = ((*cmsg).cmsg_len as usize - libc::CMSG_LEN(0) as usize)
                        / std::mem::size_of::<c_int>();
                    if available >= 1 {
                        std::ptr::copy_nonoverlapping(
                            libc::CMSG_DATA(cmsg) as *const c_int,
                            fd_buffer.as_mut_ptr(),
                            1,
                        );
                        received_fd = fd_buffer[0];
                    }
                }
                cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
            }
            let _ = received_fd;
            received_fd >= 0
        }
    };
    if !received {
        log::error!("fchown request fd receive failed");
        write_status(client_fd, 0);
        return;
    }
    let uid = i32::from_ne_bytes(uid_buffer);
    if uid < 0 {
        log::error!("fchown request uid invalid uid={}", uid);
        write_status(client_fd, 0);
        return;
    }
    // SAFETY: fd_buffer[0] 为对端经 SCM_RIGHTS 传入的本进程 fd，fchown 后关闭。
    let result = unsafe { libc::fchown(fd_buffer[0], uid as u32, u32::MAX) };
    // SAFETY: 同上，fd 归本进程所有。
    unsafe { libc::close(fd_buffer[0]) };
    if result == 0 {
        log::info!("companion fchown ok uid={}", uid);
    } else {
        log::warn!(
            "companion fchown failed uid={} errno={}",
            uid,
            crate::platform::errno::last()
        );
    }
    write_status(client_fd, if result == 0 { 1 } else { 0 });
}

fn handle_mount_request(client_fd: c_int) {
    let payload_len = match read_payload_length(client_fd) {
        Some(len) => len,
        None => {
            log::error!("payload length read failed");
            return;
        }
    };

    if payload_len == 0 || payload_len > MAX_PAYLOAD_BYTES {
        log::error!("payload length invalid len={}", payload_len);
        write_status(client_fd, 0);
        return;
    }
    log::debug!("payload len={}", payload_len);

    let payload = match read_payload_data(client_fd, payload_len) {
        Some(data) => data,
        None => {
            log::error!("payload read failed");
            write_status(client_fd, 0);
            return;
        }
    };

    let request = match parse_companion_mount_request(&payload) {
        Ok(req) => req,
        Err(err) => {
            log::error!("request parse failed err={}", err);
            write_status(client_fd, 0);
            return;
        }
    };

    if !request.package_name.is_empty() {
        Logger::init(Some(&request.package_name));
    }

    log_mount_request(&request);

    let status = if execute_companion_mount_request(&request) {
        1
    } else {
        0
    };
    write_status(client_fd, status);
}

fn read_payload_length(client_fd: c_int) -> Option<u32> {
    let mut buffer = [0u8; 4];
    if !fs::read_all_timeout(client_fd, &mut buffer, READ_TIMEOUT) {
        log::warn!("read length failed fd={}", client_fd);
        return None;
    }
    Some(u32::from_ne_bytes(buffer))
}

// 按长度读取负载并强制 UTF-8 解码
fn read_payload_data(client_fd: c_int, payload_len: u32) -> Option<String> {
    let mut buffer = vec![0u8; payload_len as usize];
    if !fs::read_all_timeout(client_fd, &mut buffer, READ_TIMEOUT) {
        log::warn!("read payload failed fd={} len={}", client_fd, payload_len);
        return None;
    }
    match String::from_utf8(buffer) {
        Ok(text) => Some(text),
        Err(_) => {
            log::warn!("payload not utf8 fd={} len={}", client_fd, payload_len);
            None
        }
    }
}

fn write_status(client_fd: c_int, status: i32) {
    let _ = fs::write_all(client_fd, &status.to_ne_bytes());
}

fn log_mount_request(request: &CompanionMountRequest) {
    log::info!(
        "req op=apply pid={} pkg={} allow={} excl={} sandbox={} ro={} map={} map_only={} file_monitor={} version={:x}",
        request.pid,
        request.package_name,
        request.allowed_real_paths.len(),
        request.excluded_real_paths.len(),
        request.sandboxed_paths.len(),
        request.read_only_paths.len(),
        request.path_mappings.len(),
        request.is_mapping_mode_only,
        request.is_file_monitor_enabled,
        request.config_version
    );

    if !request.allowed_real_paths.is_empty() {
        for path in &request.allowed_real_paths {
            log::info!("req allow={}", path);
        }
    }
    if !request.excluded_real_paths.is_empty() {
        for path in &request.excluded_real_paths {
            log::info!("req excl={}", path);
        }
    }
    if !request.sandboxed_paths.is_empty() {
        for path in &request.sandboxed_paths {
            log::info!("req sandbox={}", path);
        }
    }
    if !request.read_only_paths.is_empty() {
        for path in &request.read_only_paths {
            log::info!("req readonly={}", path);
        }
    }
    if !request.path_mappings.is_empty() {
        for mapping in &request.path_mappings {
            log::info!("req map {} -> {}", mapping.request_path, mapping.final_path);
        }
    }
}
