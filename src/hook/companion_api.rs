// MP 进程内的 companion 桥：root 侧 companion 代执行需要特权的操作。
//
// 背景（真机 2026-10-18）：MediaProvider 以普通 uid 运行、无 CAP_CHOWN，
// 进程内 lchown 对代写产生的 media_rw 属主条目必然 EPERM；detached 扫描/
// 普查类方案都属于事后遍历。companion 是 zygisk 的 root 常驻进程，fd 经
// SCM_RIGHTS 传递后可即时 fchown——文件在应用拿到 fd 之前就是正确属主，
// 无扫描、无竞态、无修复窗口。
use crate::zygisk::abi;
use std::os::unix::io::RawFd;
use std::sync::OnceLock;

use libc::c_int;

struct CompanionApi(abi::Api);
// SAFETY: api 的 table 指针由 zygisk 框架提供且进程生命周期内有效（MP 进程
// 不 dlclose 模块），跨线程调用仅触达 zygisk 的线程安全入口。
unsafe impl Send for CompanionApi {}
unsafe impl Sync for CompanionApi {}

static MP_API: OnceLock<CompanionApi> = OnceLock::new();

/// 保存 zygisk api 以供 hook 运行期连接 companion（on_load 时调用一次）。
pub fn save_companion_api(api: &abi::Api) {
    let _ = MP_API.set(CompanionApi(*api));
}

fn connect_companion() -> Option<RawFd> {
    let api = MP_API.get()?;
    let fd = api.0.connect_companion();
    if fd < 0 {
        return None;
    }
    Some(fd)
}

/// 请求 companion（root）把 `fd` 的属主改为 `uid`，同步等待结果。
///
/// 协议：1 字节类型 'F' → sendmsg 携带 SCM_RIGHTS(fd) 与 4 字节 uid →
/// companion fchown 后回写 4 字节状态。失败返回 false，调用方回退既有
/// 修复通道。
pub fn companion_fchown(fd: RawFd, uid: i32) -> bool {
    if fd < 0 || uid < 0 {
        return false;
    }
    let Some(sock) = connect_companion() else {
        return false;
    };
    let ok = (|| {
        // SAFETY: sock/fd 均为进程内有效 fd；iov 与 control 缓冲为栈上有效内存，
        // sendmsg 只读取它们。
        let sent = unsafe {
            let uid_bytes = uid.to_ne_bytes();
            let iov = libc::iovec {
                iov_base: uid_bytes.as_ptr() as *mut libc::c_void,
                iov_len: uid_bytes.len(),
            };
            // ancillary：SCM_RIGHTS 携带 fd
            // SAFETY: CMSG_SPACE 为纯常量计算，无运行时副作用。
            let mut cmsg_buffer =
                [0u8; unsafe { libc::CMSG_SPACE(std::mem::size_of::<c_int>() as u32) } as usize];
            let msg: libc::msghdr = libc::msghdr {
                msg_name: std::ptr::null_mut(),
                msg_namelen: 0,
                msg_iov: &iov as *const libc::iovec as *mut libc::iovec,
                msg_iovlen: 1,
                msg_control: cmsg_buffer.as_mut_ptr() as *mut libc::c_void,
                msg_controllen: cmsg_buffer.len(),
                msg_flags: 0,
            };
            // 填充 SCM_RIGHTS
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            if cmsg.is_null() {
                return false;
            }
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<c_int>() as u32) as usize;
            std::ptr::copy_nonoverlapping(
                &fd as *const c_int as *const u8,
                libc::CMSG_DATA(cmsg),
                std::mem::size_of::<c_int>(),
            );
            let _ = libc::signal(libc::SIGPIPE, libc::SIG_IGN);
            let type_byte: u8 = b'F';
            let header = libc::iovec {
                iov_base: &type_byte as *const u8 as *mut libc::c_void,
                iov_len: 1,
            };
            let msg2: libc::msghdr = libc::msghdr {
                msg_name: std::ptr::null_mut(),
                msg_namelen: 0,
                msg_iov: &header as *const libc::iovec as *mut libc::iovec,
                msg_iovlen: 1,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
            };
            if libc::sendmsg(sock, &msg2, 0) != 1 {
                return false;
            }
            libc::sendmsg(sock, &msg, 0) >= 0
        };
        if !sent {
            return false;
        }
        let mut ack = [0u8; 4];
        // SAFETY: ack 为栈上缓冲，read 只写入它。
        crate::platform::fs::read_all_timeout(sock, &mut ack, std::time::Duration::from_secs(5))
            && i32::from_ne_bytes(ack) == 1
    })();
    // SAFETY: sock 为本函数 connect 返回的 fd，使用完毕关闭。
    unsafe { libc::close(sock) };
    ok
}
