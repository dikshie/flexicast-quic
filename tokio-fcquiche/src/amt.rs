//! Safe asynchronous Rust wrapper around `libamt` (`amt.h` / `libamt.a`).

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::unix::io::RawFd;
use std::ptr::NonNull;
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

#[repr(C)]
struct amt_gateway_t {
    _private: [u8; 0],
}

extern "C" {
    fn amt_gateway_open(
        relay: *const libc::sockaddr,
        relay_len: libc::socklen_t,
        group: *const libc::sockaddr,
        group_len: libc::socklen_t,
        source: *const libc::sockaddr,
        source_len: libc::socklen_t,
        ssm: libc::c_int,
        timeout_ms: libc::c_int,
        retries: libc::c_int,
    ) -> *mut amt_gateway_t;

    fn amt_gateway_fd(gw: *const amt_gateway_t) -> libc::c_int;
    fn amt_gateway_next_timeout_ms(gw: *const amt_gateway_t) -> libc::c_int;
    fn amt_gateway_timeout(gw: *mut amt_gateway_t) -> libc::c_int;

    fn amt_gateway_recv(
        gw: *mut amt_gateway_t,
        from: *mut libc::sockaddr_storage,
        from_len: *mut libc::socklen_t,
        to: *mut libc::sockaddr_storage,
        to_len: *mut libc::socklen_t,
        ttl: *mut libc::c_int,
        buf: *mut u8,
        buflen: libc::size_t,
    ) -> libc::ssize_t;

    fn amt_gateway_close(gw: *mut amt_gateway_t);
}

struct RawAmtHandle(NonNull<amt_gateway_t>);

// Safety: `amt_gateway_t` owns its socket fd and internal state without thread-local
// dependencies, and is only ever accessed mutably from one task at a time.
unsafe impl Send for RawAmtHandle {}

/// Asynchronous handle to an AMT (RFC 7450) gateway tunnel.
pub struct AmtGateway {
    gw: NonNull<amt_gateway_t>,
    async_fd: Option<AsyncFd<RawFd>>,
}

// Safety: `AmtGateway` wraps `RawAmtHandle` + `AsyncFd<RawFd>` and requires `&mut self`
// for all mutating I/O operations.
unsafe impl Send for AmtGateway {}

impl AmtGateway {
    /// Opens an AMT tunnel to `relay` and joins `group` (optionally SSM from `source`).
    ///
    /// Runs the synchronous AMT handshake on a blocking thread pool task, then
    /// switches the underlying UDP socket to non-blocking mode for Tokio `AsyncFd`.
    pub async fn open(
        relay: SocketAddr,
        group: SocketAddr,
        source: Option<SocketAddr>,
        ssm: bool,
        timeout_ms: i32,
        retries: i32,
    ) -> io::Result<Self> {
        let handle = tokio::task::spawn_blocking(move || {
            let relay_sa = socket2::SockAddr::from(relay);
            let group_sa = socket2::SockAddr::from(group);
            let source_sa = source.map(socket2::SockAddr::from);

            let (src_ptr, src_len) = match source_sa.as_ref() {
                Some(sa) => (sa.as_ptr() as *const libc::sockaddr, sa.len() as libc::socklen_t),
                None => (std::ptr::null(), 0),
            };

            let ptr = unsafe {
                amt_gateway_open(
                    relay_sa.as_ptr() as *const libc::sockaddr,
                    relay_sa.len() as libc::socklen_t,
                    group_sa.as_ptr() as *const libc::sockaddr,
                    group_sa.len() as libc::socklen_t,
                    src_ptr,
                    src_len,
                    if ssm { 1 } else { 0 },
                    timeout_ms as libc::c_int,
                    retries as libc::c_int,
                )
            };

            NonNull::new(ptr).map(RawAmtHandle).ok_or_else(io::Error::last_os_error)
        })
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))??;

        let fd = unsafe { amt_gateway_fd(handle.0.as_ptr()) };
        if fd < 0 {
            unsafe { amt_gateway_close(handle.0.as_ptr()) };
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "amt_gateway_fd returned invalid fd",
            ));
        }

        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            let err = io::Error::last_os_error();
            unsafe { amt_gateway_close(handle.0.as_ptr()) };
            return Err(err);
        }

        let async_fd = match AsyncFd::with_interest(fd, Interest::READABLE) {
            Ok(afd) => afd,
            Err(e) => {
                unsafe { amt_gateway_close(handle.0.as_ptr()) };
                return Err(e);
            },
        };

        Ok(Self {
            gw: handle.0,
            async_fd: Some(async_fd),
        })
    }

    /// Waits for and reads the next decapsulated multicast UDP payload.
    ///
    /// AMT control traffic (e.g., Membership Queries) is handled transparently.
    pub async fn recv(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, SocketAddr)> {
        loop {
            let mut guard = self
                .async_fd
                .as_ref()
                .expect("async_fd missing")
                .readable()
                .await?;

            match try_recv_raw(self.gw.as_ptr(), buf) {
                Ok(Some(pkt)) => return Ok(pkt),
                Ok(None) => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    guard.clear_ready();
                    continue;
                },
                Err(e) => return Err(e),
            }
        }
    }

    /// Non-blocking attempt to read one decapsulated multicast payload.
    ///
    /// Returns `Ok(None)` if a control-plane AMT message was consumed internally,
    /// or `Err(WouldBlock)` if no datagram is currently available.
    pub fn try_recv(
        &mut self,
        buf: &mut [u8],
    ) -> io::Result<Option<(usize, SocketAddr, SocketAddr)>> {
        try_recv_raw(self.gw.as_ptr(), buf)
    }

    /// Duration until the next proactive AMT refresh (`amt_gateway_timeout`) is due.
    pub fn next_timeout(&self) -> Duration {
        let ms = unsafe { amt_gateway_next_timeout_ms(self.gw.as_ptr()) };
        Duration::from_millis(ms.max(0) as u64)
    }

    /// Sends a proactive AMT Request to refresh membership state at the relay.
    pub fn on_timeout(&mut self) -> io::Result<()> {
        let rc = unsafe { amt_gateway_timeout(self.gw.as_ptr()) };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

impl Drop for AmtGateway {
    fn drop(&mut self) {
        // Deregister fd from Tokio reactor before `amt_gateway_close` closes it.
        self.async_fd.take();
        unsafe {
            amt_gateway_close(self.gw.as_ptr());
        }
    }
}

fn try_recv_raw(
    gw: *mut amt_gateway_t,
    buf: &mut [u8],
) -> io::Result<Option<(usize, SocketAddr, SocketAddr)>> {
    let mut from_ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut to_ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut from_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let mut to_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let mut ttl: libc::c_int = 0;

    let n = unsafe {
        amt_gateway_recv(
            gw,
            &mut from_ss,
            &mut from_len,
            &mut to_ss,
            &mut to_len,
            &mut ttl,
            buf.as_mut_ptr(),
            buf.len(),
        )
    };

    if n > 0 {
        let from = unsafe { sockaddr_storage_to_std(&from_ss, from_len)? };
        let to = unsafe { sockaddr_storage_to_std(&to_ss, to_len)? };
        Ok(Some((n as usize, from, to)))
    } else if n == 0 {
        Ok(None)
    } else {
        Err(io::Error::last_os_error())
    }
}

unsafe fn sockaddr_storage_to_std(
    ss: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> io::Result<SocketAddr> {
    let family = ss.ss_family as libc::c_int;
    if family == libc::AF_INET && (len as usize) >= std::mem::size_of::<libc::sockaddr_in>() {
        let sin = &*(ss as *const libc::sockaddr_storage as *const libc::sockaddr_in);
        let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
        let port = u16::from_be(sin.sin_port);
        Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
    } else if family == libc::AF_INET6
        && (len as usize) >= std::mem::size_of::<libc::sockaddr_in6>()
    {
        let sin6 = &*(ss as *const libc::sockaddr_storage as *const libc::sockaddr_in6);
        let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
        let port = u16::from_be(sin6.sin6_port);
        Ok(SocketAddr::V6(SocketAddrV6::new(
            ip,
            port,
            sin6.sin6_flowinfo,
            sin6.sin6_scope_id,
        )))
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported sockaddr family: {}", family),
        ))
    }
}
