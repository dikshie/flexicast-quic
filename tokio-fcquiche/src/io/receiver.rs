//! Flexicast QUIC receiver wrapped in tokio.

use crate::amt::AmtGateway;
use crate::Result;
use log::*;
use quiche::flexicast::FlexicastConnection;
use quiche::flexicast::McClientStatus;
use quiche::flexicast::McRole;
use quiche::h3::Connection as H3Conn;
use quiche::h3::Header;
use quiche::Config;
use quiche::ConnectionId;
use ring::rand::SecureRandom;
use ring::rand::SystemRandom;
use std::net;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::FcQuicMsg;
use crate::CHANNEL_BUFFER_SIZE;
use crate::MAX_DATAGRAM_SIZE;

#[cfg(feature = "qlog")]
use crate::make_qlog_writer;

/// Creates a Flexicast QUIC receiver using tokio.
pub struct TokioFcQuicRecv {
    /// QUIC configuration.
    config: Config,

    /// Local IP to bind to multicast.
    local_ip: Ipv4Addr,

    /// Whether to perform flexicast.
    flexicast: bool,

    /// Transmission channel to send data from QUIC to the app.
    tx_app: mpsc::Sender<FcQuicMsg>,

    /// Reception channel to receive data from the app to QUIC.
    rx_app: mpsc::Receiver<FcQuicMsg>,

    /// Address of the server to contact.
    peer_addr: SocketAddr,

    /// Whether we do unicast proxy.
    proxy_uc: bool,

    h3_config: Option<quiche::h3::Config>,

    /// Potential HTTP/3 request state on the receiver.
    h3_conn: Option<H3Conn>,

    /// Potential HTTP/3 pending request.
    h3_pending_request: Option<Vec<Header>>,

    /// Whether AMT fallback is allowed when native multicast packets do not arrive.
    amt_fallback_allowed: bool,

    /// Optional AMT relay IPv4 address.
    amt_relay_ip: Option<Ipv4Addr>,

    /// Delay without native multicast packets before falling back to AMT.
    amt_fallback_delay: Duration,
}

impl TokioFcQuicRecv {
    /// Creates a new instance.
    pub fn new(
        peer_addr: SocketAddr, config: Config, local_ip: Ipv4Addr,
        flexicast: bool, proxy_uc: bool, rx_from_app: mpsc::Receiver<FcQuicMsg>,
        h3_config: Option<quiche::h3::Config>, amt_fallback_allowed: bool,
        amt_relay_ip: Option<Ipv4Addr>,
    ) -> (Self, mpsc::Receiver<FcQuicMsg>) {
        let (tx_app, rx_app) = mpsc::channel(CHANNEL_BUFFER_SIZE);
        (
            Self {
                peer_addr,
                config,
                local_ip,
                flexicast,
                tx_app,
                rx_app: rx_from_app,
                proxy_uc,
                h3_config,
                h3_conn: None,
                h3_pending_request: None,
                amt_fallback_allowed,
                amt_relay_ip,
                amt_fallback_delay: Duration::from_millis(750),
            },
            rx_app,
        )
    }

    /// Overrides the inactivity timeout before falling back to AMT.
    pub fn with_amt_fallback_delay(mut self, delay: Duration) -> Self {
        self.amt_fallback_delay = delay;
        self
    }

    /// Asynchronously runs the Flexicast QUIC receiver, sending data to the
    /// application.
    pub async fn run(&mut self) -> crate::Result<()> {
        let mut buf = [0; 65535];
        let mut mc_buf = [0; 65535];
        let mut amt_buf = [0; 65535];
        let mut out = [0; MAX_DATAGRAM_SIZE];

        // Creation of the flexicast path.
        let mut added_mc_cid = false;
        let mut probe_mc_path = false;

        let mut mc_socket_opt: Option<UdpSocket> = None;
        let mut joined_mc_ip = false;
        let mc_addr: SocketAddr = "0.0.0.0:4433".parse()?;

        // AMT fallback state.
        let mut amt_gw: Option<AmtGateway> = None;
        let mut amt_fallback_deadline: Option<tokio::time::Instant> = None;
        let mut mc_group_info: Option<(Ipv4Addr, Ipv4Addr, u16, bool)> = None;

        // Create the UDP socket backing the QUIC connection.
        let bind_addr: std::net::SocketAddr = "0.0.0.0:0".parse()?;
        let mut socket = UdpSocket::bind(bind_addr).await?;
        let local_addr = socket.local_addr()?;

        // Generate a random source connection ID for the connection.
        let mut scid = [0; 16];
        let random = SystemRandom::new();
        random.fill(&mut scid[..]).unwrap();

        let scid = quiche::ConnectionId::from_ref(&scid);
        // Create a QUIC connection and initiate handshake.
        let mut conn = quiche::connect(
            None,
            &scid,
            local_addr,
            self.peer_addr,
            &mut self.config,
        )?;

        // Stream ID of the HTTP/3 request.
        let mut _h3_stream_id: Option<u64> = None;

        // Only bother with qlog if the user specified it.
        #[cfg(feature = "qlog")]
        {
            if let Some(dir) = std::env::var_os("QLOGDIR") {
                let id = format!("Client-{}", self.local_ip.to_string());
                let writer = make_qlog_writer(&dir, "client", &id);

                conn.set_qlog(
                    std::boxed::Box::new(writer),
                    "quiche-client qlog".to_string(),
                    format!("{} id={}", "quiche-client qlog", id),
                );
            }
        }

        info!(
            "connecting to {:} from {:} with scid {}",
            self.peer_addr,
            socket.local_addr()?,
            hex_dump(&scid)
        );

        let (write, send_info) =
            conn.send(&mut out).expect("initial send failed");
        socket.send_to(&out[..write], send_info.to).await?;

        loop {
            let timeout = conn.timeout();
            let amt_timeout = amt_gw
                .as_ref()
                .map(|gw| gw.next_timeout().max(Duration::from_millis(10)));
            let mut read_uc = false;
            let mut read_mc = false;
            let mut read_amt = false;
            let mut trigger_amt_fallback = false;

            tokio::select! {
                Some(_) = optional_timeout(timeout) => {
                    conn.on_timeout();
                },

                Ok((len, from)) = socket.recv_from(&mut buf) => {
                    let recv_info = quiche::RecvInfo {
                        to: socket.local_addr()?,
                        from,
                        from_mc: false,
                    };
                    conn.recv(&mut buf[..len], recv_info)?;
                    read_uc = true;
                },

                Ok((len, from)) = optional_recv_from(mc_socket_opt.as_ref(), &mut mc_buf), if mc_socket_opt.is_some() => {
                    if amt_gw.is_none() && self.amt_fallback_allowed && amt_fallback_deadline.is_some() {
                        amt_fallback_deadline = Some(tokio::time::Instant::now() + self.amt_fallback_delay);
                    }
                    let recv_info = quiche::RecvInfo {
                        to: mc_addr,
                        from: normalize_mc_from(from, mc_group_info),
                        from_mc: true,
                    };
                    conn.recv(&mut mc_buf[..len], recv_info)?;
                    read_mc = true;
                },

                res = optional_amt_recv(amt_gw.as_mut(), &mut amt_buf), if amt_gw.is_some() => {
                    match res {
                        Ok((len, from)) => {
                            let recv_info = quiche::RecvInfo {
                                to: mc_addr,
                                from: normalize_mc_from(from, mc_group_info),
                                from_mc: true,
                            };
                            conn.recv(&mut amt_buf[..len], recv_info)?;
                            read_amt = true;
                        },
                        Err(e) => {
                            warn!("AMT recv error: {}", e);
                        },
                    }
                },

                _ = optional_sleep_until(amt_fallback_deadline), if amt_fallback_deadline.is_some() && amt_gw.is_none() => {
                    amt_fallback_deadline = None;
                    trigger_amt_fallback = true;
                },

                _ = optional_sleep_delay(amt_timeout), if amt_timeout.is_some() => {
                    if let Some(gw) = amt_gw.as_mut() {
                        if let Err(e) = gw.on_timeout() {
                            warn!("AMT refresh timeout failed: {}", e);
                        } else {
                            debug!("AMT proactive refresh Request sent");
                        }
                    }
                },

                Some(msg) = self.rx_app.recv() => {
                    if self.recv_app_msg(msg)? {
                        conn.close(true, 0x00, b"bye")?;
                    }
                }
            }

            if trigger_amt_fallback {
                if let (Some(relay_ip), Some((group_ip, src_ip, udp_port, _))) = (self.amt_relay_ip, mc_group_info) {
                    info!(
                        "No native multicast packets received within {:?}; falling back to AMT relay {} for group {} (source {})",
                        self.amt_fallback_delay, relay_ip, group_ip, src_ip
                    );
                    let relay_addr = SocketAddr::V4(SocketAddrV4::new(relay_ip, 2268));
                    let group_addr = SocketAddr::V4(SocketAddrV4::new(group_ip, udp_port));
                    let source_addr = SocketAddr::V4(SocketAddrV4::new(src_ip, 0));
                    match AmtGateway::open(relay_addr, group_addr, Some(source_addr), true, 1000, 3).await {
                        Ok(gw) => {
                            info!(
                                "AMT tunnel established via relay {} for ({}, {}:{})",
                                relay_ip, src_ip, group_ip, udp_port
                            );
                            if let Some(mc_sock) = mc_socket_opt.take() {
                                if let Err(e) = mc_sock.leave_multicast_v4(group_ip, self.local_ip) {
                                    debug!("leave_multicast_v4({}) ignored: {}", group_ip, e);
                                }
                                info!("Left MULTICAST group {}", group_ip);
                                info!("Left multicast group after creating AMT gateway");
                            }
                            amt_gw = Some(gw);
                        },
                        Err(e) => {
                            error!("AMT fallback failed to open tunnel to {}: {}; will retry", relay_ip, e);
                            amt_fallback_deadline = Some(tokio::time::Instant::now() + Duration::from_secs(5));
                        },
                    }
                }
            }

            // Sets the HTTP/3 connection if a configuration was provided.
            if conn.is_established() && self.h3_conn.is_none() {
                if let Some(h3_config) = self.h3_config.as_ref() {
                    self.h3_conn =
                        Some(H3Conn::with_transport(&mut conn, h3_config)?);
                }
            }

            // Going out of the tokio select. Process all incomming packets at
            // once, avoiding costly sent of packets.
            let mut i = 0;
            let nb_read_max = 10;
            if read_uc {
                'uc_read: loop {
                    if let Ok((len, from)) = socket.try_recv_from(&mut buf) {
                        let recv_info = quiche::RecvInfo {
                            to: socket.local_addr()?,
                            from,
                            from_mc: false,
                        };
                        conn.recv(&mut buf[..len], recv_info)?;
                    } else {
                        break 'uc_read;
                    }
                    i += 1;
                    if i > nb_read_max {
                        debug!("READ {i} packets through UC. Going out...");
                        break;
                    }
                }
            }
            i = 0;
            if read_mc {
                if let Some(mc_socket) = mc_socket_opt.as_ref() {
                    'mc_read: loop {
                        if let Ok((len, from)) = mc_socket.try_recv_from(&mut buf)
                        {
                            if amt_gw.is_none() && self.amt_fallback_allowed && amt_fallback_deadline.is_some() {
                                amt_fallback_deadline = Some(tokio::time::Instant::now() + self.amt_fallback_delay);
                            }
                            let recv_info = quiche::RecvInfo {
                                to: mc_addr,
                                from: normalize_mc_from(from, mc_group_info),
                                from_mc: true,
                            };
                            conn.recv(&mut buf[..len], recv_info)?;
                        } else {
                            break 'mc_read;
                        }
                        i += 1;
                        if i > nb_read_max {
                            debug!("READ {i} packets through MC. Going out...");
                            break;
                        }
                    }
                }
            }
            i = 0;
            if read_amt {
                if let Some(gw) = amt_gw.as_mut() {
                    'amt_read: loop {
                        match gw.try_recv(&mut buf) {
                            Ok(Some((len, from, _to))) => {
                                let recv_info = quiche::RecvInfo {
                                    to: mc_addr,
                                    from: normalize_mc_from(from, mc_group_info),
                                    from_mc: true,
                                };
                                conn.recv(&mut buf[..len], recv_info)?;
                            },
                            Ok(None) => {
                                // Control message handled internally; keep draining.
                                continue;
                            },
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                break 'amt_read;
                            },
                            Err(e) => {
                                warn!("AMT try_recv error: {}", e);
                                break 'amt_read;
                            },
                        }
                        i += 1;
                        if i > nb_read_max {
                            debug!("READ {i} packets through AMT. Going out...");
                            break;
                        }
                    }
                }
            }

            // Process flexicast events.
            if conn.get_flexicast_attributes().is_some() && self.flexicast {
                // Join the flexicast channel and creates the listening socket if
                // not already done.
                if matches!(
                    conn.get_flexicast_attributes().unwrap().get_mc_role(),
                    McRole::Client(McClientStatus::AwareUnjoined) |
                        McRole::Client(McClientStatus::Changing)
                ) {
                    debug!("Client joins the flexicast channel.");

                    // Did not join the flexicast channel before.
                    let flexicast = conn.get_flexicast_attributes().unwrap();
                    let mc_announce_data =
                        flexicast.get_mc_announce_data(0).unwrap().to_owned();

                    // Add the new connection ID for the announce data.
                    if !added_mc_cid {
                        debug!("Add a new connection ID");
                        let scid =
                            ConnectionId::from_ref(&mc_announce_data.channel_id);
                        conn.add_mc_cid(&scid)?;
                    }

                    // Create a second path.
                    if !probe_mc_path && added_mc_cid {
                        debug!("Create the second path. Client addr={:?}. Server addr={:?}", mc_addr, self.peer_addr);
                        let src_ip = Ipv4Addr::from(mc_announce_data.source_ip);
                        let group_ip_v4 = Ipv4Addr::from(mc_announce_data.group_ip);
                        mc_group_info = Some((
                            group_ip_v4,
                            src_ip,
                            mc_announce_data.udp_port,
                            mc_announce_data.probe_path,
                        ));
                        let src_addr =
                            SocketAddr::V4(SocketAddrV4::new(src_ip, 4443));
                        let fc_path_id = conn.create_mc_path(
                            mc_addr,
                            src_addr,
                            mc_announce_data.probe_path,
                        );
                        debug!("Out of create mc path:{:?}", fc_path_id);
                        if let Ok(fc_path_id) = fc_path_id {
                            conn.fc_set_path_id(Some(fc_path_id))?;

                            // If soft-flexicast is used by the source, the client
                            // will receive flexicast QUIC
                            // packets with its unicast
                            // address as destination of the IP packet. Bind the
                            // socket to the local address
                            // with the flexicast destination
                            // port.
                            let mc_group_sockaddr: net::SocketAddr =
                                if mc_announce_data.probe_path {
                                    let ip = socket.local_addr()?.ip();
                                    net::SocketAddr::new(
                                        ip,
                                        mc_announce_data.udp_port,
                                    )
                                } else {
                                    let group_ip = if self.proxy_uc {
                                        "0.0.0.0".parse()?
                                    } else {
                                        net::Ipv4Addr::from(
                                            mc_announce_data.group_ip.to_owned(),
                                        )
                                    };
                                    net::SocketAddr::V4(net::SocketAddrV4::new(
                                        group_ip,
                                        mc_announce_data.udp_port,
                                    ))
                                };

                            match bind_mc_socket(mc_group_sockaddr) {
                                Ok(mc_socket) => {
                                    info!(
                                        "Multicast client binds on address: {:?}",
                                        mc_group_sockaddr
                                    );
                                    mc_socket_opt = Some(mc_socket);
                                },
                                Err(e) if self.amt_fallback_allowed && self.amt_relay_ip.is_some() => {
                                    warn!(
                                        "Failed to bind native multicast socket {:?}: {}; will fall back to AMT",
                                        mc_group_sockaddr, e
                                    );
                                    amt_fallback_deadline = Some(tokio::time::Instant::now());
                                },
                                Err(e) => return Err(e.into()),
                            }

                            probe_mc_path = true;

                            conn.mc_join_channel(
                                false,
                                Some(&mc_announce_data.channel_id),
                            )?;
                        }
                    }
                    added_mc_cid = true;
                }

                // Join the flexicast socket.
                if let Some(flexicast) = conn.get_flexicast_attributes() {
                    if flexicast.get_mc_role() ==
                        McRole::Client(McClientStatus::ListenMcPath(true)) &&
                        !joined_mc_ip &&
                        !self.proxy_uc
                    {
                        let group_ip = net::Ipv4Addr::from(
                            flexicast
                                .get_mc_announce_data(0).ok_or("Impossible to fetch the FC_ANNOUNCE_DATA")?
                                .group_ip
                                .to_owned(),
                        );
                        info!("Join MULTICAST {}", group_ip);
                        if let Some(mc_sock) = mc_socket_opt.as_mut() {
                            match mc_sock.join_multicast_v4(group_ip, self.local_ip) {
                                Ok(()) => {
                                    if self.amt_fallback_allowed {
                                        if self.amt_relay_ip.is_some() {
                                            amt_fallback_deadline = Some(
                                                tokio::time::Instant::now() + self.amt_fallback_delay,
                                            );
                                        } else {
                                            warn!("--amt-fallback enabled without --amt-relay; AMT fallback inactive");
                                        }
                                    }
                                },
                                Err(e) if self.amt_fallback_allowed && self.amt_relay_ip.is_some() => {
                                    warn!(
                                        "join_multicast_v4({}) failed: {}; triggering AMT fallback",
                                        group_ip, e
                                    );
                                    amt_fallback_deadline = Some(tokio::time::Instant::now());
                                },
                                Err(e) => return Err(e.into()),
                            }
                        } else if self.amt_fallback_allowed && self.amt_relay_ip.is_some() {
                            amt_fallback_deadline = Some(tokio::time::Instant::now());
                        }
                        joined_mc_ip = true;
                    }
                }
            }

            // Process all readable streams.
            'streams: for stream_id in conn.readable() {
                if stream_id & 0b11 == 0b11 && stream_id > 30 {
                    if !conn.stream_readable(stream_id) {
                        continue 'streams;
                    }

                    while let Ok((read, fin)) =
                        conn.stream_recv(stream_id, &mut buf[..])
                    {
                        let msg = FcQuicMsg::Stream((
                            buf[..read].to_vec(),
                            fin,
                            stream_id,
                        ));
                        self.tx_app.send(msg).await?;
                    }
                }
            }

            // Sends the HTTP/3 request.
            if let Some(h3_conn) = self.h3_conn.as_mut() {
                if let Some(headers) = self.h3_pending_request.take() {
                    let _ = h3_conn.send_request(&mut conn, &headers, true);
                }
            }

            // Processes HTTP/3 events.
            loop {
                if let Some(h3_conn) = self.h3_conn.as_mut() {
                    match h3_conn.poll(&mut conn) {
                        Ok((
                            _stream_id,
                            quiche::h3::Event::Headers { list, .. },
                        )) => {
                            let msg = FcQuicMsg::Http3RespHeader(list);
                            self.tx_app.send(msg).await?;
                        },

                        Ok((stream_id, quiche::h3::Event::Data)) => {
                            while let Ok(read) =
                                h3_conn.recv_body(&mut conn, stream_id, &mut buf)
                            {
                                let msg = FcQuicMsg::Http3RespBody(
                                    buf[..read].to_vec(),
                                );
                                self.tx_app.send(msg).await?;
                            }
                        },

                        Err(quiche::h3::Error::Done) => break,

                        Ok(_) => (),

                        Err(e) => return Err(e.into()),
                    }
                } else {
                    break;
                }
            }

            // Generate outgoing QUIC packets and send them on the UDP socket,
            // until quiche reports that there are no more packets to
            // be sent.
            loop {
                let (write, send_info) = match conn.send(&mut out) {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => {
                        break;
                    },

                    Err(e) => {
                        error!("send failed: {:?}", e);

                        conn.close(false, 0x1, b"fail").ok();
                        break;
                    },
                };

                // Depending on `send_info`, use the appropriate socket.
                // The client may send packets on the flexicast channel for the
                // path probing phase.
                let src_port = send_info.from.port();
                let out_socket =
                    if src_port == socket.local_addr().unwrap().port() {
                        &mut socket
                    } else if src_port == mc_addr.port() {
                        mc_socket_opt.as_mut().expect("Multicast socket is None")
                    } else {
                        panic!(
                            "Unknown source addr to send packets: {:?}",
                            send_info
                        );
                    };
                out_socket.send_to(&out[..write], send_info.to).await?;
            }

            if conn.is_closed() {
                info!("connection closed, {:?}", conn.stats());
                break;
            }
        }

        Ok(())
    }

    /// Receives a message from the application to send to QUIC.
    pub fn recv_app_msg(&mut self, msg: FcQuicMsg) -> Result<bool> {
        match msg {
            FcQuicMsg::Http3Request(headers) => {
                self.h3_pending_request = Some(headers);
            },

            FcQuicMsg::Close => {
                return Ok(true); // Close.
            }

            _ => panic!("Cannot send other message from the receiving-side"),
        }

        Ok(false)
    }
}

fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter().map(|b| format!("{b:02x}")).collect();

    vec.join("")
}

pub async fn optional_timeout(
    timeout: Option<std::time::Duration>,
) -> Option<()> {
    match timeout {
        Some(t) => {
            if t != std::time::Duration::ZERO {
                tokio::time::sleep(t).await;
            }
            Some(())
        },
        None => None,
    }
}

async fn optional_recv_from(
    opt_sock: Option<&UdpSocket>, buf: &mut [u8],
) -> std::io::Result<(usize, SocketAddr)> {
    match opt_sock {
        Some(socket) => socket.recv_from(buf).await,
        None => std::future::pending().await,
    }
}

async fn optional_amt_recv(
    opt_gw: Option<&mut AmtGateway>, buf: &mut [u8],
) -> std::io::Result<(usize, SocketAddr)> {
    match opt_gw {
        Some(gw) => {
            let (len, from, _to) = gw.recv(buf).await?;
            Ok((len, from))
        },
        None => std::future::pending().await,
    }
}

async fn optional_sleep_until(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(d) => tokio::time::sleep_until(d).await,
        None => std::future::pending().await,
    }
}

async fn optional_sleep_delay(delay: Option<Duration>) {
    match delay {
        Some(d) => tokio::time::sleep(d).await,
        None => std::future::pending().await,
    }
}

fn bind_mc_socket(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let domain = match addr {
        SocketAddr::V4(_) => socket2::Domain::IPV4,
        SocketAddr::V6(_) => socket2::Domain::IPV6,
    };
    let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, None)?;
    sock.set_reuse_address(true)?;
    #[cfg(all(unix, not(target_os = "solaris")))]
    {
        let _ = sock.set_reuse_port(true);
    }
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    UdpSocket::from_std(sock.into())
}

fn normalize_mc_from(
    from: SocketAddr,
    mc_group_info: Option<(Ipv4Addr, Ipv4Addr, u16, bool)>,
) -> SocketAddr {
    if let Some((_, src_ip, _, probe_path)) = mc_group_info {
        if !probe_path && from.ip() == std::net::IpAddr::V4(src_ip) && from.port() != 4443 {
            return SocketAddr::V4(SocketAddrV4::new(src_ip, 4443));
        }
    }
    from
}
