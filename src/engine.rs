//! HTTP CONNECT / SOCKS5 engine for the native app proxy. The provider hands each captured flow
//! over as one end of a Unix socket pair: a stream for TCP, datagrams for UDP.
use std::{
    ffi::{CStr, c_char},
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::fd::FromRawFd,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, TcpStream, UdpSocket, UnixDatagram, UnixStream},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;
use tun2proxy::{ArgProxy, ProxyConnector, ProxyType, socks5_proto::Address};

/// Each proxy connection and its handshake, and each DNS exchange, gets this long.
const TIMEOUT: Duration = Duration::from_secs(10);
/// Resolver for DNS addressed to a local or private server, which the proxy cannot reach.
const DNS_SERVER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
/// Concurrent DNS exchanges per UDP flow; further queries are dropped and retried by the client.
const DNS_PER_FLOW: usize = 16;
/// A UDP frame: a SOCKS5 address of at most 259 bytes followed by the datagram.
const MAX_FRAME: usize = 259 + 65535;

/// The current proxy. Replacing it ends every session opened through the previous one.
#[derive(Clone)]
struct Upstream {
    connector: Arc<ProxyConnector>,
    socks: bool,
    stop: CancellationToken,
}
struct Engine {
    runtime: tokio::runtime::Runtime,
    upstream: Upstream,
}
static ENGINE: Mutex<Option<Engine>> = Mutex::new(None);
static INTERFACE: AtomicU32 = AtomicU32::new(0);

fn engine_runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
}

fn supported(proxy: &ArgProxy) -> bool {
    matches!(proxy.proxy_type, ProxyType::Http | ProxyType::Socks5)
}

unsafe fn parse_proxy(proxy: *const c_char) -> Option<ArgProxy> {
    if proxy.is_null() {
        return None;
    }
    let url = unsafe { CStr::from_ptr(proxy) }.to_str().ok()?;
    ArgProxy::try_from(url).ok().filter(supported)
}

/// Starts the engine, or switches a running engine to `proxy` and ends the previous proxy's
/// sessions. 0 on success, 1 for an unsupported proxy, 2 when the runtime cannot start.
/// `proxy` must be a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_engine_start(proxy: *const c_char) -> i32 {
    let Some(proxy) = (unsafe { parse_proxy(proxy) }) else {
        return 1;
    };
    let Ok(connector) = ProxyConnector::new(&proxy) else {
        return 1;
    };
    let upstream = Upstream {
        connector: Arc::new(connector),
        socks: proxy.proxy_type == ProxyType::Socks5,
        stop: CancellationToken::new(),
    };
    let mut engine = ENGINE.lock().unwrap();
    match engine.as_mut() {
        Some(engine) => std::mem::replace(&mut engine.upstream, upstream)
            .stop
            .cancel(),
        None => match engine_runtime() {
            Ok(runtime) => *engine = Some(Engine { runtime, upstream }),
            Err(_) => return 2,
        },
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn proxy_engine_stop() {
    let engine = ENGINE.lock().unwrap().take();
    if let Some(engine) = engine {
        engine.upstream.stop.cancel();
        // Sessions end on cancellation; bound the wait for any still unwinding.
        engine.runtime.shutdown_timeout(Duration::from_millis(500));
    }
}

/// The physical interface for upstream sockets. Zero refuses new connections.
#[unsafe(no_mangle)]
pub extern "C" fn proxy_engine_set_interface(interface: u32) {
    INTERFACE.store(interface, Ordering::Release);
}

/// Runs a session with the current proxy until it ends or the proxy changes.
fn spawn<F: Future<Output = io::Result<()>> + Send + 'static>(
    session: impl FnOnce(Upstream) -> F,
) -> bool {
    let engine = ENGINE.lock().unwrap();
    let Some(engine) = engine.as_ref() else {
        return false;
    };
    let stop = engine.upstream.stop.clone();
    let session = session(engine.upstream.clone());
    engine.runtime.spawn(async move {
        tokio::select! {
            _ = stop.cancelled() => {}
            _ = session => {}
        }
    });
    true
}

/// A flow destination. The proxy resolves domain names.
struct Target {
    address: SocketAddr,
    domain: Option<String>,
}
impl Target {
    fn new(host: &str, port: u16) -> Option<Self> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Some(Self {
                address: SocketAddr::new(ip, port),
                domain: None,
            });
        }
        let valid = !host.is_empty()
            && host.len() <= 255
            && host
                .bytes()
                .all(|c| c.is_ascii_graphic() && c != b'@' && c != b'/');
        valid.then(|| Self {
            address: SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)),
            domain: Some(host.to_owned()),
        })
    }
}

/// Upstream sockets leave through the physical interface the provider reports, never through
/// another VPN's tunnel. Host tests connect unbound.
fn bind_egress<S: std::os::fd::AsFd>(socket: &S, ipv4: bool) -> io::Result<()> {
    if cfg!(not(target_os = "ios")) {
        return Ok(());
    }
    let index = std::num::NonZeroU32::new(INTERFACE.load(Ordering::Acquire))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no physical interface"))?;
    let socket = socket2::SockRef::from(socket);
    if ipv4 {
        socket.bind_device_by_index_v4(Some(index))
    } else {
        socket.bind_device_by_index_v6(Some(index))
    }
}

/// Connects to the proxy and completes its handshake for `target`. With `udp_associate`, also
/// returns the SOCKS5 UDP relay address.
async fn open(
    upstream: &Upstream,
    target: &Target,
    udp_associate: bool,
) -> io::Result<(TcpStream, Option<SocketAddr>)> {
    let server = upstream.connector.server();
    tokio::time::timeout(TIMEOUT, async {
        let socket = if server.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        bind_egress(&socket, server.is_ipv4())?;
        let mut stream = socket.connect(server).await?;
        let relay = upstream
            .connector
            .handshake(
                &mut stream,
                target.address,
                target.domain.clone(),
                udp_associate,
            )
            .await
            .map_err(io::Error::other)?;
        Ok((stream, relay))
    })
    .await?
}

/// Relays one TCP flow to `host`, an IP address or domain name, at `port`. Owns `fd`, a stream
/// socket that first receives one status byte: 0 once the proxy has connected, otherwise 1.
/// `host` must be a NUL-terminated string. Returns 0 when the session started.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_engine_tcp(fd: i32, host: *const c_char, port: u16) -> i32 {
    let flow = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
    let target = (!host.is_null() && port != 0)
        .then(|| unsafe { CStr::from_ptr(host) }.to_str().ok())
        .flatten()
        .and_then(|host| Target::new(host, port));
    let started =
        target.is_some_and(|target| spawn(move |upstream| tcp_session(flow, target, upstream)));
    if started { 0 } else { 1 }
}

async fn tcp_session(
    flow: std::os::unix::net::UnixStream,
    target: Target,
    upstream: Upstream,
) -> io::Result<()> {
    flow.set_nonblocking(true)?;
    let mut flow = UnixStream::from_std(flow)?;
    let mut server = match open(&upstream, &target, false).await {
        Ok((server, _)) => server,
        Err(error) => {
            flow.write_all(&[1]).await?;
            return Err(error);
        }
    };
    flow.write_all(&[0]).await?;
    tokio::io::copy_bidirectional(&mut flow, &mut server).await?;
    Ok(())
}

/// Relays one UDP flow. Owns `fd`, a datagram socket whose frames carry a SOCKS5 address, the
/// remote endpoint, followed by the payload in both directions. DNS goes over TCP through the
/// proxy. Other datagrams use one UDP ASSOCIATE per flow with a SOCKS5 proxy and are dropped
/// with an HTTP proxy. Returns 0 when the session started.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_engine_udp(fd: i32) -> i32 {
    let flow = unsafe { std::os::unix::net::UnixDatagram::from_raw_fd(fd) };
    if spawn(move |upstream| udp_session(flow, upstream)) {
        0
    } else {
        1
    }
}

/// A SOCKS5 UDP ASSOCIATE. The proxy keeps the relay while the control connection stays open.
struct Relay {
    control: TcpStream,
    socket: UdpSocket,
    address: SocketAddr,
}
impl Relay {
    async fn open(upstream: &Upstream) -> io::Result<Self> {
        let unspecified = Target {
            address: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            domain: None,
        };
        let (control, relay) = open(upstream, &unspecified, true).await?;
        let address = relay.ok_or_else(|| io::Error::other("the proxy granted no UDP relay"))?;
        let local = if address.is_ipv4() {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        } else {
            SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0))
        };
        let socket = std::net::UdpSocket::bind(local)?;
        bind_egress(&socket, address.is_ipv4())?;
        socket.set_nonblocking(true)?;
        // Unconnected: Darwin rejects send_to on a connected UDP socket, so replies are
        // filtered by source instead.
        Ok(Self {
            control,
            socket: UdpSocket::from_std(socket)?,
            address,
        })
    }
}

async fn udp_session(flow: std::os::unix::net::UnixDatagram, upstream: Upstream) -> io::Result<()> {
    flow.set_nonblocking(true)?;
    let flow = Arc::new(UnixDatagram::from_std(flow)?);
    let mut relay: Option<Relay> = None;
    let mut dns = JoinSet::new();
    // Three zero bytes (RSV, RSV, FRAG) turn a frame into a SOCKS5 UDP datagram.
    let mut outgoing = vec![0u8; 3 + MAX_FRAME];
    let mut incoming = vec![0u8; 3 + MAX_FRAME];
    let mut control = [0u8; 64];
    loop {
        tokio::select! {
            received = flow.recv(&mut outgoing[3..]) => {
                // The provider closing its end reports ECONNRESET, which ends the session.
                let frame = &outgoing[3..3 + received?];
                let Ok((address, used)) = Address::read_from(frame) else { continue };
                let port = match &address {
                    Address::Socket(address) => address.port(),
                    Address::Domain(_, port) => *port,
                };
                if port == 53 {
                    if dns.len() < DNS_PER_FLOW {
                        let query = frame[used..].to_vec();
                        dns.spawn(dns_exchange(upstream.clone(), flow.clone(), address, query));
                    }
                    continue;
                }
                if !upstream.socks {
                    continue;
                }
                if relay.is_none() {
                    relay = Some(Relay::open(&upstream).await?);
                }
                if let Some(relay) = &relay {
                    drop_when_full(relay.socket.send_to(&outgoing[..3 + frame.len()], relay.address).await)?;
                }
            }
            received = async {
                let relay = relay.as_mut().unwrap();
                tokio::select! {
                    received = relay.socket.recv_from(&mut incoming) => Some(received),
                    // The relay lasts as long as its control connection.
                    _ = relay.control.read(&mut control) => None,
                }
            }, if relay.is_some() => {
                let Some(received) = received else { return Ok(()) };
                let (length, source) = received?;
                let datagram = &incoming[..length];
                // Fragmented datagrams are not supported and are dropped.
                if source != relay.as_ref().unwrap().address || length < 4 || datagram[2] != 0 || Address::read_from(&datagram[3..]).is_err() {
                    continue;
                }
                drop_when_full(flow.send(&datagram[3..]).await)?;
            }
            Some(_) = dns.join_next(), if !dns.is_empty() => {}
        }
    }
}

/// A datagram that finds its queue full is dropped, as the network may drop it; Darwin reports
/// a full Unix datagram receiver as ENOBUFS rather than waiting.
fn drop_when_full(sent: io::Result<usize>) -> io::Result<()> {
    match sent {
        Err(error) if error.raw_os_error() == Some(libc::ENOBUFS) => Ok(()),
        sent => sent.map(drop),
    }
}

/// Whether the proxy can be expected to reach this resolver.
fn public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, ..] = ip.octets();
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_broadcast()
                || ip.is_multicast()
                || (a == 100 && b & 0xc0 == 64))
        }
        IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(ip) => public(IpAddr::V4(ip)),
            None => {
                !(ip.is_loopback()
                    || ip.is_unspecified()
                    || ip.is_multicast()
                    || ip.is_unique_local()
                    || ip.is_unicast_link_local())
            }
        },
    }
}

/// Sends one DNS query over TCP through the proxy and returns the answer as if from `address`.
async fn dns_exchange(
    upstream: Upstream,
    flow: Arc<UnixDatagram>,
    address: Address,
    query: Vec<u8>,
) -> io::Result<()> {
    let server = match address {
        Address::Socket(server) if public(server.ip()) => server,
        _ => DNS_SERVER,
    };
    let target = Target {
        address: server,
        domain: None,
    };
    let (mut stream, _) = open(&upstream, &target, false).await?;
    let answer = tokio::time::timeout(TIMEOUT, async {
        let length = u16::try_from(query.len()).map_err(io::Error::other)?;
        stream
            .write_all(&[&length.to_be_bytes()[..], &query].concat())
            .await?;
        let mut answer = vec![0u8; stream.read_u16().await?.into()];
        stream.read_exact(&mut answer).await?;
        io::Result::Ok(answer)
    })
    .await??;
    let mut frame = Vec::with_capacity(answer.len() + 19);
    address.write_to(&mut frame);
    frame.extend_from_slice(&answer);
    flow.send(&frame).await?;
    Ok(())
}

/// The proxy plus the physical interface name a probe must bind to.
unsafe fn probe_target(
    proxy: *const c_char,
    interface: u32,
) -> Option<(ArgProxy, std::net::SocketAddrV4, String)> {
    if interface == 0 {
        return None;
    }
    let proxy = unsafe { parse_proxy(proxy) }?;
    let SocketAddr::V4(address) = proxy.addr else {
        return None;
    };
    let mut name = [0; libc::IFNAMSIZ];
    if unsafe { libc::if_indextoname(interface, name.as_mut_ptr()) }.is_null() {
        return None;
    }
    let name = unsafe { CStr::from_ptr(name.as_ptr()) }.to_str().ok()?;
    Some((proxy, address, name.to_owned()))
}

/// Milliseconds for a fresh TCP handshake with the proxy, or -1.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_engine_latency(proxy: *const c_char, interface: u32) -> i64 {
    let Some((_, address, name)) = (unsafe { probe_target(proxy, interface) }) else {
        return -1;
    };
    crate::latency::measure(address, &name)
        .map(|ms| ms as i64)
        .unwrap_or(-1)
}

/// UDP relay availability: 1 relayed, 0 refused by the SOCKS5 proxy, 2 blocked (HTTP), -1 unknown.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_engine_udp_relay(proxy: *const c_char, interface: u32) -> i32 {
    let Some((proxy, address, name)) = (unsafe { probe_target(proxy, interface) }) else {
        return -1;
    };
    if proxy.proxy_type == ProxyType::Http {
        return 2;
    }
    let credentials = proxy
        .credentials
        .as_ref()
        .map(|key| (key.username.as_str(), key.password.as_str()));
    crate::latency::udp_relay(address, &name, credentials)
        .map(i32::from)
        .unwrap_or(-1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader, Read, Write},
        net::{TcpListener, UdpSocket},
        os::{fd::IntoRawFd, unix::net},
        sync::mpsc,
        thread,
    };

    /// The engine is process-global, so tests using it must not overlap.
    static SERIAL: Mutex<()> = Mutex::new(());

    fn start(proxy: &str) {
        let proxy = std::ffi::CString::new(proxy).unwrap();
        assert_eq!(unsafe { proxy_engine_start(proxy.as_ptr()) }, 0);
    }

    fn tcp_flow(host: &str, port: u16) -> net::UnixStream {
        let (flow, engine) = net::UnixStream::pair().unwrap();
        flow.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let host = std::ffi::CString::new(host).unwrap();
        assert_eq!(
            unsafe { proxy_engine_tcp(engine.into_raw_fd(), host.as_ptr(), port) },
            0
        );
        flow
    }

    fn udp_flow() -> net::UnixDatagram {
        let (flow, engine) = net::UnixDatagram::pair().unwrap();
        flow.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        assert_eq!(unsafe { proxy_engine_udp(engine.into_raw_fd()) }, 0);
        flow
    }

    fn frame(address: SocketAddr, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        Address::from(address).write_to(&mut frame);
        frame.extend_from_slice(payload);
        frame
    }

    /// An HTTP proxy that accepts one CONNECT, sends the request line and authorization header
    /// back through `requests`, then echoes the tunnel's bytes.
    fn http_proxy(status: u16, requests: mpsc::Sender<(String, String)>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            for connection in listener.incoming() {
                let requests = requests.clone();
                thread::spawn(move || {
                    let mut client = connection.unwrap();
                    let mut reader = BufReader::new(client.try_clone().unwrap());
                    let (mut line, mut auth) = (String::new(), String::new());
                    reader.read_line(&mut line).unwrap();
                    loop {
                        let mut header = String::new();
                        reader.read_line(&mut header).unwrap();
                        if header == "\r\n" {
                            break;
                        }
                        if let Some(value) = header.strip_prefix("Proxy-Authorization: ") {
                            auth = value.trim().to_owned();
                        }
                    }
                    let _ = requests.send((line.trim().to_owned(), auth));
                    write!(client, "HTTP/1.1 {status} Status\r\n\r\n").unwrap();
                    if status != 200 {
                        return;
                    }
                    let _ = std::io::copy(&mut reader, &mut client);
                });
            }
        });
        address
    }

    #[test]
    fn tcp_flows_connect_through_an_http_proxy_by_name_with_credentials() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let (requests, received) = mpsc::channel();
        let proxy = http_proxy(200, requests);
        start(&format!("http://user:p%3Ass@{proxy}"));
        let mut flow = tcp_flow("example.com", 443);
        let mut status = [9u8];
        flow.read_exact(&mut status).unwrap();
        assert_eq!(status, [0]);
        let (line, auth) = received.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(line, "CONNECT example.com:443 HTTP/1.1");
        assert_eq!(auth, "Basic dXNlcjpwOnNz");
        flow.write_all(b"ping").unwrap();
        let mut echo = [0u8; 4];
        flow.read_exact(&mut echo).unwrap();
        assert_eq!(&echo, b"ping");
        // Half-close travels through the proxy, which then ends the tunnel.
        flow.shutdown(std::net::Shutdown::Write).unwrap();
        assert_eq!(flow.read(&mut echo).unwrap(), 0);
        proxy_engine_stop();
    }

    #[test]
    fn a_refused_connect_reports_failure_before_any_data() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let (requests, _received) = mpsc::channel();
        let proxy = http_proxy(403, requests);
        start(&format!("http://{proxy}"));
        let mut flow = tcp_flow("2606:4700:4700::1111", 443);
        let mut status = [9u8];
        flow.read_exact(&mut status).unwrap();
        assert_eq!(status, [1]);
        assert_eq!(flow.read(&mut status).unwrap(), 0);
        proxy_engine_stop();
    }

    /// A SOCKS5 proxy that checks the credentials `user` / `p:ss`, answers each request with
    /// `reply_code`, echoes CONNECT tunnels, and for UDP ASSOCIATE reports `relay`. Requested
    /// commands and addresses go to `requests`.
    fn socks5_proxy(
        reply_code: u8,
        relay: SocketAddr,
        requests: mpsc::Sender<(u8, Address)>,
    ) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            for connection in listener.incoming() {
                let requests = requests.clone();
                thread::spawn(move || {
                    let mut client = connection.unwrap();
                    let mut greeting = [0u8; 2];
                    client.read_exact(&mut greeting).unwrap();
                    let mut methods = vec![0u8; greeting[1].into()];
                    client.read_exact(&mut methods).unwrap();
                    assert!(methods.contains(&2));
                    client.write_all(&[5, 2]).unwrap();
                    let mut head = [0u8; 2];
                    client.read_exact(&mut head).unwrap();
                    let mut username = vec![0u8; head[1].into()];
                    client.read_exact(&mut username).unwrap();
                    let mut length = [0u8];
                    client.read_exact(&mut length).unwrap();
                    let mut password = vec![0u8; length[0].into()];
                    client.read_exact(&mut password).unwrap();
                    assert_eq!((&username[..], &password[..]), (&b"user"[..], &b"p:ss"[..]));
                    client.write_all(&[1, 0]).unwrap();
                    let mut request = vec![0u8; 3];
                    client.read_exact(&mut request).unwrap();
                    let mut rest = [0u8; 262];
                    let n = client.read(&mut rest).unwrap();
                    let (target, _) = Address::read_from(&rest[..n]).unwrap();
                    let _ = requests.send((request[1], target));
                    let mut reply = vec![5, reply_code, 0];
                    Address::from(relay).write_to(&mut reply);
                    client.write_all(&reply).unwrap();
                    let _ = std::io::copy(&mut &client, &mut &client);
                });
            }
        });
        address
    }

    #[test]
    fn tcp_flows_connect_through_a_socks5_proxy_with_credentials() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let (requests, received) = mpsc::channel();
        let proxy = socks5_proxy(0, "127.0.0.1:1".parse().unwrap(), requests);
        start(&format!("socks5://user:p%3Ass@{proxy}"));
        let mut flow = tcp_flow("1.1.1.1", 80);
        let mut status = [9u8];
        flow.read_exact(&mut status).unwrap();
        assert_eq!(status, [0]);
        let request = received.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(request, (1, Address::Socket("1.1.1.1:80".parse().unwrap())));
        flow.write_all(b"ping").unwrap();
        let mut echo = [0u8; 4];
        flow.read_exact(&mut echo).unwrap();
        assert_eq!(&echo, b"ping");
        proxy_engine_stop();
    }

    #[test]
    fn socks5_udp_flows_use_one_udp_associate_relay() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let relay = UdpSocket::bind("127.0.0.1:0").unwrap();
        relay
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let (requests, received) = mpsc::channel();
        let proxy = socks5_proxy(0, relay.local_addr().unwrap(), requests);
        start(&format!("socks5://user:p%3Ass@{proxy}"));
        let flow = udp_flow();
        let quic: SocketAddr = "1.1.1.1:443".parse().unwrap();
        flow.send(&frame(quic, b"quic?")).unwrap();
        let mut datagram = [0u8; 1500];
        let (n, client) = relay.recv_from(&mut datagram).unwrap();
        assert_eq!(
            &datagram[..n],
            &[&[0, 0, 0][..], &frame(quic, b"quic?")].concat()[..]
        );
        assert_eq!(received.recv_timeout(Duration::from_secs(5)).unwrap().0, 3);
        relay
            .send_to(&[&[0, 0, 0][..], &frame(quic, b"ok")].concat(), client)
            .unwrap();
        let n = flow.recv(&mut datagram).unwrap();
        assert_eq!(&datagram[..n], &frame(quic, b"ok")[..]);
        // A second datagram reuses the association.
        flow.send(&frame(quic, b"again")).unwrap();
        relay.recv_from(&mut datagram).unwrap();
        assert!(received.try_recv().is_err());
        // A burst the provider has not yet read overflows its queue: datagrams are dropped,
        // as the network may drop them, and the flow carries on.
        for _ in 0..600 {
            relay
                .send_to(&[&[0, 0, 0][..], &frame(quic, &[7; 1400])].concat(), client)
                .unwrap();
        }
        std::thread::sleep(Duration::from_millis(300));
        let mut burst = [0u8; 2000];
        while flow.recv(&mut burst).map(|n| n > 10).unwrap_or(false)
            && flow.set_nonblocking(true).is_ok()
        {}
        flow.set_nonblocking(false).unwrap();
        flow.send(&frame(quic, b"after")).unwrap();
        let (n, _) = relay.recv_from(&mut datagram).unwrap();
        assert!(
            datagram[..n].ends_with(b"after"),
            "the UDP session ended after the burst"
        );
        proxy_engine_stop();
    }

    #[test]
    fn dns_goes_over_tcp_through_the_proxy_and_answers_from_the_queried_server() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        // The proxy answers the DNS exchange itself: a two-byte length and the message.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = listener.local_addr().unwrap();
        let (requests, received) = mpsc::channel();
        thread::spawn(move || {
            let (mut client, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(client.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            while {
                let mut header = String::new();
                reader.read_line(&mut header).unwrap();
                header != "\r\n"
            } {}
            client
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .unwrap();
            let mut length = [0u8; 2];
            reader.read_exact(&mut length).unwrap();
            let mut query = vec![0u8; u16::from_be_bytes(length).into()];
            reader.read_exact(&mut query).unwrap();
            requests.send((line.trim().to_owned(), query)).unwrap();
            client.write_all(&[0, 6]).unwrap();
            client.write_all(b"answer").unwrap();
        });
        start(&format!("http://{proxy}"));
        let flow = udp_flow();
        // A LAN resolver is unreachable from the proxy, so the query goes to the fallback.
        let router: SocketAddr = "192.168.1.1:53".parse().unwrap();
        flow.send(&frame(router, b"query")).unwrap();
        let mut datagram = [0u8; 512];
        let n = flow.recv(&mut datagram).unwrap();
        assert_eq!(&datagram[..n], &frame(router, b"answer")[..]);
        let (line, query) = received.recv().unwrap();
        assert_eq!(line, "CONNECT 8.8.8.8:53 HTTP/1.1");
        assert_eq!(query, b"query");
        proxy_engine_stop();
    }

    #[test]
    fn unsupported_proxies_and_destinations_are_rejected() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let proxy = std::ffi::CString::new("socks4://127.0.0.1:1080").unwrap();
        assert_eq!(unsafe { proxy_engine_start(proxy.as_ptr()) }, 1);
        start("http://127.0.0.1:9");
        for host in ["", "bad host", "user@example.com"] {
            let (_flow, engine) = net::UnixStream::pair().unwrap();
            let host = std::ffi::CString::new(host).unwrap();
            assert_eq!(
                unsafe { proxy_engine_tcp(engine.into_raw_fd(), host.as_ptr(), 443) },
                1
            );
        }
        proxy_engine_stop();
    }

    #[test]
    fn only_public_resolvers_are_asked_through_the_proxy() {
        for ip in ["8.8.8.8", "2001:4860:4860::8888"] {
            assert!(public(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "192.168.86.1",
            "10.0.0.1",
            "100.100.100.100",
            "127.0.0.1",
            "fe80::1",
            "fd7a:115c:a1e0::53",
            "::ffff:192.168.1.1",
        ] {
            assert!(!public(ip.parse().unwrap()), "{ip}");
        }
    }
}
