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
const DNS_PORT: u16 = 53;
/// Concurrent DNS exchanges per UDP flow; further queries are dropped and retried by the client.
const DNS_PER_FLOW: usize = 16;
/// A UDP frame: a SOCKS5 address of at most 259 bytes followed by the datagram.
const MAX_FRAME: usize = 259 + 65535;

/// The current proxy. Replacing it ends every session opened through the previous one.
#[derive(Clone)]
struct Upstream {
    proxy: Arc<ArgProxy>,
    connector: Arc<ProxyConnector>,
    stop: CancellationToken,
}
impl Upstream {
    fn socks(&self) -> bool {
        self.proxy.proxy_type == ProxyType::Socks5
    }
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

/// Starts the engine, or switches a running engine to `proxy` and ends the previous proxy's
/// sessions. 0 on success, 1 for an unsupported proxy, 2 when the runtime cannot start.
///
/// # Safety
/// `proxy` must be a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_engine_start(proxy: *const c_char) -> i32 {
    let url = (!proxy.is_null())
        .then(|| unsafe { CStr::from_ptr(proxy) }.to_str().ok())
        .flatten();
    let Some(proxy) = url.and_then(|url| ArgProxy::try_from(url).ok()) else {
        return 1;
    };
    let Ok(connector) = ProxyConnector::new(&proxy) else {
        return 1;
    };
    let upstream = Upstream {
        proxy: Arc::new(proxy),
        connector: Arc::new(connector),
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

/// Runs a session with the current proxy until it ends or the proxy changes. `session` returns
/// None to refuse the flow.
fn spawn<F: Future<Output = io::Result<()>> + Send + 'static>(
    session: impl FnOnce(Upstream) -> Option<F>,
) -> bool {
    let engine = ENGINE.lock().unwrap();
    let Some(engine) = engine.as_ref() else {
        return false;
    };
    let stop = engine.upstream.stop.clone();
    let Some(session) = session(engine.upstream.clone()) else {
        return false;
    };
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
/// another VPN's tunnel.
fn bind_egress<S: std::os::fd::AsFd>(socket: &S, ipv4: bool) -> io::Result<()> {
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
/// Returns 0 when the session started.
///
/// # Safety
/// `host` must be a NUL-terminated string, and the engine takes ownership of `fd`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_engine_tcp(fd: i32, host: *const c_char, port: u16) -> i32 {
    let flow = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
    let target = (!host.is_null() && port != 0)
        .then(|| unsafe { CStr::from_ptr(host) }.to_str().ok())
        .flatten()
        .and_then(|host| Target::new(host, port));
    let started = target
        .is_some_and(|target| spawn(move |upstream| Some(tcp_session(flow, target, upstream))));
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

/// Relays one UDP flow whose first datagram goes to `port`. Owns `fd`, a datagram socket whose
/// frames carry a SOCKS5 address, the remote endpoint, followed by the payload in both
/// directions. DNS goes over TCP through the proxy. Other datagrams use one UDP ASSOCIATE per
/// flow with a SOCKS5 proxy; HTTP CONNECT carries none, so an HTTP proxy refuses such a flow at
/// once, letting QUIC fall back to TCP, and drops such datagrams. Returns 0 when the session
/// started.
///
/// # Safety
/// The engine takes ownership of `fd`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_engine_udp(fd: i32, port: u16) -> i32 {
    let flow = unsafe { std::os::unix::net::UnixDatagram::from_raw_fd(fd) };
    let started = spawn(move |upstream| {
        (port == DNS_PORT || upstream.socks()).then(|| udp_session(flow, upstream))
    });
    if started { 0 } else { 1 }
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
                if port == DNS_PORT {
                    if dns.len() < DNS_PER_FLOW {
                        let query = frame[used..].to_vec();
                        dns.spawn(dns_exchange(upstream.clone(), flow.clone(), address, query));
                    }
                    continue;
                }
                if !upstream.socks() {
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

/// Runs the connection check through the current proxy and interface and writes it as JSON into
/// `out`. Returns the length written, or 0 when the proxy did not answer.
///
/// # Safety
/// `out` must point to `capacity` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_engine_check(out: *mut u8, capacity: usize) -> usize {
    let Some(proxy) = ENGINE.lock().unwrap().as_ref().map(|e| e.upstream.proxy.clone()) else {
        return 0;
    };
    let socket = || {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        bind_egress(&socket, true)?;
        Ok(socket)
    };
    let Some(json) = crate::check::run(&proxy, socket)
        .ok()
        .and_then(|check| serde_json::to_vec(&check).ok())
        .filter(|json| json.len() <= capacity && !out.is_null())
    else {
        return 0;
    };
    unsafe { std::ptr::copy_nonoverlapping(json.as_ptr(), out, json.len()) };
    json.len()
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

    /// Starts the engine with `proxy`, its upstream sockets bound to the loopback interface.
    fn start(proxy: &str) {
        let loopback = std::ffi::CString::new("lo0").unwrap();
        proxy_engine_set_interface(unsafe { libc::if_nametoindex(loopback.as_ptr()) });
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

    fn udp_flow(port: u16) -> net::UnixDatagram {
        let (flow, engine) = net::UnixDatagram::pair().unwrap();
        flow.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        assert_eq!(unsafe { proxy_engine_udp(engine.into_raw_fd(), port) }, 0);
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
        let flow = udp_flow(443);
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
    fn dns_goes_over_tcp_through_the_proxy_to_resolvers_it_can_reach() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let (requests, received) = mpsc::channel();
        start(&format!("http://{}", http_proxy(200, requests)));
        // A resolver the proxy cannot reach, such as one on the LAN, is replaced by 8.8.8.8.
        for (resolver, asked) in [
            ("8.8.8.8:53", "8.8.8.8:53"),
            ("[2001:4860:4860::8888]:53", "[2001:4860:4860::8888]:53"),
            ("192.168.86.1:53", "8.8.8.8:53"),
            ("10.0.0.1:53", "8.8.8.8:53"),
            ("100.100.100.100:53", "8.8.8.8:53"),
            ("127.0.0.1:53", "8.8.8.8:53"),
            ("[fe80::1]:53", "8.8.8.8:53"),
            ("[fd7a:115c:a1e0::53]:53", "8.8.8.8:53"),
            ("[::ffff:192.168.1.1]:53", "8.8.8.8:53"),
        ] {
            let resolver: SocketAddr = resolver.parse().unwrap();
            let flow = udp_flow(53);
            flow.send(&frame(resolver, b"query")).unwrap();
            let mut datagram = [0u8; 512];
            let n = flow.recv(&mut datagram).unwrap();
            // The proxy echoes, so the answer is the query, returned as if from the resolver.
            assert_eq!(&datagram[..n], &frame(resolver, b"query")[..], "{resolver}");
            let (line, _) = received.recv_timeout(Duration::from_secs(5)).unwrap();
            assert_eq!(line, format!("CONNECT {asked} HTTP/1.1"), "{resolver}");
        }
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
        // HTTP CONNECT carries no datagrams, so QUIC is refused and falls back to TCP.
        let (_flow, engine) = net::UnixDatagram::pair().unwrap();
        assert_eq!(unsafe { proxy_engine_udp(engine.into_raw_fd(), 443) }, 1);
        proxy_engine_stop();
    }

    #[test]
    fn the_connection_check_measures_the_current_proxy_over_the_physical_interface() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = listener.local_addr().unwrap();
        thread::spawn(move || listener.incoming().for_each(drop));
        start(&format!("http://{proxy}"));
        let check = || {
            let mut out = [0u8; 128];
            let n = unsafe { proxy_engine_check(out.as_mut_ptr(), out.len()) };
            (n > 0).then(|| serde_json::from_slice::<crate::check::Check>(&out[..n]).unwrap())
        };
        let result = check().unwrap();
        assert!(result.latency_ms >= 1);
        assert_eq!(result.udp, Some(crate::check::UdpRelay::Blocked));
        // Without a physical interface, nothing connects.
        proxy_engine_set_interface(0);
        assert_eq!(check(), None);
        proxy_engine_stop();
        assert_eq!(check(), None);
    }
}
