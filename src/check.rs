//! The connection check: a fresh TCP handshake to the proxy and, for a SOCKS5 proxy, whether it
//! grants UDP ASSOCIATE.
use serde::{Deserialize, Serialize};
use socket2::Socket;
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, SocketAddrV4},
    time::{Duration, Instant},
};
use tun2proxy::{ArgProxy, ProxyType};

const TIMEOUT: Duration = Duration::from_secs(3);

/// What Test Connection reports. The provider produces it; the CLI hands it to the app.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Check {
    pub latency_ms: u64,
    /// Unknown when the SOCKS5 handshake failed.
    pub udp: Option<UdpRelay>,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UdpRelay {
    Relayed,
    /// The SOCKS5 proxy refused UDP ASSOCIATE.
    Unsupported,
    /// HTTP CONNECT carries no datagrams.
    Blocked,
}

/// Checks `proxy` over fresh sockets from `socket`, which binds each to the physical interface.
pub fn run(proxy: &ArgProxy, socket: impl Fn() -> io::Result<Socket>) -> io::Result<Check> {
    let SocketAddr::V4(address) = proxy.addr else {
        return Err(io::Error::from(io::ErrorKind::Unsupported));
    };
    let latency_ms = connect(&socket()?, address)?;
    let udp = match proxy.proxy_type {
        ProxyType::Http => Some(UdpRelay::Blocked),
        ProxyType::Socks4 | ProxyType::None => None,
        ProxyType::Socks5 => {
            let credentials = proxy.credentials.as_ref();
            udp_associate(socket()?, address, credentials.map(|key| (key.username.as_str(), key.password.as_str())))
                .ok()
                .map(|granted| if granted { UdpRelay::Relayed } else { UdpRelay::Unsupported })
        }
    };
    Ok(Check { latency_ms, udp })
}

/// Milliseconds for the TCP handshake.
fn connect(socket: &Socket, address: SocketAddrV4) -> io::Result<u64> {
    let started = Instant::now();
    socket.connect_timeout(&address.into(), TIMEOUT)?;
    Ok((started.elapsed().as_secs_f64() * 1000.0).round().max(1.0) as u64)
}

/// Whether a SOCKS5 proxy grants UDP ASSOCIATE (RFC 1928 §4, RFC 1929 credentials).
/// `Ok(false)` is an explicit refusal; handshake failures are errors.
fn udp_associate(
    socket: Socket,
    address: SocketAddrV4,
    credentials: Option<(&str, &str)>,
) -> io::Result<bool> {
    connect(&socket, address)?;
    socket.set_read_timeout(Some(TIMEOUT))?;
    socket.set_write_timeout(Some(TIMEOUT))?;
    let mut stream: std::net::TcpStream = socket.into();
    let invalid = |message: &str| io::Error::new(io::ErrorKind::InvalidData, message.to_owned());
    let method = if credentials.is_some() { 2 } else { 0 };
    stream.write_all(&[5, 1, method])?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply)?;
    if reply != [5, method] {
        return Err(invalid("proxy rejected the authentication method"));
    }
    if let Some((username, password)) = credentials {
        stream.write_all(&tun2proxy::socks5_proto::password_request(username, password)?)?;
        stream.read_exact(&mut reply)?;
        if reply[1] != 0 {
            return Err(invalid("proxy rejected the credentials"));
        }
    }
    // From an unspecified client endpoint; only the reply code matters.
    stream.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head)?;
    if head[0] != 5 {
        return Err(invalid("proxy sent an invalid SOCKS5 reply"));
    }
    Ok(head[1] == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket2::{Domain, Protocol, Type};
    use std::net::TcpListener;

    fn socket() -> io::Result<Socket> {
        Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
    }

    /// A SOCKS5 proxy for one latency connection and one UDP ASSOCIATE answered with
    /// `reply_code`. With `expect_auth` it requires `user` / `p:ss`.
    fn socks5_proxy(expect_auth: bool, reply_code: u8) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            // Held open: hanging up at once can fail the client's connect with POLLHUP.
            let _latency = listener.accept().unwrap();
            let (mut client, _) = listener.accept().unwrap();
            let mut greeting = [0u8; 3];
            client.read_exact(&mut greeting).unwrap();
            let offered = greeting[2];
            client.write_all(&[5, if expect_auth { 2 } else { 0 }]).unwrap();
            if offered != if expect_auth { 2 } else { 0 } {
                return;
            }
            if expect_auth {
                let mut head = [0u8; 2];
                client.read_exact(&mut head).unwrap();
                let mut username = vec![0u8; head[1] as usize];
                client.read_exact(&mut username).unwrap();
                let mut length = [0u8; 1];
                client.read_exact(&mut length).unwrap();
                let mut password = vec![0u8; length[0] as usize];
                client.read_exact(&mut password).unwrap();
                let ok = (username.as_slice(), password.as_slice()) == (b"user".as_slice(), b"p:ss".as_slice());
                client.write_all(&[1, if ok { 0 } else { 1 }]).unwrap();
            }
            let mut request = [0u8; 10];
            client.read_exact(&mut request).unwrap();
            assert_eq!(request[..4], [5, 3, 0, 1]);
            client.write_all(&[5, reply_code, 0, 1, 127, 0, 0, 1, 4, 210]).unwrap();
            let _ = client.read(&mut [0u8; 1]);
        });
        address
    }

    fn check(url: String) -> Check {
        run(&ArgProxy::try_from(url.as_str()).unwrap(), socket).unwrap()
    }

    #[test]
    fn socks5_udp_is_reported_relayed_unsupported_or_unknown() {
        let granted = check(format!("socks5://{}", socks5_proxy(false, 0)));
        assert!(granted.latency_ms >= 1);
        assert_eq!(granted.udp, Some(UdpRelay::Relayed));
        let with_credentials = check(format!("socks5://user:p%3Ass@{}", socks5_proxy(true, 0)));
        assert_eq!(with_credentials.udp, Some(UdpRelay::Relayed));
        assert_eq!(check(format!("socks5://{}", socks5_proxy(false, 7))).udp, Some(UdpRelay::Unsupported));
        // A proxy that only offers no-auth rejects our credential method: UDP is unknown.
        assert_eq!(check(format!("socks5://user:p%3Ass@{}", socks5_proxy(false, 0))).udp, None);
    }
}
