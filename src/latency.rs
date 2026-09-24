//! Fresh probes to the configured proxy over a physical interface, never through the tunnel.
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    ffi::CString,
    io::{self, Read, Write},
    net::SocketAddrV4,
    num::NonZeroU32,
    time::{Duration, Instant},
};

const TIMEOUT: Duration = Duration::from_secs(3);

fn physical_socket(interface: &str) -> io::Result<Socket> {
    if interface.starts_with("utun") || interface == "lo0" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "physical interface required",
        ));
    }
    let name = CString::new(interface)?;
    let index = NonZeroU32::new(unsafe { libc::if_nametoindex(name.as_ptr()) })
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no physical interface"))?;
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.bind_device_by_index_v4(Some(index))?;
    Ok(socket)
}

/// Milliseconds for one TCP handshake to the proxy.
pub fn measure(address: SocketAddrV4, interface: &str) -> io::Result<u64> {
    connect(&physical_socket(interface)?, address)
}

/// Whether a SOCKS5 proxy grants UDP ASSOCIATE (RFC 1928 §4, RFC 1929 credentials).
/// `Ok(false)` is an explicit refusal; handshake failures are errors.
pub fn udp_relay(
    address: SocketAddrV4,
    interface: &str,
    credentials: Option<(&str, &str)>,
) -> io::Result<bool> {
    let socket = physical_socket(interface)?;
    connect(&socket, address)?;
    socket.set_read_timeout(Some(TIMEOUT))?;
    socket.set_write_timeout(Some(TIMEOUT))?;
    let mut stream: std::net::TcpStream = socket.into();
    socks5_udp_associate(&mut stream, credentials)
}

fn connect(socket: &Socket, address: SocketAddrV4) -> io::Result<u64> {
    let started = Instant::now();
    socket.connect_timeout(&address.into(), TIMEOUT)?;
    Ok((started.elapsed().as_secs_f64() * 1000.0).round().max(1.0) as u64)
}

fn socks5_udp_associate<S: Read + Write>(
    stream: &mut S,
    credentials: Option<(&str, &str)>,
) -> io::Result<bool> {
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
    // UDP ASSOCIATE from an unspecified client endpoint; only the reply code matters.
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
    use std::net::{TcpListener, TcpStream};

    /// A minimal SOCKS5 server answering one UDP ASSOCIATE with the given reply code.
    fn socks5_server(expect_auth: bool, reply_code: u8) -> SocketAddrV4 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let std::net::SocketAddr::V4(address) = listener.local_addr().unwrap() else {
            panic!()
        };
        std::thread::spawn(move || {
            let (mut client, _) = listener.accept().unwrap();
            let mut greeting = [0u8; 3];
            client.read_exact(&mut greeting).unwrap();
            let method = if expect_auth { 2 } else { 0 };
            assert_eq!(greeting, [5, 1, method]);
            client.write_all(&[5, method]).unwrap();
            if expect_auth {
                let mut head = [0u8; 2];
                client.read_exact(&mut head).unwrap();
                let mut username = vec![0u8; head[1] as usize];
                client.read_exact(&mut username).unwrap();
                let mut length = [0u8; 1];
                client.read_exact(&mut length).unwrap();
                let mut password = vec![0u8; length[0] as usize];
                client.read_exact(&mut password).unwrap();
                assert_eq!((username.as_slice(), password.as_slice()), (b"user".as_slice(), b"p:ss".as_slice()));
                client.write_all(&[1, 0]).unwrap();
            }
            let mut request = [0u8; 10];
            client.read_exact(&mut request).unwrap();
            assert_eq!(request[..4], [5, 3, 0, 1]);
            client.write_all(&[5, reply_code, 0, 1, 127, 0, 0, 1, 4, 210]).unwrap();
            let _ = client.read(&mut [0u8; 1]);
        });
        address
    }

    #[test]
    fn udp_associate_reports_grant_refusal_and_bad_credentials() {
        let mut stream = TcpStream::connect(socks5_server(false, 0)).unwrap();
        assert!(socks5_udp_associate(&mut stream, None).unwrap());
        let mut stream = TcpStream::connect(socks5_server(true, 0)).unwrap();
        assert!(socks5_udp_associate(&mut stream, Some(("user", "p:ss"))).unwrap());
        let mut stream = TcpStream::connect(socks5_server(false, 7)).unwrap();
        assert!(!socks5_udp_associate(&mut stream, None).unwrap());
        // A server that only offers no-auth rejects our credential method.
        let mut stream = TcpStream::connect(socks5_server(false, 0)).unwrap();
        assert!(socks5_udp_associate(&mut stream, Some(("user", "p:ss"))).is_err());
    }
}
