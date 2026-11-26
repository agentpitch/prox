use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyKind {
    HttpConnect,
    Socks5,
}

#[derive(Clone, Copy, Debug)]
pub struct ProxyHop<'a> {
    pub kind: ProxyKind,
    pub address: &'a str,
    pub username: &'a str,
    pub password: &'a str,
}

/// Opens tunnels in route order over a connection to the first hop. The
/// caller keeps using this same buffered stream so data after CONNECT is kept.
pub fn negotiate_chain(
    stream: &mut BufReader<impl Read + Write>,
    proxies: &[ProxyHop<'_>],
    destination: &str,
) -> io::Result<()> {
    for (index, proxy) in proxies.iter().enumerate() {
        let target = proxies
            .get(index + 1)
            .map_or(destination, |hop| hop.address);
        match proxy.kind {
            ProxyKind::HttpConnect => http_connect(stream, *proxy, target)?,
            ProxyKind::Socks5 => socks5_connect(stream, *proxy, target)?,
        }
    }
    Ok(())
}

const MAX_CONNECT_RESPONSE_BYTES: usize = 64 << 10;

fn http_connect(
    stream: &mut BufReader<impl Read + Write>,
    proxy: ProxyHop<'_>,
    target: &str,
) -> io::Result<()> {
    if target.contains(['\r', '\n']) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid CONNECT authority",
        ));
    }
    let mut request =
        format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Connection: Keep-Alive\r\n");
    if !proxy.username.is_empty() || !proxy.password.is_empty() {
        let credentials = format!("{}:{}", proxy.username, proxy.password);
        request.push_str("Proxy-Authorization: Basic ");
        request.push_str(&encode_base64(credentials.as_bytes()));
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    send(stream, request.as_bytes())?;

    let mut remaining = MAX_CONNECT_RESPONSE_BYTES;
    let mut buffer = Vec::new();
    read_connect_line(stream, &mut remaining, &mut buffer)?;
    let status = String::from_utf8_lossy(&buffer);
    let mut fields = status.split_whitespace();
    if !matches!(fields.next(), Some("HTTP/1.0" | "HTTP/1.1")) || fields.next() != Some("200") {
        return Err(protocol_error(format!(
            "http CONNECT failed: {}",
            status.trim()
        )));
    }
    while buffer != b"\r\n" {
        read_connect_line(stream, &mut remaining, &mut buffer)?;
    }
    Ok(())
}

fn read_connect_line(
    stream: &mut impl BufRead,
    remaining: &mut usize,
    buffer: &mut Vec<u8>,
) -> io::Result<()> {
    buffer.clear();
    let read = stream
        .take((*remaining + 1) as u64)
        .read_until(b'\n', buffer)?;
    if read > *remaining {
        return Err(protocol_error(format!(
            "http CONNECT response headers exceed {MAX_CONNECT_RESPONSE_BYTES} bytes"
        )));
    }
    if buffer.last() != Some(&b'\n') {
        return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
    }
    *remaining -= read;
    Ok(())
}

fn encode_base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or_default();
        let third = chunk.get(2).copied().unwrap_or_default();
        let indices = [
            first >> 2,
            (first & 3) << 4 | second >> 4,
            (second & 15) << 2 | third >> 6,
            third & 63,
        ];
        for (position, index) in indices.into_iter().enumerate() {
            let character = if position <= chunk.len() {
                ALPHABET[usize::from(index)]
            } else {
                b'='
            };
            encoded.push(char::from(character));
        }
    }
    encoded
}

fn socks5_connect(
    stream: &mut BufReader<impl Read + Write>,
    proxy: ProxyHop<'_>,
    target: &str,
) -> io::Result<()> {
    let with_credentials = !proxy.username.is_empty() || !proxy.password.is_empty();
    let greeting: &[u8] = if with_credentials {
        &[5, 2, 0, 2]
    } else {
        &[5, 1, 0]
    };
    send(stream, greeting)?;
    let mut response = [0; 2];
    stream.read_exact(&mut response)?;
    match response {
        [5, 0] => {}
        [5, 2] => socks5_authenticate(stream, proxy.username, proxy.password)?,
        [5, _] => return Err(protocol_error("socks5 auth rejected")),
        _ => return Err(protocol_error("invalid socks5 response")),
    }

    let (host, port) =
        split_host_port(target).ok_or_else(|| protocol_error("expected host:port"))?;
    let port = port
        .parse::<std::num::NonZeroU16>()
        .map_err(|_| protocol_error(format!("invalid port {port:?}")))?
        .get();
    let mut request = Vec::with_capacity(host.len() + 7);
    request.extend([5, 1, 0]);
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            request.push(1);
            request.extend(ip.octets());
        }
        Ok(IpAddr::V6(ip)) => match ip.to_ipv4_mapped() {
            Some(v4) => {
                request.push(1);
                request.extend(v4.octets());
            }
            None => {
                request.push(4);
                request.extend(ip.octets());
            }
        },
        Err(_) => {
            let length =
                u8::try_from(host.len()).map_err(|_| protocol_error("socks5 host is too long"))?;
            request.extend([3, length]);
            request.extend(host.as_bytes());
        }
    }
    request.extend(port.to_be_bytes());
    send(stream, &request)?;

    let mut reply = [0; 4];
    stream.read_exact(&mut reply)?;
    if reply[1] != 0 {
        return Err(protocol_error(format!(
            "socks5 connect failed code={}",
            reply[1]
        )));
    }
    let length = match reply[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut size = [0];
            stream.read_exact(&mut size)?;
            usize::from(size[0])
        }
        kind => return Err(protocol_error(format!("invalid atyp {kind}"))),
    };
    let mut address_and_port = [0; 257];
    stream.read_exact(&mut address_and_port[..length + 2])
}

fn socks5_authenticate(
    stream: &mut BufReader<impl Read + Write>,
    user: &str,
    password: &str,
) -> io::Result<()> {
    let error = |_| protocol_error("socks5 credentials too long");
    let user_length = u8::try_from(user.len()).map_err(error)?;
    let password_length = u8::try_from(password.len()).map_err(error)?;
    let mut request = Vec::with_capacity(3 + user.len() + password.len());
    request.extend([1, user_length]);
    request.extend(user.as_bytes());
    request.push(password_length);
    request.extend(password.as_bytes());
    send(stream, &request)?;
    let mut response = [0; 2];
    stream.read_exact(&mut response)?;
    if response != [1, 0] {
        return Err(protocol_error("socks5 username/password auth failed"));
    }
    Ok(())
}

fn send(stream: &mut BufReader<impl Read + Write>, bytes: &[u8]) -> io::Result<()> {
    let writer = stream.get_mut();
    writer.write_all(bytes)?;
    writer.flush()
}

pub(crate) fn split_host_port(address: &str) -> Option<(&str, &str)> {
    let (host, port) = if let Some(address) = address.strip_prefix('[') {
        address.split_once("]:")?
    } else {
        address.split_once(':')?
    };
    (!host.contains(['[', ']']) && !port.contains(['[', ']', ':'])).then_some((host, port))
}

fn protocol_error(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
