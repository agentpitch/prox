use crate::upstream::split_host_port;
use std::borrow::Cow;
use std::io::{self, Read};
use std::net::{IpAddr, TcpStream};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Http,
    Tls,
}

#[derive(Debug, PartialEq, Eq)]
pub struct SniffResult {
    pub hostname: String,
    pub protocol: Protocol,
}

const METHODS: [&[u8]; 8] = [
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
];
const TLS_RECORDS: usize = 8;

/// Reads a bounded prefix for inspection. Forward the returned bytes before
/// copying the rest of the stream so no application data is consumed by sniffing.
pub fn read_prefix(
    mut stream: &TcpStream,
    max_bytes: usize,
    timeout: Duration,
) -> io::Result<(Vec<u8>, Option<SniffResult>)> {
    let max_bytes = if max_bytes == 0 { 4096 } else { max_bytes };
    let started = Instant::now();
    let previous_timeout = stream.read_timeout()?;
    let mut data = vec![0; max_bytes];
    let mut filled = 0;
    let mut target = max_bytes.min(5);

    let result = (|| {
        while filled < target {
            if !timeout.is_zero() {
                let remaining = timeout.saturating_sub(started.elapsed());
                if remaining.is_zero() {
                    break;
                }
                stream.set_read_timeout(Some(remaining))?;
            }
            match stream.read(&mut data[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(ref err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err)
                    if filled > 0
                        || matches!(
                            err.kind(),
                            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                        ) =>
                {
                    break;
                }
                Err(err) => return Err(err),
            }
            if filled < target {
                continue;
            }
            let prefix = &data[..filled];
            if let Some(need) = tls_record_need(prefix) {
                target = max_bytes.min(need);
            } else if http_host(prefix).is_some_and(|host| !host.is_empty()) {
                break;
            } else if looks_like_http(prefix) {
                if prefix.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    break;
                }
                target = max_bytes.min(filled + 1);
            } else if prefix.len() < 8
                && METHODS.iter().any(|method| {
                    method
                        .get(..prefix.len())
                        .is_some_and(|start| start.eq_ignore_ascii_case(prefix))
                })
            {
                target = max_bytes.min(filled + 1);
            } else {
                break;
            }
        }
        Ok(())
    })();

    let restored = if timeout.is_zero() {
        Ok(())
    } else {
        stream.set_read_timeout(previous_timeout)
    };
    result?;
    restored?;
    data.truncate(filled);
    let sniff = inspect(&data);
    Ok((data, sniff))
}

pub fn inspect(data: &[u8]) -> Option<SniffResult> {
    if let Some(hostname) = http_host(data).and_then(normalize_hostname) {
        return Some(SniffResult {
            hostname,
            protocol: Protocol::Http,
        });
    }
    let payload = client_hello(data)?;
    let hostname = normalize_hostname(server_name(&payload)?)?;
    Some(SniffResult {
        hostname,
        protocol: Protocol::Tls,
    })
}

fn looks_like_http(data: &[u8]) -> bool {
    METHODS.iter().any(|method| data.starts_with(method))
}

fn http_host(data: &[u8]) -> Option<&str> {
    if !looks_like_http(data) {
        return None;
    }
    let mut offset = 0;
    while let Some(end) = data[offset..].windows(2).position(|bytes| bytes == b"\r\n") {
        let line = &data[offset..offset + end];
        if line.is_empty() {
            break;
        }
        if line
            .get(..5)
            .is_some_and(|front| front.eq_ignore_ascii_case(b"host:"))
        {
            let host = std::str::from_utf8(&line[5..]).ok()?.trim();
            return Some(host_without_port(host));
        }
        if line
            .get(..8)
            .is_some_and(|front| front.eq_ignore_ascii_case(b"CONNECT "))
        {
            let address = line.splitn(3, |&byte| byte == b' ').nth(1)?;
            return Some(host_without_port(std::str::from_utf8(address).ok()?));
        }
        offset += end + 2;
    }
    None
}

fn host_without_port(input: &str) -> &str {
    split_host_port(input).map_or(input.trim_matches(['[', ']']), |(host, _)| host)
}

fn normalize_hostname(host: &str) -> Option<String> {
    let host = host.trim_matches(['[', ']']).trim();
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    if host.parse::<IpAddr>().is_err()
        && !host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        })
    {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

fn tls_record_need(mut data: &[u8]) -> Option<usize> {
    if data.first() != Some(&0x16) {
        return None;
    }
    let input_size = data.len();
    let mut offset = 0;
    let mut payload_bytes = 0;
    let mut header = [0; 4];
    for _ in 0..TLS_RECORDS {
        if data.len() < 5 {
            return Some(offset + 5);
        }
        if data[0] != 0x16 {
            return Some(input_size);
        }
        let record_size = usize::from(u16::from_be_bytes([data[3], data[4]]));
        if record_size == 0 || data.len() < 5 + record_size {
            return Some(offset + 5 + record_size);
        }
        let record = &data[5..5 + record_size];
        if payload_bytes < header.len() {
            let n = (header.len() - payload_bytes).min(record_size);
            header[payload_bytes..payload_bytes + n].copy_from_slice(&record[..n]);
        }
        payload_bytes += record_size;
        offset += 5 + record_size;
        if payload_bytes >= header.len()
            && (header[0] != 1 || payload_bytes >= handshake_size(&header))
        {
            return Some(offset);
        }
        data = &data[5 + record_size..];
    }
    Some(offset)
}

fn handshake_size(header: &[u8]) -> usize {
    4 + ((usize::from(header[1]) << 16) | (usize::from(header[2]) << 8) | usize::from(header[3]))
}

fn client_hello(mut data: &[u8]) -> Option<Cow<'_, [u8]>> {
    let mut joined = Vec::new();
    for _ in 0..TLS_RECORDS {
        let header = data.get(..5)?;
        let size = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if header[0] != 0x16 || size == 0 {
            return None;
        }
        let payload = data.get(5..5 + size)?;
        if joined.is_empty()
            && payload.len() >= 4
            && payload[0] == 1
            && payload.len() >= handshake_size(payload)
        {
            return Some(Cow::Borrowed(&payload[..handshake_size(payload)]));
        }
        joined.extend_from_slice(payload);
        if joined.len() >= 4 {
            if joined[0] != 1 {
                return None;
            }
            let needed = handshake_size(&joined);
            if joined.len() >= needed {
                joined.truncate(needed);
                return Some(Cow::Owned(joined));
            }
        }
        data = &data[5 + size..];
    }
    None
}

fn server_name(payload: &[u8]) -> Option<&str> {
    let mut body = payload.get(4 + 2 + 32..)?;
    read_vector(&mut body, 1)?;
    read_vector(&mut body, 2)?;
    read_vector(&mut body, 1)?;
    let mut extensions = read_vector(&mut body, 2)?;
    while extensions.len() >= 4 {
        let kind = u16::from_be_bytes([extensions[0], extensions[1]]);
        extensions = &extensions[2..];
        let mut extension = read_vector(&mut extensions, 2)?;
        if kind != 0 {
            continue;
        }
        let mut names = read_vector(&mut extension, 2)?;
        while names.len() >= 3 {
            let kind = names[0];
            names = &names[1..];
            let name = read_vector(&mut names, 2)?;
            if kind == 0 {
                return std::str::from_utf8(name).ok();
            }
        }
        return None;
    }
    None
}

fn read_vector<'a>(input: &mut &'a [u8], length_bytes: usize) -> Option<&'a [u8]> {
    let length = input
        .get(..length_bytes)?
        .iter()
        .fold(0, |size, b| (size << 8) | usize::from(*b));
    let data = input.get(length_bytes..length_bytes + length)?;
    *input = &input[length_bytes + length..];
    Some(data)
}
