use crate::http::trusted_host;
use crate::upstream::split_host_port;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

const MAX_REPLY: u64 = 8 << 20;

pub fn normalize(raw: &str) -> Result<String, String> {
    let domain = raw
        .trim()
        .strip_prefix("http://")
        .ok_or("only http loopback URLs are accepted")?;
    let domain = domain.strip_suffix('/').unwrap_or(domain);
    if domain.is_empty()
        || domain.contains(['/', '?', '#', '@', '\r', '\n'])
        || !trusted_host(domain)
    {
        return Err("control URL must be an HTTP loopback origin".into());
    }
    Ok(format!("http://{domain}"))
}

pub fn request(
    url: &str,
    method: &str,
    path: &str,
    body: &[u8],
    agent: bool,
    timeout: Duration,
) -> io::Result<(u16, Vec<u8>)> {
    let url = normalize(url).map_err(io::Error::other)?;
    let authority = &url["http://".len()..];
    let (host, port) = split_host_port(authority).map_or((authority, 80), |(host, port)| {
        (host, port.parse().unwrap_or(80))
    });
    let host = host.trim_matches(['[', ']']);
    let mut candidates = Vec::new();
    if host.eq_ignore_ascii_case("localhost") {
        candidates.extend([
            SocketAddr::from(([127, 0, 0, 1], port)),
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], port)),
        ]);
    } else {
        let ip = host.parse::<IpAddr>().map_err(io::Error::other)?;
        candidates.push(SocketAddr::new(ip, port));
    }
    let started = Instant::now();
    let mut last_error = None;
    for addr in candidates {
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        match TcpStream::connect_timeout(&addr, remaining) {
            Ok(mut stream) => {
                return exchange(&mut stream, authority, method, path, body, agent, remaining);
            }
            Err(err) => {
                last_error = Some(err);
            }
        }
    }
    Err(last_error.unwrap_or_else(|| io::Error::other("no loopback addresses found")))
}

fn exchange(
    stream: &mut TcpStream,
    authority: &str,
    method: &str,
    path: &str,
    body: &[u8],
    agent: bool,
    timeout: Duration,
) -> io::Result<(u16, Vec<u8>)> {
    if !path.starts_with('/')
        || path.contains(['\r', '\n', ' '])
        || !matches!(method, "GET" | "POST" | "PUT" | "DELETE")
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let mut header=format!("{method} {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nAccept: application/json\r\n");
    if agent {
        header.push_str("X-PitchProx-Agent: 1\r\n");
    }
    if !body.is_empty() {
        header.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        ));
    }
    header.push_str("\r\n");
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    let mut input = BufReader::new(stream);
    let mut line = String::new();
    read_line(&mut input, &mut line)?;
    let status = line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| io::Error::other("invalid HTTP status line"))?;
    let mut length = None;
    let mut chunked = false;
    let mut ended = false;
    for _ in 0..100 {
        read_line(&mut input, &mut line)?;
        if line == "\r\n" || line == "\n" {
            ended = true;
            break;
        }
        let (key, value) = line
            .split_once(':')
            .ok_or_else(|| io::Error::other("invalid HTTP header"))?;
        if key.eq_ignore_ascii_case("content-length") {
            length = Some(value.trim().parse::<u64>().map_err(io::Error::other)?);
        } else if key.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value.trim().eq_ignore_ascii_case("chunked");
        }
    }
    if !ended {
        return Err(io::Error::other("response headers are too large"));
    }
    let mut data = Vec::new();
    if chunked {
        loop {
            read_line(&mut input, &mut line)?;
            let size = u64::from_str_radix(line.trim().split(';').next().unwrap_or(""), 16)
                .map_err(io::Error::other)?;
            if size == 0 {
                break;
            }
            if size > MAX_REPLY - data.len() as u64 {
                return Err(io::Error::other("response is too large"));
            }
            if input.by_ref().take(size).read_to_end(&mut data)? as u64 != size {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            let mut separator = [0; 2];
            input.read_exact(&mut separator)?;
            if separator != *b"\r\n" {
                return Err(io::Error::other("invalid chunk delimiter"));
            }
        }
    } else {
        if length.is_some_and(|v| v > MAX_REPLY) {
            return Err(io::Error::other("response is too large"));
        }
        input
            .take(length.unwrap_or(MAX_REPLY + 1))
            .read_to_end(&mut data)?;
        if length.is_some_and(|v| v != data.len() as u64) {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        if data.len() as u64 > MAX_REPLY {
            return Err(io::Error::other("response is too large"));
        }
    }
    Ok((status, data))
}

fn read_line(input: &mut impl BufRead, line: &mut String) -> io::Result<()> {
    line.clear();
    input.take(8193).read_line(line)?;
    if !line.ends_with('\n') || line.len() > 8192 {
        return Err(io::Error::other("invalid HTTP response line"));
    }
    Ok(())
}
