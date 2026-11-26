use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug)]
pub struct Packet<'a> {
    raw: &'a mut [u8],
    tcp_offset: usize,
    pub ipv6: bool,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub syn: bool,
    pub ack: bool,
    pub rst: bool,
    pub fin: bool,
}

impl<'a> Packet<'a> {
    pub fn parse(raw: &'a mut [u8]) -> Result<Self, &'static str> {
        if raw.len() < 20 {
            return Err("packet too small");
        }
        let (ipv6, tcp_offset, src, dst) = match raw[0] >> 4 {
            4 => {
                let offset = usize::from(raw[0] & 0x0f) * 4;
                if offset < 20 || raw.len() < offset + 20 || raw[9] != 6 {
                    return Err("not ipv4 tcp");
                }
                let src = IpAddr::from(<[u8; 4]>::try_from(&raw[12..16]).unwrap());
                let dst = IpAddr::from(<[u8; 4]>::try_from(&raw[16..20]).unwrap());
                (false, offset, src, dst)
            }
            6 => {
                if raw.len() < 40 {
                    return Err("not ipv6 tcp");
                }
                let offset = ipv6_tcp_offset(raw)?;
                let src = IpAddr::from(<[u8; 16]>::try_from(&raw[8..24]).unwrap());
                let dst = IpAddr::from(<[u8; 16]>::try_from(&raw[24..40]).unwrap());
                (true, offset, src, dst)
            }
            _ => return Err("unknown ip version"),
        };
        let tcp = &raw[tcp_offset..];
        let flags = tcp[13];
        Ok(Self {
            ipv6,
            tcp_offset,
            src,
            dst,
            src_port: u16::from_be_bytes([tcp[0], tcp[1]]),
            dst_port: u16::from_be_bytes([tcp[2], tcp[3]]),
            syn: flags & 0x02 != 0,
            ack: flags & 0x10 != 0,
            rst: flags & 0x04 != 0,
            fin: flags & 0x01 != 0,
            raw,
        })
    }

    pub fn bytes(&self) -> &[u8] {
        self.raw
    }

    /// The caller must recalculate checksums after changing addresses or ports.
    pub fn set_source(&mut self, ip: IpAddr, port: u16) -> Result<(), &'static str> {
        if self.ipv6 {
            self.raw[8..24].copy_from_slice(&as_ipv6_bytes(ip));
        } else {
            self.raw[12..16].copy_from_slice(&as_ipv4(ip)?.octets());
        }
        self.raw[self.tcp_offset..self.tcp_offset + 2].copy_from_slice(&port.to_be_bytes());
        self.src = ip;
        self.src_port = port;
        Ok(())
    }

    /// The caller must recalculate checksums after changing addresses or ports.
    pub fn set_destination(&mut self, ip: IpAddr, port: u16) -> Result<(), &'static str> {
        if self.ipv6 {
            self.raw[24..40].copy_from_slice(&as_ipv6_bytes(ip));
        } else {
            self.raw[16..20].copy_from_slice(&as_ipv4(ip)?.octets());
        }
        self.raw[self.tcp_offset + 2..self.tcp_offset + 4].copy_from_slice(&port.to_be_bytes());
        self.dst = ip;
        self.dst_port = port;
        Ok(())
    }
}

fn ipv6_tcp_offset(raw: &[u8]) -> Result<usize, &'static str> {
    let mut next = raw[6];
    let mut offset = 40;
    for _ in 0..=8 {
        let length = match next {
            6 if raw.len() >= offset + 20 => return Ok(offset),
            6 => return Err("truncated ipv6 tcp header"),
            0 | 43 | 60 | 135 => {
                let size = raw
                    .get(offset + 1)
                    .ok_or("truncated ipv6 extension header")?;
                let length = (usize::from(*size) + 1) * 8;
                if raw.len() < offset + length {
                    return Err("invalid ipv6 extension header length");
                }
                length
            }
            44 => {
                let header = raw
                    .get(offset..offset + 8)
                    .ok_or("truncated ipv6 fragment header")?;
                if u16::from_be_bytes([header[2], header[3]]) & 0xfff8 != 0 {
                    return Err("non-initial ipv6 fragment");
                }
                8
            }
            51 => {
                let size = raw
                    .get(offset + 1)
                    .ok_or("truncated ipv6 authentication header")?;
                let length = (usize::from(*size) + 2) * 4;
                if raw.len() < offset + length {
                    return Err("invalid ipv6 authentication header length");
                }
                length
            }
            _ => return Err("ipv6 packet does not contain tcp"),
        };
        next = raw[offset];
        offset += length;
    }
    Err("too many ipv6 extension headers")
}

fn as_ipv4(ip: IpAddr) -> Result<Ipv4Addr, &'static str> {
    match ip {
        IpAddr::V4(ip) => Ok(ip),
        IpAddr::V6(ip) => ip.to_ipv4_mapped().ok_or("IPv6 address in an IPv4 packet"),
    }
}

fn as_ipv6_bytes(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
        IpAddr::V6(ip) => ip.octets(),
    }
}
