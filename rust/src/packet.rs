use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug)]
pub struct Packet<'a> {
    raw: &'a mut [u8],
    tcp_offset: usize,
    fragmented: bool,
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
        let (ipv6, tcp_offset, fragmented, src, dst) = match raw[0] >> 4 {
            4 => {
                let offset = usize::from(raw[0] & 0x0f) * 4;
                if offset < 20 || raw.len() < offset + 20 || raw[9] != 6 {
                    return Err("not ipv4 tcp");
                }
                let src = IpAddr::from(<[u8; 4]>::try_from(&raw[12..16]).unwrap());
                let dst = IpAddr::from(<[u8; 4]>::try_from(&raw[16..20]).unwrap());
                let fragmented = u16::from_be_bytes([raw[6], raw[7]]) & 0x3fff != 0;
                (false, offset, fragmented, src, dst)
            }
            6 => {
                if raw.len() < 40 {
                    return Err("not ipv6 tcp");
                }
                let (offset, fragmented) = ipv6_tcp_offset(raw)?;
                let src = IpAddr::from(<[u8; 16]>::try_from(&raw[8..24]).unwrap());
                let dst = IpAddr::from(<[u8; 16]>::try_from(&raw[24..40]).unwrap());
                (true, offset, fragmented, src, dst)
            }
            _ => return Err("unknown ip version"),
        };
        let tcp = &raw[tcp_offset..];
        let flags = tcp[13];
        Ok(Self {
            ipv6,
            tcp_offset,
            fragmented,
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

    /// Restores TCP and, for IPv4, the IP header checksum after address translation.
    pub fn repair_checksums(&mut self) -> Result<(), &'static str> {
        let packet_len = if self.ipv6 {
            40 + usize::from(u16::from_be_bytes([self.raw[4], self.raw[5]]))
        } else {
            usize::from(u16::from_be_bytes([self.raw[2], self.raw[3]]))
        };
        let tcp_header_len = usize::from(self.raw[self.tcp_offset + 12] >> 4) * 4;
        if self.fragmented
            || tcp_header_len < 20
            || packet_len < self.tcp_offset + tcp_header_len
            || packet_len > self.raw.len()
        {
            return Err("cannot checksum a fragmented or incomplete TCP packet");
        }

        let addresses = if self.ipv6 { 8..40 } else { 12..20 };
        let tcp = &mut self.raw[..packet_len];
        let pseudo_header =
            checksum_words(&tcp[addresses]) + 6 + (tcp.len() - self.tcp_offset) as u32;
        let tcp = &mut tcp[self.tcp_offset..];
        tcp[16..18].fill(0);
        let tcp_checksum = finish_checksum(pseudo_header + checksum_words(tcp));
        tcp[16..18].copy_from_slice(&tcp_checksum.to_be_bytes());
        if !self.ipv6 {
            let header = &mut self.raw[..self.tcp_offset];
            header[10..12].fill(0);
            let ip_checksum = finish_checksum(checksum_words(header));
            header[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
        }
        Ok(())
    }
}

fn checksum_words(bytes: &[u8]) -> u32 {
    let words = bytes.chunks_exact(2);
    let tail = words.remainder().first().copied().unwrap_or(0);
    words
        .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
        .sum::<u32>()
        + (u32::from(tail) << 8)
}

fn finish_checksum(sum: u32) -> u16 {
    let sum = (sum & 0xffff) + (sum >> 16);
    !(((sum & 0xffff) + (sum >> 16)) as u16)
}

fn ipv6_tcp_offset(raw: &[u8]) -> Result<(usize, bool), &'static str> {
    let mut next = raw[6];
    let mut offset = 40;
    let mut fragmented = false;
    for _ in 0..=8 {
        let length = match next {
            6 if raw.len() >= offset + 20 => return Ok((offset, fragmented)),
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
                fragmented |= header[3] & 1 != 0;
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

#[cfg(test)]
mod tests {
    use super::Packet;

    fn check_against_reference(hex: &str, ip_checksum: Option<[u8; 2]>, tcp_checksum: [u8; 2]) {
        let mut bytes: Vec<_> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let mut packet = Packet::parse(&mut bytes).unwrap();
        packet.repair_checksums().unwrap();
        let offset = packet.tcp_offset;
        assert_eq!(packet.bytes()[offset + 16..offset + 18], tcp_checksum);
        if let Some(expected) = ip_checksum {
            assert_eq!(packet.bytes()[10..12], expected);
        }

        // Missing payload and the first fragment of a larger segment are not checksummable.
        let short = bytes.len() - 1;
        let mut packet = Packet::parse(&mut bytes[..short]).unwrap();
        assert!(packet.repair_checksums().is_err());
        if bytes[0] >> 4 == 4 {
            bytes[6] |= 0x20;
            assert!(Packet::parse(&mut bytes)
                .unwrap()
                .repair_checksums()
                .is_err());
        }
    }

    #[test]
    fn ipv4_tcp_checksums_match_win_divert_with_ip_and_tcp_options() {
        check_against_reference(
            "460000338321400040060000c0000201c633640201010000271044330102030400000000601840000000000001010000deadbe",
            Some([0xc9, 0x6b]),
            [0x66, 0x95],
        );
    }

    #[test]
    fn ipv6_tcp_checksum_matches_win_divert_with_an_extension_header() {
        check_against_reference(
            "600000000021004020010db800000000000000000000000120010db80000000000000000000000020600000000000000bb01443300000000000000005002400000000000deadbe1234",
            None,
            [0x44, 0x73],
        );
    }
}
