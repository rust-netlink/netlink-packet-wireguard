// SPDX-License-Identifier: MIT

use std::{
    convert::TryFrom,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

use netlink_packet_core::{
    emit_u16, emit_u16_be, emit_u32, parse_u16_be, parse_u32, DecodeError,
};

pub(crate) const SOCKET_ADDR_V4_LEN: usize = 16;
pub(crate) const SOCKET_ADDR_V6_LEN: usize = 28;

const AF_INET6: u16 = 10;
const AF_INET: u16 = 2;

/// Parse an IPv6 socket address, defined as `sockaddr_in6` in kernel
fn parse_socket_addr_v6(payload: &[u8]) -> SocketAddrV6 {
    assert_eq!(payload.len(), SOCKET_ADDR_V6_LEN);
    // We don't need the address family to build a SocketAddrv6
    // let address_family = parse_u16(&payload[..2]);
    let port = parse_u16_be(&payload[2..4]).unwrap();
    let flow_info = parse_u32(&payload[4..8]).unwrap();
    // We know we have exactly 16 bytes so this won't fail
    let ip_bytes = <[u8; 16]>::try_from(&payload[8..24]).unwrap();
    let ip = Ipv6Addr::from(ip_bytes);
    let scope_id = parse_u32(&payload[24..28]).unwrap();
    SocketAddrV6::new(ip, port, flow_info, scope_id)
}

/// Parse an IPv4 socket address, defined as `struct sockaddr_in` in kernel.
fn parse_socket_addr_v4(payload: &[u8]) -> SocketAddrV4 {
    assert_eq!(payload.len(), 16);
    // We don't need the address family to build a SocketAddr4v
    // let address_family = parse_u16(&payload[..2]).unwrap();
    let port = parse_u16_be(&payload[2..4]).unwrap();
    // We know we have exactly 4 bytes so this won't fail
    let ip_bytes = <[u8; 4]>::try_from(&payload[4..8]).unwrap();
    let ip = Ipv4Addr::from(ip_bytes);
    SocketAddrV4::new(ip, port)
}

fn emit_socket_addr_v4(addr: &SocketAddrV4, buf: &mut [u8]) {
    emit_u16(&mut buf[..2], AF_INET).unwrap();
    emit_u16_be(&mut buf[2..4], addr.port()).unwrap();
    buf[4..8].copy_from_slice(addr.ip().octets().as_slice());
    // padding
    buf[8..16].copy_from_slice([0; 8].as_slice());
}

fn emit_socket_addr_v6(addr: &SocketAddrV6, buf: &mut [u8]) {
    emit_u16(&mut buf[..2], AF_INET6).unwrap();
    emit_u16_be(&mut buf[2..4], addr.port()).unwrap();
    emit_u32(&mut buf[4..8], addr.flowinfo()).unwrap();
    buf[8..24].copy_from_slice(addr.ip().octets().as_slice());
    emit_u32(&mut buf[24..28], addr.scope_id()).unwrap();
}

pub(crate) fn emit_socket_addr(addr: &SocketAddr, buf: &mut [u8]) {
    match addr {
        SocketAddr::V4(v4) => emit_socket_addr_v4(v4, buf),
        SocketAddr::V6(v6) => emit_socket_addr_v6(v6, buf),
    }
}

pub(crate) fn parse_socket_addr(buf: &[u8]) -> Result<SocketAddr, DecodeError> {
    match buf.len() {
        SOCKET_ADDR_V4_LEN => Ok(SocketAddr::V4(parse_socket_addr_v4(buf))),
        SOCKET_ADDR_V6_LEN => Ok(SocketAddr::V6(parse_socket_addr_v6(buf))),
        _ => Err(format!(
            "invalid socket address (should be 16 or 28 bytes): {:x?}",
            buf
        )
        .into()),
    }
}

// test data are using hard coded little endian byte order, not for big-endian
#[cfg(not(target_endian = "big"))]
#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;

    // 127.0.0.1:7290
    const SOCKADDR_IN_BYTES_1: &[u8] = &[
        0x02, 0x00, 0x1c, 0x7a, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];
    // 192.168.1.1:51820
    const SOCKADDR_IN_BYTES_2: &[u8] = &[
        0x02, 0x00, 0xca, 0x6c, 0xc0, 0xa8, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];

    // fe80::e458:8ead:89bb:8e25%3:51820
    const SOCKADDR_IN6_BYTES_1: &[u8] = &[
        0x0a, 0x00, 0xca, 0x6c, 0x10, 0x00, 0x00, 0x00, 0xfe, 0x80, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xe4, 0x58, 0x8e, 0xad, 0x89, 0xbb, 0x8e, 0x25,
        0x03, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn test_parse_socket_addr_in_1() {
        let ipaddr = parse_socket_addr(SOCKADDR_IN_BYTES_1).unwrap();
        assert_eq!(ipaddr, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 7290).into());
    }

    #[test]
    fn test_parse_socket_addr_in_2() {
        let ipaddr = parse_socket_addr(SOCKADDR_IN_BYTES_2).unwrap();
        assert_eq!(
            ipaddr,
            SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 51820).into()
        );
    }

    #[test]
    fn test_parse_socket_addr_in6_1() {
        let ipaddr = parse_socket_addr(SOCKADDR_IN6_BYTES_1).unwrap();
        assert_eq!(
            ipaddr,
            SocketAddrV6::new(
                Ipv6Addr::from_str("fe80::e458:8ead:89bb:8e25").unwrap(),
                51820,
                16,
                3
            )
            .into()
        );
    }
}
