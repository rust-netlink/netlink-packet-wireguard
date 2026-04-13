// SPDX-License-Identifier: MIT

use std::{
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
};

use netlink_packet_core::{Emitable, Parseable, ParseableParametrized};
use netlink_packet_generic::{GenlBuffer, GenlHeader};
use pretty_assertions::assert_eq;

use crate::{
    AmneziaWg, AmneziaWgAttribute, Wireguard, WireguardAddressFamily,
    WireguardAllowedIp, WireguardAllowedIpAttr, WireguardAttribute,
    WireguardCmd, WireguardMessage, WireguardPeer, WireguardPeerAttribute,
    WireguardTimeSpec,
};

// nlmon capture of netlink packet sent by `sudo wg` command with netlink
// header purged(generic netlink command is first byte).
#[test]
fn test_query_request() {
    let raw: Vec<u8> = vec![
        0x00, 0x01, 0x00, 0x00, 0x07, 0x00, 0x02, 0x00, 0x63, 0x6e, 0x00, 0x00,
    ];

    let expected: WireguardMessage<Wireguard> = WireguardMessage {
        cmd: WireguardCmd::GetDevice,
        attributes: vec![WireguardAttribute::IfName("cn".to_string())],
    };

    let header = GenlHeader::parse(&GenlBuffer::new(&raw)).unwrap();

    assert_eq!(
        expected,
        WireguardMessage::<Wireguard>::parse_with_param(&raw[4..], header)
            .unwrap(),
    );
    let mut buffer = vec![0; expected.buffer_len() + header.buffer_len()];
    header.emit(&mut buffer);
    expected.emit(&mut buffer[4..]);
    assert_eq!(&buffer, &raw);
}

// nlmon capture of kernel netlink packet reply of `sudo wg` command with
// netlink header purged(generic netlink command is first byte).
//  * private key is masked to vec![01..31]
//  * ip address is masked to 1.1.1.1:1111
#[test]
fn test_query_reply() {
    let raw: Vec<u8> = vec![
        0x00, 0x01, 0x00, 0x00, 0x06, 0x00, 0x06, 0x00, 0x2c, 0x80, 0x00, 0x00,
        0x08, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x07, 0x00, 0x02, 0x00, 0x63, 0x6e, 0x00, 0x00,
        0x24, 0x00, 0x03, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x24, 0x00, 0x04, 0x00, 0xcc, 0xaf, 0x10, 0xe1, 0xa9, 0xd7, 0xd0, 0x5f,
        0xf2, 0xbd, 0xd2, 0xa0, 0xf1, 0x78, 0x2d, 0x97, 0x46, 0x9a, 0x1c, 0xf7,
        0xbe, 0x88, 0x0f, 0x68, 0x75, 0xa7, 0x79, 0x93, 0x5d, 0x1d, 0x21, 0x75,
        0xc0, 0x00, 0x08, 0x80, 0xbc, 0x00, 0x00, 0x80, 0x24, 0x00, 0x01, 0x00,
        0x77, 0xdc, 0x9a, 0xc0, 0xb3, 0xf0, 0xc5, 0xe7, 0x5b, 0xb8, 0xd3, 0x42,
        0x2d, 0x88, 0xec, 0x92, 0xd1, 0x3a, 0x34, 0x23, 0x22, 0x90, 0x87, 0x82,
        0x15, 0x51, 0x57, 0x19, 0x69, 0xde, 0xa0, 0x44, 0x24, 0x00, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x06, 0x00,
        0x9a, 0x24, 0x77, 0x69, 0x00, 0x00, 0x00, 0x00, 0x02, 0x0e, 0xa8, 0x0f,
        0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x05, 0x00, 0x19, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x08, 0x00, 0x80, 0x40, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x07, 0x00, 0x98, 0x44, 0xd0, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x0a, 0x00, 0x01, 0x00, 0x00, 0x00, 0x14, 0x00, 0x04, 0x00,
        0x02, 0x00, 0x04, 0x57, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x09, 0x80, 0x1c, 0x00, 0x00, 0x80,
        0x05, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x01, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let attributes = vec![
        WireguardAttribute::ListenPort(32812),
        WireguardAttribute::Fwmark(0),
        WireguardAttribute::IfIndex(3),
        WireguardAttribute::IfName("cn".to_string()),
        WireguardAttribute::PrivateKey([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
            19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        ]),
        WireguardAttribute::PublicKey([
            204, 175, 16, 225, 169, 215, 208, 95, 242, 189, 210, 160, 241, 120,
            45, 151, 70, 154, 28, 247, 190, 136, 15, 104, 117, 167, 121, 147,
            93, 29, 33, 117,
        ]),
        WireguardAttribute::Peers(vec![WireguardPeer(vec![
            WireguardPeerAttribute::PublicKey([
                119, 220, 154, 192, 179, 240, 197, 231, 91, 184, 211, 66, 45,
                136, 236, 146, 209, 58, 52, 35, 34, 144, 135, 130, 21, 81, 87,
                25, 105, 222, 160, 68,
            ]),
            WireguardPeerAttribute::PresharedKey([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]),
            WireguardPeerAttribute::LastHandshake(WireguardTimeSpec {
                seconds: 1769415834,
                nano_seconds: 262671874,
            }),
            WireguardPeerAttribute::PersistentKeepalive(25),
            WireguardPeerAttribute::TxBytes(1917056),
            WireguardPeerAttribute::RxBytes(30426264),
            WireguardPeerAttribute::ProtocolVersion(1),
            WireguardPeerAttribute::Endpoint(
                std::net::SocketAddr::from_str("1.1.1.1:1111").unwrap(),
            ),
            WireguardPeerAttribute::AllowedIps(vec![WireguardAllowedIp(vec![
                WireguardAllowedIpAttr::Cidr(0),
                WireguardAllowedIpAttr::Family(WireguardAddressFamily::Ipv4),
                WireguardAllowedIpAttr::IpAddr(IpAddr::V4(
                    Ipv4Addr::UNSPECIFIED,
                )),
            ])]),
        ])]),
    ];

    let expected: WireguardMessage<Wireguard> = WireguardMessage {
        cmd: WireguardCmd::GetDevice,
        attributes,
    };

    let header = GenlHeader::parse(&GenlBuffer::new(&raw)).unwrap();

    assert_eq!(
        expected,
        WireguardMessage::parse_with_param(&raw[4..], header).unwrap(),
    );

    let mut buffer = vec![0; expected.buffer_len() + header.buffer_len()];
    header.emit(&mut buffer);
    expected.emit(&mut buffer[4..]);
    assert_eq!(&buffer, &raw);
}

#[test]
fn test_amnezia_junk_parameters() {
    // Message with Amnezia Specific Junk params
    let msg: WireguardMessage<AmneziaWg> = WireguardMessage {
        cmd: WireguardCmd::SetDevice,
        attributes: vec![
            AmneziaWgAttribute::IfName("awg0".into()),
            AmneziaWgAttribute::JC(4),
            AmneziaWgAttribute::Jmin(40),
            AmneziaWgAttribute::Jmax(70),
        ],
    };

    let mut buffer = vec![0; msg.buffer_len()];
    msg.emit(&mut buffer);

    // Checking Amnezia Specific bytes
    // JunkCount (JC) should be 11 (0x0b)
    // Netlink Attribute: [Length (2 bytes), Type (2 bytes), Value (n bytes)]

    assert!(
        buffer
            .windows(6)
            .any(|w| w == &[0x06, 0x00, 0x09, 0x00, 0x04, 0x00]),
        "JC failed"
    );

    assert!(
        buffer
            .windows(6)
            .any(|w| w == &[0x06, 0x00, 0x0a, 0x00, 0x28, 0x00]),
        "Jmin failed"
    );
}

#[test]
fn test_amnezia_magic_headers() {
    let msg: WireguardMessage<AmneziaWg> = WireguardMessage {
        cmd: WireguardCmd::SetDevice,
        attributes: vec![
            AmneziaWgAttribute::H1(0x1122), // u16
            AmneziaWgAttribute::S1(0x5566), // u16
        ],
    };

    let mut buffer = vec![0; msg.buffer_len()];
    msg.emit(&mut buffer);

    // H1 (type 14 / 0x0e, lenght 6): [06, 00, 0e, 00, 22, 11]
    assert!(buffer
        .windows(6)
        .any(|w| w == &[0x06, 0x00, 0x0e, 0x00, 0x22, 0x11]));

    // S1 (type 12 / 0x0c, length 6): [06, 00, 0c, 00, 66, 55]
    assert!(buffer
        .windows(6)
        .any(|w| w == &[0x06, 0x00, 0x0c, 0x00, 0x66, 0x55]));
}
