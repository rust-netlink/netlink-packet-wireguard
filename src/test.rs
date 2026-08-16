// SPDX-License-Identifier: MIT

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use netlink_packet_core::{Emitable, ParseableParametrized};
use netlink_packet_generic::GenlHeader;
use pretty_assertions::assert_eq;

use crate::{
    WireguardAddressFamily, WireguardAllowedIp, WireguardAllowedIpAttr,
    WireguardAttribute, WireguardCmd, WireguardDeviceFlags, WireguardMessage,
    WireguardPeer, WireguardPeerAttribute, WireguardPeerFlags,
    WireguardTimeSpec,
};

// nlmon capture of netlink packet sent by `sudo wg` command with netlink
// header purged(generic netlink command is first byte).
#[test]
fn test_query_request() {
    let raw: Vec<u8> = vec![
        0x00, 0x01, 0x00, 0x00, 0x07, 0x00, 0x02, 0x00, 0x63, 0x6e, 0x00, 0x00,
    ];

    let expected = WireguardMessage {
        cmd: WireguardCmd::GetDevice,
        attributes: vec![WireguardAttribute::IfName("cn".to_string())],
    };

    let header = GenlHeader::parse(&raw[..]).unwrap();

    assert_eq!(
        expected,
        WireguardMessage::parse_with_param(&raw[4..], header).unwrap(),
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

    let expected = WireguardMessage {
        cmd: WireguardCmd::GetDevice,
        attributes: vec![
            WireguardAttribute::ListenPort(32812),
            WireguardAttribute::Fwmark(0),
            WireguardAttribute::IfIndex(3),
            WireguardAttribute::IfName("cn".to_string()),
            WireguardAttribute::PrivateKey([
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
                18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
            ]),
            WireguardAttribute::PublicKey([
                204, 175, 16, 225, 169, 215, 208, 95, 242, 189, 210, 160, 241,
                120, 45, 151, 70, 154, 28, 247, 190, 136, 15, 104, 117, 167,
                121, 147, 93, 29, 33, 117,
            ]),
            WireguardAttribute::Peers(vec![WireguardPeer(vec![
                WireguardPeerAttribute::PublicKey([
                    119, 220, 154, 192, 179, 240, 197, 231, 91, 184, 211, 66,
                    45, 136, 236, 146, 209, 58, 52, 35, 34, 144, 135, 130, 21,
                    81, 87, 25, 105, 222, 160, 68,
                ]),
                WireguardPeerAttribute::PresharedKey([
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
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
                WireguardPeerAttribute::AllowedIps(vec![WireguardAllowedIp(
                    vec![
                        WireguardAllowedIpAttr::Cidr(0),
                        WireguardAllowedIpAttr::Family(
                            WireguardAddressFamily::Ipv4,
                        ),
                        WireguardAllowedIpAttr::IpAddr(IpAddr::V4(
                            Ipv4Addr::UNSPECIFIED,
                        )),
                    ],
                )]),
            ])]),
        ],
    };

    let header = GenlHeader::parse(&raw[..]).unwrap();

    assert_eq!(
        expected,
        WireguardMessage::parse_with_param(&raw[4..], header).unwrap(),
    );

    let mut buffer = vec![0; expected.buffer_len() + header.buffer_len()];
    header.emit(&mut buffer);
    expected.emit(&mut buffer[4..]);
    assert_eq!(&buffer, &raw);
}

// nlmon capture of kernel netlink packet reply of `sudo wg setconf` command
// against existing wireguard interface
#[test]
fn test_setconf_against_exiting_wg() {
    let raw: Vec<u8> = vec![
        0x01, 0x01, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00, 0x77, 0x67, 0x30, 0x00,
        0x24, 0x00, 0x03, 0x00, 0x08, 0xf8, 0x74, 0x0f, 0xc2, 0x87, 0xda, 0x7a,
        0x1c, 0x44, 0xfc, 0x1a, 0x73, 0x5c, 0xec, 0xf3, 0xb0, 0x9e, 0x33, 0x81,
        0x18, 0x22, 0x08, 0x75, 0x34, 0x8b, 0x88, 0xac, 0x75, 0x5b, 0xfe, 0x59,
        0x06, 0x00, 0x06, 0x00, 0x03, 0xd9, 0x00, 0x00, 0x08, 0x00, 0x07, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x7c, 0x00, 0x08, 0x80, 0x78, 0x00, 0x00, 0x80, 0x24, 0x00, 0x01, 0x00,
        0x7b, 0xff, 0x32, 0x8c, 0x65, 0x6b, 0x0d, 0xa2, 0x38, 0x58, 0x16, 0xee,
        0x0b, 0x47, 0xe9, 0xdc, 0x5b, 0xba, 0x3b, 0xf7, 0x79, 0x82, 0xd8, 0xdc,
        0x99, 0x34, 0x73, 0xed, 0xe5, 0x72, 0xb4, 0x0f, 0x08, 0x00, 0x03, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x48, 0x00, 0x09, 0x80, 0x1c, 0x00, 0x00, 0x80,
        0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00,
        0xc0, 0x00, 0x02, 0x02, 0x05, 0x00, 0x03, 0x00, 0x20, 0x00, 0x00, 0x00,
        0x28, 0x00, 0x00, 0x80, 0x06, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x02, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x05, 0x00, 0x03, 0x00,
        0x80, 0x00, 0x00, 0x00,
    ];

    let expected = WireguardMessage {
        cmd: WireguardCmd::SetDevice,
        attributes: vec![
            WireguardAttribute::IfName("wg0".to_string()),
            WireguardAttribute::PrivateKey([
                8, 248, 116, 15, 194, 135, 218, 122, 28, 68, 252, 26, 115, 92,
                236, 243, 176, 158, 51, 129, 24, 34, 8, 117, 52, 139, 136, 172,
                117, 91, 254, 89,
            ]),
            WireguardAttribute::ListenPort(55555),
            WireguardAttribute::Fwmark(0),
            WireguardAttribute::Flags(WireguardDeviceFlags::ReplacePeers),
            WireguardAttribute::Peers(vec![WireguardPeer(vec![
                WireguardPeerAttribute::PublicKey([
                    123, 255, 50, 140, 101, 107, 13, 162, 56, 88, 22, 238, 11,
                    71, 233, 220, 91, 186, 59, 247, 121, 130, 216, 220, 153,
                    52, 115, 237, 229, 114, 180, 15,
                ]),
                WireguardPeerAttribute::Flags(
                    WireguardPeerFlags::ReplaceAllowedIps,
                ),
                WireguardPeerAttribute::AllowedIps(vec![
                    WireguardAllowedIp(vec![
                        WireguardAllowedIpAttr::Family(
                            WireguardAddressFamily::Ipv4,
                        ),
                        WireguardAllowedIpAttr::IpAddr(IpAddr::V4(
                            Ipv4Addr::new(192, 0, 2, 2),
                        )),
                        WireguardAllowedIpAttr::Cidr(32),
                    ]),
                    WireguardAllowedIp(vec![
                        WireguardAllowedIpAttr::Family(
                            WireguardAddressFamily::Ipv6,
                        ),
                        WireguardAllowedIpAttr::IpAddr(IpAddr::V6(
                            Ipv6Addr::from_str("2001:db8:1::2").unwrap(),
                        )),
                        WireguardAllowedIpAttr::Cidr(128),
                    ]),
                ]),
            ])]),
        ],
    };

    let header = GenlHeader::parse(&raw[..]).unwrap();

    assert_eq!(
        expected,
        WireguardMessage::parse_with_param(&raw[4..], header).unwrap(),
    );

    let mut buffer = vec![0; expected.buffer_len() + header.buffer_len()];
    header.emit(&mut buffer);
    expected.emit(&mut buffer[4..]);
    assert_eq!(&buffer, &raw);
}
