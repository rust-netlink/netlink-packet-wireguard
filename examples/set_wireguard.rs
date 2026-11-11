// SPDX-License-Identifier: MIT

mod common;

use std::{
    convert::TryInto,
    env::args,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use base64::prelude::{Engine as _, BASE64_STANDARD};
use netlink_packet_core::{
    Emitable, NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_REQUEST,
};
use netlink_packet_generic::GenlMessage;
use netlink_packet_wireguard::{
    WireguardAddressFamily, WireguardAllowedIp, WireguardAllowedIpAttr,
    WireguardAttribute, WireguardCmd, WireguardMessage, WireguardPeer,
    WireguardPeerAttribute,
};
use netlink_sys::{
    protocols::NETLINK_GENERIC, Socket, SocketAddr as NlSocketAddr,
};

fn main() {
    let argv: Vec<String> = args().collect();
    if argv.len() < 2 {
        eprintln!("Usage: set_wireguard <ifname>");
        return;
    }

    // The wireguard interface need to exist before executing this code.
    // This can be done with `ip link <name> type wireguard` command.
    let name = argv[1].clone();
    let priv_key = generate_priv_key();
    let peer_pub_key: [u8; WireguardAttribute::WG_KEY_LEN] = BASE64_STANDARD
        .decode("8bdQrVLqiw3ZoHCucNh1YfH0iCWuyStniRr8t7H24Fk=")
        .unwrap()
        .try_into()
        .unwrap();

    let mut socket = Socket::new(NETLINK_GENERIC).unwrap();
    socket.bind_auto().unwrap();
    socket.connect(&NlSocketAddr::new(0, 0)).unwrap();

    let family_id = common::resolve_family_id(&mut socket, "wireguard");

    let attributes = vec![
        WireguardAttribute::IfName(name),
        WireguardAttribute::PrivateKey(priv_key),
        WireguardAttribute::ListenPort(51820),
        WireguardAttribute::Fwmark(0),
        WireguardAttribute::Peers(vec![WireguardPeer(vec![
            WireguardPeerAttribute::PublicKey(peer_pub_key),
            WireguardPeerAttribute::Endpoint(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(10, 10, 10, 1)),
                51820,
            )),
            WireguardPeerAttribute::AllowedIps(vec![
                WireguardAllowedIp(vec![
                    // ipv4 0.0.0.0/0
                    WireguardAllowedIpAttr::Family(
                        WireguardAddressFamily::Ipv4,
                    ),
                    WireguardAllowedIpAttr::IpAddr("0.0.0.0".parse().unwrap()),
                    WireguardAllowedIpAttr::Cidr(0),
                ]),
                WireguardAllowedIp(vec![
                    // ipv6 ::/0
                    WireguardAllowedIpAttr::Family(
                        WireguardAddressFamily::Ipv6,
                    ),
                    WireguardAllowedIpAttr::IpAddr("::".parse().unwrap()),
                    WireguardAllowedIpAttr::Cidr(0),
                ]),
            ]),
        ])]),
    ];

    let mut genlmsg: GenlMessage<WireguardMessage> =
        GenlMessage::from_payload(WireguardMessage {
            cmd: WireguardCmd::SetDevice,
            attributes,
        });
    genlmsg.set_resolved_family_id(family_id);
    let mut nlmsg = NetlinkMessage::from(genlmsg);
    nlmsg.header.flags = NLM_F_REQUEST | NLM_F_ACK;

    let mut txbuf = Vec::new();
    nlmsg.emit(&mut txbuf).unwrap();
    socket.send(&txbuf, 0).unwrap();

    let mut rxbuf = Vec::with_capacity(8192);
    socket.recv(&mut rxbuf, 0).unwrap();
    let rx_packet =
        <NetlinkMessage<GenlMessage<WireguardMessage>>>::deserialize(&rxbuf)
            .unwrap();
    if let NetlinkPayload::Error(err) = rx_packet.payload {
        eprintln!("Error: {:?}", err.to_io());
    }
}

fn generate_priv_key() -> [u8; WireguardAttribute::WG_KEY_LEN] {
    let mut key = [0u8; WireguardAttribute::WG_KEY_LEN];
    getrandom::fill(&mut key).unwrap();
    // modify random bytes using algorithm described
    // at https://cr.yp.to/ecdh.html.
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;
    key
}
