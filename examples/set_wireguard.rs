// SPDX-License-Identifier: MIT

use std::{
    convert::TryInto,
    env::args,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use base64::prelude::{Engine as _, BASE64_STANDARD};
use futures::StreamExt;
use genetlink::new_connection;
use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_REQUEST,
};
use netlink_packet_generic::GenlMessage;
use netlink_packet_wireguard::{
    WireguardAddressFamily, WireguardAllowedIp, WireguardAllowedIpAttr,
    WireguardAttribute, WireguardCmd, WireguardMessage, WireguardPeer,
    WireguardPeerAttribute,
};

#[tokio::main]
async fn main() {
    env_logger::init();

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

    let (connection, mut handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

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

    let genlmsg: GenlMessage<WireguardMessage> =
        GenlMessage::from_payload(WireguardMessage {
            cmd: WireguardCmd::SetDevice,
            attributes,
        });
    let mut nlmsg = NetlinkMessage::from(genlmsg);
    nlmsg.header.flags = NLM_F_REQUEST | NLM_F_ACK;

    let mut res = handle.request(nlmsg).await.unwrap();

    if let Some(result) = res.next().await {
        let rx_packet = result.unwrap();
        if let NetlinkPayload::Error(e) = rx_packet.payload {
            eprintln!("Error: {:?}", e.to_io());
        }
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
