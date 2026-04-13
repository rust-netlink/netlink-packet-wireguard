// SPDX-License-Identifier: MIT

use std::env::args;

use futures::StreamExt;
use genetlink::new_connection;
use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_REQUEST,
};
use netlink_packet_generic::GenlMessage;
use netlink_packet_wireguard::{
    AmneziaWg, AmneziaWgAttribute, WgFamily, WireguardAllowedIp,
    WireguardAllowedIpAttr, WireguardCmd, WireguardMessage,
    WireguardPeerAttribute,
};

#[tokio::main]
async fn main() {
    env_logger::init();

    let argv: Vec<String> = args().collect();
    if argv.len() < 2 {
        eprintln!("Usage: get_amneziawg_info <ifname>");
        return;
    }

    let (connection, mut handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    let msg: WireguardMessage<AmneziaWg> = WireguardMessage {
        cmd: WireguardCmd::GetDevice,
        attributes: vec![AmneziaWgAttribute::IfName(argv[1].clone())],
    };

    let genlmsg: GenlMessage<WireguardMessage<AmneziaWg>> =
        GenlMessage::from_payload(msg);
    let mut nlmsg = NetlinkMessage::from(genlmsg);
    nlmsg.header.flags = NLM_F_REQUEST | NLM_F_DUMP;

    let mut res = handle.request(nlmsg).await.unwrap();

    while let Some(result) = res.next().await {
        let rx_packet = result.unwrap();
        match rx_packet.payload {
            NetlinkPayload::InnerMessage(genlmsg) => {
                print_wg_payload(genlmsg.payload);
            }
            NetlinkPayload::Error(e) => {
                eprintln!("Error: {:?}", e.to_io());
            }
            _ => (),
        };
    }
}

fn print_wg_payload<F: WgFamily<Attribute = AmneziaWgAttribute>>(
    wg: WireguardMessage<F>,
) {
    for attr in &wg.attributes {
        match attr {
            AmneziaWgAttribute::IfIndex(v) => println!("IfIndex: {}", v),
            AmneziaWgAttribute::IfName(v) => println!("IfName: {}", v),
            AmneziaWgAttribute::PrivateKey(_) => {
                println!("PrivateKey: (hidden)")
            }
            AmneziaWgAttribute::PublicKey(v) => {
                println!("PublicKey: {}", base64::encode(v))
            }
            AmneziaWgAttribute::ListenPort(v) => {
                println!("ListenPort: {}", v)
            }
            AmneziaWgAttribute::Fwmark(v) => println!("Fwmark: {}", v),
            AmneziaWgAttribute::Peers(peers) => {
                for peer in peers {
                    println!("Peer: ");
                    print_wg_peer(&peer);
                }
            }
            AmneziaWgAttribute::JC(v) => {
                println!("JunkCount: {}", v)
            }
            AmneziaWgAttribute::Jmin(v) => {
                println!("JunkPacketMinSize: {}", v)
            }
            AmneziaWgAttribute::Jmax(v) => {
                println!("JunkPacketMaxSize: {}", v)
            }
            _ => (),
        }
    }
}

fn print_wg_peer(attrs: &[WireguardPeerAttribute]) {
    for attr in attrs {
        match attr {
            WireguardPeerAttribute::PublicKey(v) => {
                println!("  PublicKey: {}", base64::encode(v))
            }
            WireguardPeerAttribute::PresharedKey(_) => {
                println!("  PresharedKey: (hidden)")
            }
            WireguardPeerAttribute::Endpoint(v) => {
                println!("  Endpoint: {}", v)
            }
            WireguardPeerAttribute::PersistentKeepalive(v) => {
                println!("  PersistentKeepalive: {}", v)
            }
            WireguardPeerAttribute::LastHandshake(v) => {
                println!("  LastHandshake: {:?}", v)
            }
            WireguardPeerAttribute::RxBytes(v) => println!("  RxBytes: {}", v),
            WireguardPeerAttribute::TxBytes(v) => println!("  TxBytes: {}", v),
            WireguardPeerAttribute::AllowedIps(ips) => {
                for ip in ips {
                    print_wg_allowedip(&ip);
                }
            }
            _ => (),
        }
    }
}

fn print_wg_allowedip(nlas: &WireguardAllowedIp) -> Option<()> {
    let ipaddr = nlas.iter().find_map(|nla| {
        if let WireguardAllowedIpAttr::IpAddr(addr) = nla {
            Some(*addr)
        } else {
            None
        }
    })?;
    let cidr = nlas.iter().find_map(|nla| {
        if let WireguardAllowedIpAttr::Cidr(cidr) = nla {
            Some(*cidr)
        } else {
            None
        }
    })?;
    println!("  AllowedIp: {}/{}", ipaddr, cidr);
    Some(())
}
