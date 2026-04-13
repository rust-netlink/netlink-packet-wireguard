// SPDX-License-Identifier: MIT

use std::env::args;

use futures::StreamExt;
use genetlink::new_connection;
use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_REQUEST,
};
use netlink_packet_generic::GenlMessage;
use netlink_packet_wireguard::{
    WireguardAllowedIpAttr, WireguardAttribute, WireguardCmd, WireguardMessage,
    WireguardPeerAttribute,
};

#[tokio::main]
async fn main() {
    env_logger::init();

    let argv: Vec<String> = args().collect();
    if argv.len() < 2 {
        eprintln!("Usage: get_amnezia_wg_info <ifname>");
        return;
    }

    let (connection, mut handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    use netlink_packet_wireguard::AmneziaWg;

    let msg: WireguardMessage<AmneziaWg> = WireguardMessage::new(
        WireguardCmd::GetDevice,
        vec![WireguardAttribute::IfName(argv[1].clone())],
    );

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

fn print_wg_payload<F: netlink_packet_wireguard::WgFamily>(
    wg: WireguardMessage<F>,
) {
    for attr in &wg.attributes {
        match attr {
            WireguardAttribute::IfIndex(v) => println!("IfIndex: {}", v),
            WireguardAttribute::IfName(v) => println!("IfName: {}", v),
            WireguardAttribute::PrivateKey(_) => {
                println!("PrivateKey: (hidden)")
            }
            WireguardAttribute::PublicKey(v) => {
                println!("PublicKey: {}", base64::encode(v))
            }
            WireguardAttribute::ListenPort(v) => {
                println!("ListenPort: {}", v)
            }
            WireguardAttribute::Fwmark(v) => println!("Fwmark: {}", v),
            WireguardAttribute::Peers(peers) => {
                for peer in peers {
                    println!("Peer: ");
                    print_wg_peer(peer);
                }
            }
            WireguardAttribute::JC(v) => {
                println!("JunkCount: {}", v)
            }
            WireguardAttribute::Jmin(v) => {
                println!("JunkPacketMinSize: {}", v)
            }
            WireguardAttribute::Jmax(v) => {
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
                    print_wg_allowedip(ip);
                }
            }
            _ => (),
        }
    }
}

fn print_wg_allowedip(nlas: &[WireguardAllowedIpAttr]) -> Option<()> {
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
