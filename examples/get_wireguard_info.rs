// SPDX-License-Identifier: MIT

mod common;

use std::env::args;

use base64::prelude::{Engine as _, BASE64_STANDARD};
use netlink_packet_core::{
    Emitable, NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_REQUEST,
};
use netlink_packet_generic::GenlMessage;
use netlink_packet_wireguard::{
    WireguardAllowedIpAttr, WireguardAttribute, WireguardCmd, WireguardMessage,
    WireguardPeerAttribute,
};
use netlink_sys::{protocols::NETLINK_GENERIC, Socket, SocketAddr};

fn main() {
    let argv: Vec<String> = args().collect();
    if argv.len() < 2 {
        eprintln!("Usage: get_wireguard_info <ifname>");
        return;
    }

    let mut socket = Socket::new(NETLINK_GENERIC).unwrap();
    socket.bind_auto().unwrap();
    socket.connect(&SocketAddr::new(0, 0)).unwrap();

    let family_id = common::resolve_family_id(&mut socket, "wireguard");

    let mut genlmsg: GenlMessage<WireguardMessage> =
        GenlMessage::from_payload(WireguardMessage {
            cmd: WireguardCmd::GetDevice,
            attributes: vec![WireguardAttribute::IfName(argv[1].clone())],
        });
    genlmsg.set_resolved_family_id(family_id);
    let mut nlmsg = NetlinkMessage::from(genlmsg);
    nlmsg.header.flags = NLM_F_REQUEST | NLM_F_DUMP;

    let mut txbuf = Vec::new();
    nlmsg.emit(&mut txbuf).unwrap();
    socket.send(&txbuf, 0).unwrap();

    let mut rxbuf = Vec::with_capacity(8192);
    let mut offset = 0;
    let mut size = 0;
    'outer: loop {
        size += socket.recv(&mut rxbuf, 0).unwrap();

        loop {
            let buf = &rxbuf[offset..];
            let msg =
                <NetlinkMessage<GenlMessage<WireguardMessage>>>::deserialize(
                    buf,
                )
                .unwrap();

            match msg.payload {
                NetlinkPayload::Done(_) => break 'outer,
                NetlinkPayload::InnerMessage(genlmsg) => {
                    print_wg_payload(genlmsg.payload);
                }
                NetlinkPayload::Error(err) => {
                    eprintln!("Received a netlink error message: {err:?}");
                    return;
                }
                _ => {}
            }

            offset += msg.header.length as usize;
            if offset == size || msg.header.length == 0 {
                break;
            }
        }
    }
}

fn print_wg_payload(wg: WireguardMessage) {
    for attr in &wg.attributes {
        match attr {
            WireguardAttribute::IfIndex(v) => println!("IfIndex: {}", v),
            WireguardAttribute::IfName(v) => println!("IfName: {}", v),
            WireguardAttribute::PrivateKey(_) => {
                println!("PrivateKey: (hidden)")
            }
            WireguardAttribute::PublicKey(v) => {
                println!("PublicKey: {}", BASE64_STANDARD.encode(v))
            }
            WireguardAttribute::ListenPort(v) => println!("ListenPort: {}", v),
            WireguardAttribute::Fwmark(v) => println!("Fwmark: {}", v),
            WireguardAttribute::Peers(peers) => {
                for peer in peers {
                    println!("Peer: ");
                    print_wg_peer(peer);
                }
            }
            _ => (),
        }
    }
}

fn print_wg_peer(attrs: &[WireguardPeerAttribute]) {
    for attr in attrs {
        match attr {
            WireguardPeerAttribute::PublicKey(v) => {
                println!("  PublicKey: {}", BASE64_STANDARD.encode(v))
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
