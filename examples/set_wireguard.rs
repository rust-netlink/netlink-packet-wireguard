// SPDX-License-Identifier: MIT

use futures::StreamExt;
use genetlink::new_connection;
use getrandom;
use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_REQUEST,
};
use netlink_packet_generic::GenlMessage;
use netlink_packet_wireguard::constants::*;
use netlink_packet_wireguard::{nlas::WgDeviceAttrs, Wireguard, WireguardCmd};
use std::env::args;

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

    let (connection, mut handle, _) = new_connection().unwrap();
    let _ = tokio::spawn(connection);

    let nlas = vec![
        WgDeviceAttrs::IfName(name),
        WgDeviceAttrs::PrivateKey(priv_key),
        WgDeviceAttrs::ListenPort(51820),
    ];

    let genlmsg: GenlMessage<Wireguard> =
        GenlMessage::from_payload(Wireguard {
            cmd: WireguardCmd::SetDevice,
            nlas,
        });
    let mut nlmsg = NetlinkMessage::from(genlmsg);
    nlmsg.header.flags = NLM_F_REQUEST | NLM_F_ACK;

    let mut res = handle.request(nlmsg).await.unwrap();

    if let Some(result) = res.next().await {
        let rx_packet = result.unwrap();
        match rx_packet.payload {
            NetlinkPayload::Error(e) => {
                eprintln!("Error: {:?}", e.to_io());
            }
            _ => (),
        }
    }
}

fn generate_priv_key() -> [u8; WG_KEY_LEN] {
    let mut key = [0u8; WG_KEY_LEN];
    getrandom::getrandom(&mut key).unwrap();
    // modify random bytes using algorithm described
    // at https://cr.yp.to/ecdh.html.
    key[0] = key[0] & 248;
    key[31] = key[31] & 127;
    key[31] = key[31] | 64;
    key
}
