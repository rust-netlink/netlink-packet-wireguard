// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    Emitable, NetlinkMessage, NetlinkPayload, NLM_F_REQUEST,
};
use netlink_packet_generic::{
    ctrl::{nlas::GenlCtrlAttrs, GenlCtrl, GenlCtrlCmd},
    GenlMessage,
};
use netlink_sys::Socket;

/// Resolve the dynamic generic netlink family id by name.
pub fn resolve_family_id(socket: &mut Socket, family_name: &str) -> u16 {
    let genlmsg: GenlMessage<GenlCtrl> = GenlMessage::from_payload(GenlCtrl {
        cmd: GenlCtrlCmd::GetFamily,
        nlas: vec![GenlCtrlAttrs::FamilyName(family_name.to_string())],
    });
    let mut nlmsg = NetlinkMessage::from(genlmsg);
    nlmsg.header.flags = NLM_F_REQUEST;

    let mut txbuf = Vec::new();
    nlmsg.emit(&mut txbuf).unwrap();
    socket.send(&txbuf, 0).unwrap();

    loop {
        let mut rxbuf = Vec::with_capacity(8192);
        socket.recv(&mut rxbuf, 0).unwrap();
        let msg = <NetlinkMessage<GenlMessage<GenlCtrl>>>::deserialize(&rxbuf)
            .unwrap();
        match msg.payload {
            NetlinkPayload::InnerMessage(genlmsg) => {
                for nla in genlmsg.payload.nlas {
                    if let GenlCtrlAttrs::FamilyId(id) = nla {
                        return id;
                    }
                }
            }
            NetlinkPayload::Error(err) => {
                panic!("failed to resolve family {family_name}: {err:?}");
            }
            _ => {}
        }
    }
}
