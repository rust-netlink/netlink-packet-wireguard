// SPDX-License-Identifier: MIT

//! The `netlink-packet-wireguard` crate is designed to paring and emitting
//! generic netlink packet for wireguard interface. The goal of this crate is
//! saving crate user from reading kernel netlink codes.

mod allowedip;
mod attribute;
mod message;
mod peer;
mod socket_addr;

#[cfg(test)]
mod test;

pub use self::{
    allowedip::{
        WireguardAddressFamily, WireguardAllowedIp, WireguardAllowedIpAttr,
    },
    attribute::WireguardAttribute,
    message::{WireguardCmd, WireguardMessage},
    peer::{WireguardPeer, WireguardPeerAttribute, WireguardTimeSpec},
};
