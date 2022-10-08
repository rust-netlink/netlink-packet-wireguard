// SPDX-License-Identifier: MIT

use crate::{
    constants::*,
    nlas::{WgPeer, WgPeerAttrs},
};
use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{Nla, NlaBuffer, NlasIterator},
    parsers::*,
    traits::*,
    DecodeError,
};
use std::{convert::TryInto, mem::size_of_val};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WgDeviceAttrs {
    Unspec(Vec<u8>),
    IfIndex(u32),
    IfName(String),
    PrivateKey([u8; WG_KEY_LEN]),
    PublicKey([u8; WG_KEY_LEN]),
    ListenPort(u16),
    Fwmark(u32),
    Peers(Vec<WgPeer>),
    Flags(u32),
}

impl Nla for WgDeviceAttrs {
    fn value_len(&self) -> usize {
        match self {
            WgDeviceAttrs::Unspec(bytes) => bytes.len(),
            WgDeviceAttrs::IfIndex(v) => size_of_val(v),
            WgDeviceAttrs::IfName(v) => v.as_bytes().len() + 1,
            WgDeviceAttrs::PrivateKey(v) => size_of_val(v),
            WgDeviceAttrs::PublicKey(v) => size_of_val(v),
            WgDeviceAttrs::ListenPort(v) => size_of_val(v),
            WgDeviceAttrs::Fwmark(v) => size_of_val(v),
            WgDeviceAttrs::Peers(nlas) => {
                nlas.iter().map(|op| op.buffer_len()).sum()
            }
            WgDeviceAttrs::Flags(v) => size_of_val(v),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            WgDeviceAttrs::Unspec(_) => WGDEVICE_A_UNSPEC,
            WgDeviceAttrs::IfIndex(_) => WGDEVICE_A_IFINDEX,
            WgDeviceAttrs::IfName(_) => WGDEVICE_A_IFNAME,
            WgDeviceAttrs::PrivateKey(_) => WGDEVICE_A_PRIVATE_KEY,
            WgDeviceAttrs::PublicKey(_) => WGDEVICE_A_PUBLIC_KEY,
            WgDeviceAttrs::ListenPort(_) => WGDEVICE_A_LISTEN_PORT,
            WgDeviceAttrs::Fwmark(_) => WGDEVICE_A_FWMARK,
            WgDeviceAttrs::Peers(_) => WGDEVICE_A_PEERS,
            WgDeviceAttrs::Flags(_) => WGDEVICE_A_FLAGS,
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            WgDeviceAttrs::Unspec(bytes) => buffer.copy_from_slice(bytes),
            WgDeviceAttrs::IfIndex(v) => NativeEndian::write_u32(buffer, *v),
            WgDeviceAttrs::IfName(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            WgDeviceAttrs::PrivateKey(v) => buffer.copy_from_slice(v),
            WgDeviceAttrs::PublicKey(v) => buffer.copy_from_slice(v),
            WgDeviceAttrs::ListenPort(v) => NativeEndian::write_u16(buffer, *v),
            WgDeviceAttrs::Fwmark(v) => NativeEndian::write_u32(buffer, *v),
            WgDeviceAttrs::Peers(nlas) => {
                let mut len = 0;
                for op in nlas {
                    op.emit(&mut buffer[len..]);
                    len += op.buffer_len();
                }
            }
            WgDeviceAttrs::Flags(v) => NativeEndian::write_u32(buffer, *v),
        }
    }

    fn is_nested(&self) -> bool {
        matches!(self, WgDeviceAttrs::Peers(_))
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for WgDeviceAttrs
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            WGDEVICE_A_UNSPEC => Self::Unspec(payload.to_vec()),
            WGDEVICE_A_IFINDEX => Self::IfIndex(
                parse_u32(payload)
                    .context("invalid WGDEVICE_A_IFINDEX value")?,
            ),
            WGDEVICE_A_IFNAME => Self::IfName(
                parse_string(payload)
                    .context("invalid WGDEVICE_A_IFNAME value")?,
            ),
            WGDEVICE_A_PRIVATE_KEY => Self::PrivateKey(
                payload
                    .try_into()
                    .context("invalid WGDEVICE_A_PRIVATE_KEY value")?,
            ),
            WGDEVICE_A_PUBLIC_KEY => Self::PublicKey(
                payload
                    .try_into()
                    .context("invalid WGDEVICE_A_PUBLIC_KEY value")?,
            ),
            WGDEVICE_A_LISTEN_PORT => Self::ListenPort(
                parse_u16(payload)
                    .context("invalid WGDEVICE_A_LISTEN_PORT value")?,
            ),
            WGDEVICE_A_FWMARK => Self::Fwmark(
                parse_u32(payload)
                    .context("invalid WGDEVICE_A_FWMARK value")?,
            ),
            WGDEVICE_A_PEERS => {
                let error_msg = "failed to parse WGDEVICE_A_PEERS";
                let mut peers = Vec::new();
                for nlas in NlasIterator::new(payload) {
                    let nlas = &nlas.context(error_msg)?;
                    let mut group = Vec::new();
                    for nla in NlasIterator::new(nlas.value()) {
                        let nla = &nla.context(error_msg)?;
                        let parsed =
                            WgPeerAttrs::parse(nla).context(error_msg)?;
                        group.push(parsed);
                    }
                    peers.push(WgPeer(group));
                }
                Self::Peers(peers)
            }
            WGDEVICE_A_FLAGS => Self::Flags(
                parse_u32(payload).context("invalid WGDEVICE_A_FLAGS value")?,
            ),
            kind => {
                return Err(DecodeError::from(format!(
                    "invalid NLA kind: {}",
                    kind
                )))
            }
        })
    }
}
