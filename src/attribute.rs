// SPDX-License-Identifier: MIT

use std::convert::TryInto;

use netlink_packet_core::{
    emit_u16, emit_u32, parse_string, parse_u16, parse_u32, DecodeError,
    DefaultNla, Emitable, ErrorContext, Nla, NlaBuffer, Parseable,
    NLA_F_NESTED,
};

use super::peer::WireguardPeers;
use crate::WireguardPeer;

const WG_KEY_LEN: usize = 32;

const WGDEVICE_A_IFINDEX: u16 = 1;
const WGDEVICE_A_IFNAME: u16 = 2;
const WGDEVICE_A_PRIVATE_KEY: u16 = 3;
const WGDEVICE_A_PUBLIC_KEY: u16 = 4;
const WGDEVICE_A_FLAGS: u16 = 5;
const WGDEVICE_A_LISTEN_PORT: u16 = 6;
const WGDEVICE_A_FWMARK: u16 = 7;
const WGDEVICE_A_PEERS: u16 = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WireguardAttribute {
    IfIndex(u32),
    IfName(String),
    PrivateKey([u8; WG_KEY_LEN]),
    PublicKey([u8; WG_KEY_LEN]),
    ListenPort(u16),
    Fwmark(u32),
    Peers(Vec<WireguardPeer>),
    Flags(u32),
    Other(DefaultNla),
}

impl WireguardAttribute {
    pub const WG_KEY_LEN: usize = WG_KEY_LEN;
}

impl Nla for WireguardAttribute {
    fn value_len(&self) -> usize {
        match self {
            Self::IfName(v) => v.len() + 1,
            Self::PrivateKey(_) | Self::PublicKey(_) => WG_KEY_LEN,
            Self::ListenPort(_) => 2,
            Self::Peers(v) => v.as_slice().buffer_len(),
            Self::Fwmark(_) | Self::IfIndex(_) | Self::Flags(_) => 4,
            Self::Other(v) => v.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::IfIndex(_) => WGDEVICE_A_IFINDEX,
            Self::IfName(_) => WGDEVICE_A_IFNAME,
            Self::PrivateKey(_) => WGDEVICE_A_PRIVATE_KEY,
            Self::PublicKey(_) => WGDEVICE_A_PUBLIC_KEY,
            Self::ListenPort(_) => WGDEVICE_A_LISTEN_PORT,
            Self::Fwmark(_) => WGDEVICE_A_FWMARK,
            Self::Peers(_) => WGDEVICE_A_PEERS | NLA_F_NESTED,
            Self::Flags(_) => WGDEVICE_A_FLAGS,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::IfIndex(v) => emit_u32(buffer, *v).unwrap(),
            Self::IfName(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            Self::PrivateKey(v) => buffer.copy_from_slice(v),
            Self::PublicKey(v) => buffer.copy_from_slice(v),
            Self::ListenPort(v) => emit_u16(buffer, *v).unwrap(),
            Self::Fwmark(v) => emit_u32(buffer, *v).unwrap(),
            Self::Peers(v) => v.as_slice().emit(buffer),
            Self::Flags(v) => emit_u32(buffer, *v).unwrap(),
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for WireguardAttribute
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
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
                    .map_err(|e: std::array::TryFromSliceError| {
                        DecodeError::from(e.to_string())
                    })
                    .context("invalid WGDEVICE_A_PRIVATE_KEY value")?,
            ),
            WGDEVICE_A_PUBLIC_KEY => Self::PublicKey(
                payload
                    .try_into()
                    .map_err(|e: std::array::TryFromSliceError| {
                        DecodeError::from(e.to_string())
                    })
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
            WGDEVICE_A_PEERS => Self::Peers(WireguardPeers::parse(buf)?.0),
            WGDEVICE_A_FLAGS => Self::Flags(
                parse_u32(payload).context("invalid WGDEVICE_A_FLAGS value")?,
            ),
            kind => Self::Other(
                DefaultNla::parse(buf)
                    .context(format!("unknown NLA type {kind}"))?,
            ),
        })
    }
}
