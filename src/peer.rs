// SPDX-License-Identifier: MIT

use std::{convert::TryInto, net::SocketAddr};

use bitflags::bitflags;
use netlink_packet_core::{
    append_bytes, append_i64, append_u16, append_u32, append_u64, parse_i64,
    parse_u16, parse_u32, parse_u64, DecodeError, DefaultNla, Emitable,
    EncodeError, ErrorContext, Nla, NlaBuffer, NlasIterator, Parseable,
    NLA_F_NESTED,
};

use super::{
    allowedip::WireguardAllowedIps,
    socket_addr::{emit_socket_addr, parse_socket_addr},
};
use crate::WireguardAllowedIp;
pub(crate) struct WireguardPeers(pub(crate) Vec<WireguardPeer>);

impl<'a> Parseable<NlaBuffer<'a>> for WireguardPeers {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let mut ret = Vec::new();
        for nla in NlasIterator::new(buf.value())? {
            ret.push(WireguardPeer::parse(&nla)?);
        }
        Ok(Self(ret))
    }
}

impl std::ops::Deref for WireguardPeers {
    type Target = Vec<WireguardPeer>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireguardPeer(pub Vec<WireguardPeerAttribute>);

impl<'a> Parseable<NlaBuffer<'a>> for WireguardPeer {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let mut ret = Vec::new();
        for nla in NlasIterator::new(buf.value())? {
            ret.push(WireguardPeerAttribute::parse(&nla)?);
        }
        Ok(Self(ret))
    }
}

impl Nla for WireguardPeer {
    fn kind(&self) -> u16 {
        // linux kernel always set it to 0
        NLA_F_NESTED
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.0.as_slice().emit(out)
    }
}

impl std::ops::Deref for WireguardPeer {
    type Target = Vec<WireguardPeerAttribute>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

const TIMESPEC_LEN: usize = 16;

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireguardTimeSpec {
    pub seconds: i64,
    pub nano_seconds: i64,
}

impl Emitable for WireguardTimeSpec {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_i64(out, self.seconds);
        append_i64(out, self.nano_seconds);
        Ok(())
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for WireguardTimeSpec {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let data = buf.value();
        if data.len() < TIMESPEC_LEN {
            Err(format!(
                "Invalid WGPEER_A_LAST_HANDSHAKE_TIME, expecting size {}, but \
                 got {:?}",
                TIMESPEC_LEN, data
            )
            .into())
        } else {
            Ok(Self {
                seconds: parse_i64(&data[..8])?,
                nano_seconds: parse_i64(&data[8..16])?,
            })
        }
    }
}

const NOISE_PUBLIC_KEY_LEN: usize = 32;
const NOISE_SYMMETRIC_KEY_LEN: usize = 32;

const WGPEER_A_PUBLIC_KEY: u16 = 1;
const WGPEER_A_PRESHARED_KEY: u16 = 2;
const WGPEER_A_FLAGS: u16 = 3;
const WGPEER_A_ENDPOINT: u16 = 4;
const WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: u16 = 5;
const WGPEER_A_LAST_HANDSHAKE_TIME: u16 = 6;
const WGPEER_A_RX_BYTES: u16 = 7;
const WGPEER_A_TX_BYTES: u16 = 8;
const WGPEER_A_ALLOWEDIPS: u16 = 9;
const WGPEER_A_PROTOCOL_VERSION: u16 = 10;

const WGPEER_F_REMOVE_ME: u32 = 1;
const WGPEER_F_REPLACE_ALLOWEDIPS: u32 = 2;
const WGPEER_F_UPDATE_ONLY: u32 = 4;

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[non_exhaustive]
    pub struct WireguardPeerFlags: u32 {
        const RemoveMe = WGPEER_F_REMOVE_ME;
        const ReplaceAllowedIps = WGPEER_F_REPLACE_ALLOWEDIPS;
        const UpdateOnly = WGPEER_F_UPDATE_ONLY;
        const _ = !0;
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WireguardPeerAttribute {
    PublicKey([u8; NOISE_PUBLIC_KEY_LEN]),
    PresharedKey([u8; NOISE_SYMMETRIC_KEY_LEN]),
    Endpoint(SocketAddr),
    PersistentKeepalive(u16),
    LastHandshake(WireguardTimeSpec),
    RxBytes(u64),
    TxBytes(u64),
    AllowedIps(Vec<WireguardAllowedIp>),
    ProtocolVersion(u32),
    Flags(WireguardPeerFlags),
    Other(DefaultNla),
}

impl Nla for WireguardPeerAttribute {
    fn kind(&self) -> u16 {
        match self {
            Self::PublicKey(_) => WGPEER_A_PUBLIC_KEY,
            Self::PresharedKey(_) => WGPEER_A_PRESHARED_KEY,
            Self::Endpoint(_) => WGPEER_A_ENDPOINT,
            Self::PersistentKeepalive(_) => {
                WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL
            }
            Self::LastHandshake(_) => WGPEER_A_LAST_HANDSHAKE_TIME,
            Self::RxBytes(_) => WGPEER_A_RX_BYTES,
            Self::TxBytes(_) => WGPEER_A_TX_BYTES,
            Self::AllowedIps(_) => WGPEER_A_ALLOWEDIPS | NLA_F_NESTED,
            Self::ProtocolVersion(_) => WGPEER_A_PROTOCOL_VERSION,
            Self::Flags(_) => WGPEER_A_FLAGS,
            Self::Other(v) => v.kind(),
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::PublicKey(v) => append_bytes(out, v),
            Self::PresharedKey(v) => append_bytes(out, v),
            Self::Endpoint(v) => emit_socket_addr(v, out),
            Self::PersistentKeepalive(v) => append_u16(out, *v),
            Self::LastHandshake(v) => v.emit(out)?,
            Self::RxBytes(v) => append_u64(out, *v),
            Self::TxBytes(v) => append_u64(out, *v),
            Self::AllowedIps(v) => v.as_slice().emit(out)?,
            Self::ProtocolVersion(v) => append_u32(out, *v),
            Self::Flags(v) => append_u32(out, v.bits()),
            Self::Other(v) => return v.emit_value(out),
        }
        Ok(())
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for WireguardPeerAttribute {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            WGPEER_A_PUBLIC_KEY => Self::PublicKey(
                payload
                    .try_into()
                    .map_err(|e: std::array::TryFromSliceError| {
                        DecodeError::from(e.to_string())
                    })
                    .context("invalid WGPEER_A_PUBLIC_KEY")?,
            ),
            WGPEER_A_PRESHARED_KEY => Self::PresharedKey(
                payload
                    .try_into()
                    .map_err(|e: std::array::TryFromSliceError| {
                        DecodeError::from(e.to_string())
                    })
                    .context("invalid WGPEER_A_PRESHARED_KEY")?,
            ),
            WGPEER_A_ENDPOINT => Self::Endpoint(
                parse_socket_addr(payload)
                    .context("invalid WGPEER_A_ENDPOINT")?,
            ),
            WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL => {
                Self::PersistentKeepalive(parse_u16(payload).context(
                    "invalid WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL value",
                )?)
            }
            WGPEER_A_LAST_HANDSHAKE_TIME => Self::LastHandshake(
                WireguardTimeSpec::parse(buf)
                    .context("invalid WGPEER_A_LAST_HANDSHAKE_TIME")?,
            ),
            WGPEER_A_RX_BYTES => Self::RxBytes(
                parse_u64(payload)
                    .context("invalid WGPEER_A_RX_BYTES value")?,
            ),
            WGPEER_A_TX_BYTES => Self::TxBytes(
                parse_u64(payload)
                    .context("invalid WGPEER_A_TX_BYTES value")?,
            ),
            WGPEER_A_ALLOWEDIPS => {
                Self::AllowedIps(WireguardAllowedIps::parse(buf)?.0)
            }
            WGPEER_A_PROTOCOL_VERSION => Self::ProtocolVersion(
                parse_u32(payload)
                    .context("invalid WGPEER_A_PROTOCOL_VERSION value")?,
            ),
            WGPEER_A_FLAGS => {
                Self::Flags(WireguardPeerFlags::from_bits_retain(
                    parse_u32(payload)
                        .context("invalid WGPEER_A_FLAGS value")?,
                ))
            }
            kind => Self::Other(
                DefaultNla::parse(buf)
                    .context(format!("unknown NLA type {kind}"))?,
            ),
        })
    }
}
