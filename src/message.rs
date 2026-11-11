// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, Emitable, EncodeError, NlasIterator, Parseable,
    ParseableParametrized,
};
use netlink_packet_generic::{GenlFamily, GenlHeader};

use crate::WireguardAttribute;
const WG_CMD_GET_DEVICE: u8 = 0;
const WG_CMD_SET_DEVICE: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WireguardCmd {
    GetDevice,
    SetDevice,
    Other(u8),
}

impl From<WireguardCmd> for u8 {
    fn from(cmd: WireguardCmd) -> Self {
        match cmd {
            WireguardCmd::GetDevice => WG_CMD_GET_DEVICE,
            WireguardCmd::SetDevice => WG_CMD_SET_DEVICE,
            WireguardCmd::Other(d) => d,
        }
    }
}

impl From<u8> for WireguardCmd {
    fn from(value: u8) -> Self {
        match value {
            WG_CMD_GET_DEVICE => Self::GetDevice,
            WG_CMD_SET_DEVICE => Self::SetDevice,
            cmd => Self::Other(cmd),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireguardMessage {
    pub cmd: WireguardCmd,
    pub attributes: Vec<WireguardAttribute>,
}

impl GenlFamily for WireguardMessage {
    fn family_name() -> &'static str {
        "wireguard"
    }

    fn version(&self) -> u8 {
        1
    }

    fn command(&self) -> u8 {
        self.cmd.into()
    }
}

impl Emitable for WireguardMessage {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.attributes.as_slice().emit(out)
    }
}

impl ParseableParametrized<[u8], GenlHeader> for WireguardMessage {
    fn parse_with_param(
        buf: &[u8],
        header: GenlHeader,
    ) -> Result<Self, DecodeError> {
        Ok(Self {
            cmd: header.cmd.into(),
            attributes: parse_attributes(buf)?,
        })
    }
}

fn parse_attributes(
    buf: &[u8],
) -> Result<Vec<WireguardAttribute>, DecodeError> {
    let mut attributes = Vec::new();
    for nla in NlasIterator::new(buf)? {
        attributes.push(WireguardAttribute::parse(&nla)?);
    }
    Ok(attributes)
}
