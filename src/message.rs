// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, Emitable, ErrorContext, NlasIterator, Parseable,
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

pub trait WgFamily: Default + Clone + std::fmt::Debug {
    const NAME: &'static str;
    const VERSION: u8;
}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct StandardWg;
impl WgFamily for StandardWg {
    const NAME: &'static str = "wireguard";
    const VERSION: u8 = 1;
}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct AmneziaWg;
impl WgFamily for AmneziaWg {
    const NAME: &'static str = "amneziawg";
    const VERSION: u8 = 2;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireguardMessage<F: WgFamily = StandardWg> {
    pub cmd: WireguardCmd,
    pub attributes: Vec<WireguardAttribute>,
    _phantom: std::marker::PhantomData<F>,
}

impl<F: WgFamily> WireguardMessage<F> {
    pub fn new(cmd: WireguardCmd, attributes: Vec<WireguardAttribute>) -> Self {
        Self {
            cmd,
            attributes,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<F: WgFamily> GenlFamily for WireguardMessage<F> {
    fn family_name() -> &'static str {
        F::NAME
    }

    fn version(&self) -> u8 {
        F::VERSION
    }

    fn command(&self) -> u8 {
        self.cmd.into()
    }
}

impl<F: WgFamily> Emitable for WireguardMessage<F> {
    fn emit(&self, buffer: &mut [u8]) {
        self.attributes.as_slice().emit(buffer)
    }

    fn buffer_len(&self) -> usize {
        self.attributes.as_slice().buffer_len()
    }
}

impl<F: WgFamily> ParseableParametrized<[u8], GenlHeader>
    for WireguardMessage<F>
{
    fn parse_with_param(
        buf: &[u8],
        header: GenlHeader,
    ) -> Result<Self, DecodeError> {
        Ok(Self {
            cmd: header.cmd.into(),
            attributes: parse_attributes(buf)?,
            _phantom: std::marker::PhantomData, // Обязательно добавляем это
        })
    }
}

fn parse_attributes(
    buf: &[u8],
) -> Result<Vec<WireguardAttribute>, DecodeError> {
    let mut attributes = Vec::new();
    let error_msg = "failed to parse wireguard netlink attributes";
    for nla in NlasIterator::new(buf) {
        let nla = &nla.context(error_msg)?;
        let parsed = WireguardAttribute::parse(nla)?;
        attributes.push(parsed);
    }
    Ok(attributes)
}
