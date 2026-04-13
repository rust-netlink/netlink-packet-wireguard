use netlink_packet_core::{
    DecodeError, Emitable, ErrorContext, Nla, NlaBuffer, NlasIterator,
    Parseable, ParseableParametrized,
};
use netlink_packet_generic::{GenlFamily, GenlHeader};

use crate::{AmneziaWgAttribute, WireguardAttribute};

const WG_CMD_GET_DEVICE: u8 = 0;
const WG_CMD_SET_DEVICE: u8 = 1;

/* =========================
   CMD
========================= */

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
    fn from(v: u8) -> Self {
        match v {
            WG_CMD_GET_DEVICE => Self::GetDevice,
            WG_CMD_SET_DEVICE => Self::SetDevice,
            x => Self::Other(x),
        }
    }
}

/* =========================
   FAMILY TRAIT
========================= */

pub trait WgFamily: Default + Clone + std::fmt::Debug {
    const NAME: &'static str;
    const VERSION: u8;

    type Attribute;
}

/* =========================
   FAMILIES
========================= */

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct Wireguard;
impl WgFamily for Wireguard {
    const NAME: &'static str = "wireguard";
    const VERSION: u8 = 1;

    type Attribute = WireguardAttribute;
}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct AmneziaWg;
impl WgFamily for AmneziaWg {
    const NAME: &'static str = "amneziawg";
    const VERSION: u8 = 2;

    type Attribute = AmneziaWgAttribute;
}

/* =========================
   MESSAGE
========================= */

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireguardMessage<F: WgFamily = Wireguard> {
    pub cmd: WireguardCmd,
    pub attributes: Vec<F::Attribute>,
}

/* =========================
   GenlFamily
========================= */

impl<F> GenlFamily for WireguardMessage<F>
where
    F: WgFamily,
{
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

/* =========================
   EMIT
========================= */

impl<F> Emitable for WireguardMessage<F>
where
    F: WgFamily,
    F::Attribute: Nla + Emitable,
{
    fn emit(&self, buffer: &mut [u8]) {
        self.attributes.as_slice().emit(buffer)
    }

    fn buffer_len(&self) -> usize {
        self.attributes.as_slice().buffer_len()
    }
}

/* =========================
   PARSE
========================= */

impl<F> ParseableParametrized<[u8], GenlHeader> for WireguardMessage<F>
where
    F: WgFamily,
    for<'a> <F as WgFamily>::Attribute: Parseable<NlaBuffer<&'a [u8]>>,
{
    fn parse_with_param(
        buf: &[u8],
        header: GenlHeader,
    ) -> Result<Self, DecodeError> {
        Ok(Self {
            cmd: header.cmd.into(),
            attributes: parse_attributes::<F>(buf)?,
        })
    }
}

/* =========================
   ATTRIBUTE PARSER
========================= */

fn parse_attributes<F>(buf: &[u8]) -> Result<Vec<F::Attribute>, DecodeError>
where
    for<'a> <F as WgFamily>::Attribute: Parseable<NlaBuffer<&'a [u8]>>,
    F: WgFamily,
{
    let mut attrs = Vec::new();

    for nla in NlasIterator::new(buf) {
        let nla = nla.context("failed nla parse")?;
        attrs.push(F::Attribute::parse(&nla)?);
    }

    Ok(attrs)
}
