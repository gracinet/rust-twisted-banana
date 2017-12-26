/// Perspective Broker message protocol
/// According to the specifications, this is an extension profile of the Banana protocol

use super::{Profile, DecodeError, Element};

pub type PerspectiveBroker = Element<PB>;

/// Perspective Broker (PB) extension profile
#[derive(Debug, PartialEq, Clone)]
pub enum PB {
    None, // 0x01
    Class, // 0x02
    DeReference, // 0x03
    Reference, // 0x04
    Dictionary, // 0x05
    Function, // 0x06, etc.
    Instance,
    List,
    Module,
    Persistent,
    Tuple,
    UnPersistable,
    Copy,
    Cache,
    Cached,
    Remote,
    Local,
    LCache,
    Version,
    Login,
    Password, // 0x15
    Challenge,
    LoggedIn,
    NotLoggedIn,
    CacheMessage,
    Message,
    Answer,
    Error,
    DecRef,
    DeCache,
    UnCache, // 0x1f
}

impl Profile for PB {
    fn decode<'a>(
        delimiter: u8,
        preamble: &'a [u8],
        full_msg: &'a [u8],
    ) -> Result<(Self, &'a [u8]), DecodeError> {
        if delimiter != 0x87 {
            return Err(DecodeError::UnknownType(delimiter));
        }
        if preamble.len() != 1 {
            return Err(DecodeError::Invalid(format!(
                "PB element type 0x87 must be prefixed by exactly one byte (got {})",
                preamble.len()
            )));
        }
        Ok((
            match preamble[0] {
                0x01 => PB::None,
                0x02 => PB::Class,
                0x03 => PB::DeReference,
                0x04 => PB::Reference,
                0x05 => PB::Dictionary,
                0x06 => PB::Function,
                0x07 => PB::Instance,
                0x08 => PB::List,
                0x09 => PB::Module,
                0x0a => PB::Persistent,
                0x0b => PB::Tuple,
                0x0c => PB::UnPersistable,
                0x0d => PB::Copy,
                0x0e => PB::Cache,
                0x0f => PB::Cached,
                0x10 => PB::Remote,
                0x11 => PB::Local,
                0x12 => PB::LCache,
                0x13 => PB::Version,
                0x14 => PB::Login,
                0x15 => PB::Password,
                0x16 => PB::Challenge,
                0x17 => PB::LoggedIn,
                0x18 => PB::NotLoggedIn,
                0x19 => PB::CacheMessage,
                0x1a => PB::Message,
                0x1b => PB::Answer,
                0x1c => PB::Error,
                0x1d => PB::DecRef,
                0x1e => PB::DeCache,
                0x1f => PB::UnCache,
                other => {
                    return Err(DecodeError::Invalid(
                        format!("Unknown PB short identifier 0x{:x}", other),
                    ));
                }
            },
            &full_msg[2..],
        ))

    }

    fn encode(&self, v: &mut Vec<u8>) {
        v.push(match *self {
            PB::None => 0x01,
            PB::Class => 0x02,
            PB::DeReference => 0x03,
            PB::Reference => 0x04,
            PB::Dictionary => 0x05,
            PB::Function => 0x06,
            PB::Instance => 0x07,
            PB::List => 0x08,
            PB::Module => 0x09,
            PB::Persistent => 0x0a,
            PB::Tuple => 0x0b,
            PB::UnPersistable => 0x0c,
            PB::Copy => 0x0b,
            PB::Cache => 0x0e,
            PB::Cached => 0x0f,
            PB::Remote => 0x10,
            PB::Local => 0x11,
            PB::LCache => 0x12,
            PB::Version => 0x13,
            PB::Login => 0x14,
            PB::Password => 0x15,
            PB::Challenge => 0x16,
            PB::LoggedIn => 0x17,
            PB::NotLoggedIn => 0x18,
            PB::CacheMessage => 0x19,
            PB::Message => 0x1a,
            PB::Answer => 0x1b,
            PB::Error => 0x1c,
            PB::DecRef => 0x1d,
            PB::DeCache => 0x1e,
            PB::UnCache => 0x1f,
        });
        v.push(0x87);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Real-life session start from a buildbot-worker speaking to the master
    /// (just after selecting pb profile)
    fn pb_session() {
        let bytes: &[u8] = &[0x02, 0x80, 0x13, 0x87, 0x06, 0x81];
        assert_eq!(
            PerspectiveBroker::from_bytes(bytes).unwrap(),
            Element::List(vec![Element::Extension(PB::Version), Element::Integer(6)])
        );
        let bytes: &[u8] = &[
            0x07,
            0x80,
            0x1a,
            0x87,
            0x01,
            0x81,
            0x04,
            0x82,
            0x72,
            0x6f,
            0x6f,
            0x74,
            0x14,
            0x87,
            0x01,
            0x81,
            0x02,
            0x80,
            0x0b,
            0x87,
            0x08,
            0x82,
            0x61,
            0x6e,
            0x74,
            0x61,
            0x72,
            0x65,
            0x73,
            0x32,
            0x01,
            0x80,
            0x05,
            0x87,
        ];
        assert_eq!(
            PerspectiveBroker::from_bytes(bytes).unwrap(),
            Element::List(vec![
                Element::Extension(PB::Message),
                Element::Integer(1),
                Element::String(String::from("root").into_bytes()),
                Element::Extension(PB::Login),
                Element::Integer(1),
                Element::List(vec![
                    Element::Extension(PB::Tuple),
                    Element::String(
                        String::from("antares2").into_bytes()
                    ),
                ]),
                Element::List(vec![Element::Extension(PB::Dictionary)]),
            ])
        );
    }

    #[test]
    fn basic_encode() {
        let elt: PerspectiveBroker = Element::Extension(PB::Dictionary);
        assert_eq!(elt.encode(), vec![5, 0x87]);
    }
}
