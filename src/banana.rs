use std::mem::transmute;

/// Represent Banana extension profiles
pub trait Profile: Sized {
    /// Attempt to decode as an extension element.
    /// preamble is made of the bytes that occur before the delimiter.
    /// It is either a length (as base128 bytes), or has special meaning
    fn decode<'a>(
        delimiter: u8,
        preamble: &'a [u8],
        full_msg: &'a [u8],
    ) -> Result<(Self, &'a [u8]), DecodeError>;
}

#[derive(Debug, PartialEq, Clone)]
pub enum Element<P: Profile> {
    Integer(i32), // split into Integer (0x81) and Negative Integer (0x83)
    String(Vec<u8>), // 0x82
    Float(f64), // 0x84
    List(Vec<Element<P>>), // 0x80
    Extension(P),
}

/// Bare Banana message protocol
pub type Banana = Element<NoneProfile>;

/// The 'none', a.k.a default extension profile
/// it adds nothing on top of vanilla banana.
#[derive(Debug, PartialEq, Clone)]
pub enum NoneProfile {
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DecodeError {
    NoType,
    Empty,
    UnknownType(u8),
    OverFlow(Vec<u8>),
    TooShort(usize, usize), // contains (expected, actual)
    Invalid(String),
}


impl<P: Profile> Element<P> {
    /// Extract length part and type byte of Banana element
    /// According to spec, the type byte is the first with higher bit set.
    /// The length can be used to actually encode contents, so that
    /// we don't decode it right away.
    fn length_type<'a>(ser: &'a [u8]) -> Result<(&'a [u8], u8), DecodeError> {
        if ser.len() == 0 {
            return Err(DecodeError::Empty);
        };
        let mut split_type = ser.splitn(2, |b| *b >= 0x80);
        let length_bytes = split_type.next().unwrap();
        let type_offset = length_bytes.len();
        if type_offset == ser.len() {
            return Err(DecodeError::NoType);
        }
        Ok((length_bytes, ser[type_offset]))
    }

    /// Decode short nonnegative integer, expressed as base128 bytes
    /// TODO (for sport) bitwise operations are likely to be more natural
    fn dec_posint(bytes: &[u8]) -> Result<i32, DecodeError> {
        let mut res: i32 = 0;
        let l = bytes.len();
        let premax = 1 << 24; // TODO const
        for i in 1..(l + 1) {
            let b = bytes[l - i];
            if res >= premax {
                // if res == (1<<24) - 1, any value of b: u7
                // gives still at most (1<<31) - 1
                // if res == (1<<24) and incl, then b=0 is still allowed,
                // giving the allowed 1<<31
                return Err(DecodeError::OverFlow(bytes.into()));
            }
            res = (res << 7) + (b as i32);
        }
        Ok(res)
    }

    /// Decode short negative integer, whose absolute value is
    /// expressed as base128 bytes.
    /// TODO (for sport) bitwise operations are likely to be more natural
    fn dec_negint(bytes: &[u8]) -> Result<i32, DecodeError> {
        let mut res: i32 = 0;
        let l = bytes.len();
        let premax = -1 << 24; // TODO const
        for i in 1..(l + 1) {
            let b = bytes[l - i];
            if res < premax || (res == premax && b != 0) {
                // if res == (-1<<24) then b=0 is still allowed,
                // giving the allowed -1<<31
                return Err(DecodeError::OverFlow(bytes.into()));
            }
            res = (res << 7) - (b as i32);
        }
        Ok(res)
    }

    fn dec_string(length_bytes: &[u8], full_msg: &[u8]) -> Result<Vec<u8>, DecodeError> {
        let l = Self::dec_posint(length_bytes)? as usize; // TODO big len
        let start = length_bytes.len() + 1;
        let end = start + l;
        if end > full_msg.len() {
            return Err(DecodeError::TooShort(l, full_msg.len() - start));
        }
        Ok(full_msg[start..end].into())
    }

    fn dec_float(length_bytes: &[u8], full_msg: &[u8]) -> Result<f64, DecodeError> {
        if length_bytes.len() != 0 {
            return Err(DecodeError::Invalid(format!(
                "Float values must not have a length preamble, but got {:?}",
                length_bytes
            )));
        }
        if full_msg.len() < 9 {
            return Err(DecodeError::TooShort(9, full_msg.len()));
        }
        // TODO spec example is given in big-endian order (IEEE 754 does
        // not specify endianness). We assume platform is little-endian
        // (ermh amd64 here).
        Ok(unsafe {
            transmute(
                [
                    full_msg[8],
                    full_msg[7],
                    full_msg[6],
                    full_msg[5],
                    full_msg[4],
                    full_msg[3],
                    full_msg[2],
                    full_msg[1],
                ],
            )
        })
    }

    /// Decode an element, incuding length marker,
    /// and return an owned Banana object, together with remaning unused bytes
    /// maybe consume incoming bytes, to get a 0-copy ?
    /// Would be nice also to allow for partial messages, allowing to stream very long
    /// communications without having to wait for completion and represent the full content in
    /// RAM. Check what applications (e.g., buildbot) actually do for big communications.
    /// stream within the protocol or outside of it ?
    pub fn from_bytes_rem<'a>(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), DecodeError> {
        let (length_bytes, delimiter) = Self::length_type(bytes).unwrap();
        match P::decode(delimiter, length_bytes, bytes) {
            Ok((ext, rem)) => {
                return Ok((Element::Extension(ext), rem));
            }
            Err(DecodeError::UnknownType(_)) => {}
            Err(err) => {
                return Err(err);
            }
        };
        match delimiter {
            0x81 => {
                Ok((
                    Element::Integer(Self::dec_posint(length_bytes)? as i32),
                    &bytes[length_bytes.len() + 1..],
                ))
            }
            0x83 => {
                Ok((
                    Element::Integer(Self::dec_negint(length_bytes)? as i32),
                    &bytes[length_bytes.len() + 1..],
                ))
            }
            0x82 => {
                let st = Self::dec_string(length_bytes, bytes)?;
                let stl = st.len();
                Ok((
                    Element::String(st),
                    &bytes[length_bytes.len() + 1 + stl..],
                ))
            }
            0x80 => Self::dec_list(length_bytes, bytes),
            0x84 => {
                Ok((
                    Element::Float(Self::dec_float(length_bytes, bytes)?),
                    &bytes[9..],
                ))
            }
            other => Err(DecodeError::UnknownType(other)),
        }
    }

    fn dec_list<'a>(
        length_bytes: &[u8],
        full_msg: &'a [u8],
    ) -> Result<(Self, &'a [u8]), DecodeError> {
        if length_bytes.len() == 0 {
            return Err(DecodeError::Invalid("List without a length".into()));
        }
        let list_len = Self::dec_posint(length_bytes)? as usize; // TODO big len
        let mut resv: Vec<Self> = Vec::with_capacity(list_len);
        let mut rem = &full_msg[length_bytes.len() + 1..];
        for _i in 0..list_len {
            let item_rem = Self::from_bytes_rem(rem)?;
            resv.push(item_rem.0);
            rem = item_rem.1;
        }
        Ok((Element::List(resv), rem))
    }

    #[inline]
    /// Decode an element, including length/type preamble, and ignore the remainder
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self::from_bytes_rem(bytes)?.0)
    }
}

impl Profile for NoneProfile {
    fn decode<'a>(
        delimiter: u8,
        _p: &'a [u8],
        _f: &'a [u8],
    ) -> Result<(Self, &'a [u8]), DecodeError> {
        Err(DecodeError::UnknownType(delimiter))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_type() {
        assert!(Banana::length_type("".as_bytes()).is_err());
        assert_eq!(Banana::length_type(&[0x42, 0x24, 0x82, 0x01]).unwrap(), (
            &[0x42 as u8, 0x24 as u8] as &[u8],
            0x82 as u8,
        ));
    }

    #[test]
    fn decode_integers() {
        let bytes: &[u8] = &[0x12, 0x34, 0x81];
        assert_eq!(Banana::from_bytes(&bytes), Ok(Element::Integer(6674)));
        let bytes: &[u8] = &[0x7f, 0x7f, 0x7f, 0x7f, 0x07, 0x81];
        assert_eq!(
            Banana::from_bytes(&bytes),
            Ok(Element::Integer(i32::max_value()))
        );
        let bytes: &[u8] = &[0x00, 0x00, 0x00, 0x00, 0x08, 0x81];
        assert_eq!(
            Banana::from_bytes(&bytes),
            Err(DecodeError::OverFlow(vec![0, 0, 0, 0, 8]))
        );
        let bytes: &[u8] = &[0x12, 0x34, 0x83];
        assert_eq!(Banana::from_bytes(&bytes), Ok(Element::Integer(-6674)));
        let bytes: &[u8] = &[0x00, 0x00, 0x00, 0x00, 0x08, 0x83];
        assert_eq!(
            Banana::from_bytes(&bytes),
            Ok(Element::Integer(i32::min_value()))
        );
    }

    #[test]
    fn decode_string() {
        let bytes: &[u8] = &[0x03, 0x82, b'b', b'a', b'n'];
        assert_eq!(
            Banana::from_bytes(&bytes),
            Ok(Element::String(String::from("ban").into_bytes()))
        );
        let bytes: &[u8] = &[0x04, 0x82, b'b', b'a', b'n'];
        assert_eq!(Banana::from_bytes(&bytes), Err(DecodeError::TooShort(4, 3)));
    }

    #[test]
    fn decode_float() {
        // example from https://en.wikipedia.org/wiki/Double-precision_floating-point_format
        // with ignored extra content at the end
        let bytes: &[u8] = &[0x84, 0x40, 0x37, 0, 0, 0, 0, 0, 0, 12, 12];
        assert_eq!(Banana::from_bytes(&bytes), Ok(Element::Float(23 as f64)));
        let bytes: &[u8] = &[0x84, 0x3f, 0xf8];
        assert_eq!(Banana::from_bytes(&bytes), Err(DecodeError::TooShort(9, 3)));
    }

    #[test]
    fn decode_list() {
        let bytes: &[u8] = &[0x02, 0x80, 0x02, 0x81, 0x03, 0x83];
        assert_eq!(
            Banana::from_bytes(&bytes).unwrap(),
            Element::List(vec![Element::Integer(2), Element::Integer(-3)])
        );
        let bytes: &[u8] = &[0x80];
        assert_eq!(
            Banana::from_bytes(&bytes),
            Err(DecodeError::Invalid("List without a length".into()))
        );
    }

    #[test]
    /// Examples from the banana spec
    fn spec_examples() {
        // integer
        let bytes: &[u8] = &[0x01, 0x81];
        assert_eq!(Banana::from_bytes(&bytes).unwrap(), Element::Integer(1));

        let bytes: &[u8] = &[0x01, 0x83];
        assert_eq!(Banana::from_bytes(&bytes).unwrap(), Element::Integer(-1));

        // float
        let bytes: &[u8] = &[0x84, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0];
        assert_eq!(Banana::from_bytes(&bytes).unwrap(), Element::Float(1.5));

        // string
        let bytes: &[u8] = &[0x05, 0x82, 0x68, 0x65, 0x6c, 0x6c, 0x6f];
        assert_eq!(
            Banana::from_bytes(&bytes).unwrap(),
            Element::String(String::from("hello").into_bytes())
        );

        // lists
        let bytes: &[u8] = &[0, 0x80];
        assert_eq!(Banana::from_bytes(&bytes).unwrap(), Element::List(vec![]));
        let bytes: &[u8] = &[2, 0x80, 0x01, 0x81, 0x17, 0x81];
        assert_eq!(
            Banana::from_bytes(&bytes).unwrap(),
            Element::List(vec![Element::Integer(1), Element::Integer(23)])
        );
        let bytes: &[u8] = &[
            2,
            0x80,
            1,
            0x81,
            1,
            0x80,
            5,
            0x82,
            0x68,
            0x65,
            0x6c,
            0x6c,
            0x6f,
        ];
        assert_eq!(
            Banana::from_bytes(&bytes).unwrap(),
            Element::List(vec![
                Element::Integer(1),
                Element::List(vec![
                    Element::String(String::from("hello").into_bytes()),
                ]),
            ])
        );
    }

    type TestProfile = Option<u8>;
    type TestProto = Element<TestProfile>;

    impl Profile for TestProfile {
        fn decode<'a>(
            delimiter: u8,
            preamble: &'a [u8],
            full_msg: &'a [u8],
        ) -> Result<(TestProfile, &'a [u8]), DecodeError> {
            if delimiter != 0xff {
                return Err(DecodeError::UnknownType(delimiter));
            }
            let rem = match full_msg.get(2..) {
                None => &[],
                Some(sl) => sl,
            };
            match preamble.len() {
                0 => Ok((None, rem)),
                1 => Ok((Some(preamble[0]), rem)),
                _ => Err(DecodeError::Invalid("Invalid length".into())),
            }
        }
    }

    #[test]
    fn with_profile() {
        let bytes: &[u8] = &[b'a', 0xff];
        assert_eq!(
            TestProto::from_bytes(&bytes).unwrap(),
            Element::Extension(Some(b'a'))
        );

        let bytes: &[u8] = &[0xff];
        assert_eq!(
            TestProto::from_bytes(&bytes).unwrap(),
            Element::Extension(None)
        );

        let bytes: &[u8] = &[b'a', 0xfe];
        assert_eq!(
            TestProto::from_bytes(&bytes),
            Err(DecodeError::UnknownType(0xfe))
        );

        let bytes: &[u8] = &[0x01, 0x02, 0xff];
        assert!(match TestProto::from_bytes(&bytes) {
            Err(DecodeError::Invalid(_)) => true,
            _ => false,
        });

        // recursion into vanilla Banana
        let bytes: &[u8] = &[2, 0x80, b'%', 0xff, 127, 0x81];
        assert_eq!(
            TestProto::from_bytes(&bytes).unwrap(),
            Element::List(vec![Element::Extension(Some(b'%')), Element::Integer(127)])
        );
    }
}
