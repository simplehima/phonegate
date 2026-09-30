//! Canonical length-prefixed encoding (protocol §2).
//!
//! Every signed, MAC'd or hashed structure is `enc(label, f1, …, fn)` where each field is
//! `u32_be(len) ‖ bytes`. Decoding is strict: wrong label, wrong field count, truncation,
//! trailing bytes or oversize input are all rejected.

use crate::error::{Error, Result};

/// Maximum size of any encoded structure.
pub const MAX_ENCODED: usize = 64 * 1024;
/// Maximum length of a string field unless a structure states otherwise.
pub const MAX_STRING: usize = 256;

/// Builder for a canonical encoding. The first field is always the label.
#[derive(Debug, Clone)]
pub struct Enc {
    buf: Vec<u8>,
}

impl Enc {
    pub fn new(label: &str) -> Self {
        debug_assert!(label.starts_with("phonegate/v1/"));
        Enc { buf: Vec::with_capacity(128) }.bytes(label.as_bytes())
    }

    pub fn bytes(mut self, b: &[u8]) -> Self {
        let len = u32::try_from(b.len()).expect("field larger than 4 GiB");
        self.buf.extend_from_slice(&len.to_be_bytes());
        self.buf.extend_from_slice(b);
        self
    }

    pub fn str(self, s: &str) -> Self {
        self.bytes(s.as_bytes())
    }

    pub fn u64(self, v: u64) -> Self {
        self.bytes(&v.to_be_bytes())
    }

    /// A list of byte strings, itself canonically encoded (no label).
    pub fn list(self, items: &[Vec<u8>]) -> Self {
        let inner = enc_list(items);
        self.bytes(&inner)
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// Encodes a list of byte strings without a label.
pub fn enc_list(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for it in items {
        let len = u32::try_from(it.len()).expect("item larger than 4 GiB");
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(it);
    }
    out
}

/// Splits raw canonical bytes into fields without interpreting them.
pub fn split(data: &[u8]) -> Result<Vec<&[u8]>> {
    if data.len() > MAX_ENCODED {
        return Err(Error::Decode("encoded structure too large"));
    }
    let mut fields = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        if rest.len() < 4 {
            return Err(Error::Decode("truncated length prefix"));
        }
        let len = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
        rest = &rest[4..];
        if rest.len() < len {
            return Err(Error::Decode("truncated field"));
        }
        fields.push(&rest[..len]);
        rest = &rest[len..];
    }
    Ok(fields)
}

/// Decodes a list encoded with [`enc_list`].
pub fn decode_list(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    Ok(split(data)?.into_iter().map(|f| f.to_vec()).collect())
}

/// Decoded fields of a labelled structure. Index 0 is the label; accessors use indexes of the
/// payload fields starting at 1 to match the contract tables.
#[derive(Debug)]
pub struct Fields<'a> {
    fields: Vec<&'a [u8]>,
}

/// Decodes `data`, requiring `label` and exactly `count` fields **including** the label.
pub fn decode<'a>(data: &'a [u8], label: &str, count: usize) -> Result<Fields<'a>> {
    let fields = split(data)?;
    if fields.is_empty() || fields[0] != label.as_bytes() {
        return Err(Error::Decode("label mismatch"));
    }
    if fields.len() != count {
        return Err(Error::Decode("wrong field count"));
    }
    Ok(Fields { fields })
}

impl<'a> Fields<'a> {
    pub fn bytes(&self, i: usize) -> &'a [u8] {
        self.fields[i]
    }

    pub fn fixed<const N: usize>(&self, i: usize) -> Result<[u8; N]> {
        self.fields[i]
            .try_into()
            .map_err(|_| Error::Decode("fixed-size field has wrong length"))
    }

    pub fn u64(&self, i: usize) -> Result<u64> {
        Ok(u64::from_be_bytes(self.fixed::<8>(i)?))
    }

    pub fn string(&self, i: usize) -> Result<String> {
        self.string_max(i, MAX_STRING)
    }

    pub fn string_max(&self, i: usize, max: usize) -> Result<String> {
        let b = self.fields[i];
        if b.len() > max {
            return Err(Error::Decode("string too long"));
        }
        String::from_utf8(b.to_vec()).map_err(|_| Error::Decode("invalid utf-8"))
    }

    pub fn list(&self, i: usize) -> Result<Vec<Vec<u8>>> {
        decode_list(self.fields[i])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let e = Enc::new("phonegate/v1/test").bytes(b"ab").str("héllo").u64(7).finish();
        let f = decode(&e, "phonegate/v1/test", 4).unwrap();
        assert_eq!(f.bytes(1), b"ab");
        assert_eq!(f.string(2).unwrap(), "héllo");
        assert_eq!(f.u64(3).unwrap(), 7);
    }

    #[test]
    fn exact_layout() {
        let e = Enc::new("phonegate/v1/x").u64(1).finish();
        let mut expect = vec![0, 0, 0, 14];
        expect.extend_from_slice(b"phonegate/v1/x");
        expect.extend_from_slice(&[0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(e, expect);
    }

    #[test]
    fn rejects_truncated_prefix() {
        let mut e = Enc::new("phonegate/v1/t").bytes(b"x").finish();
        e.truncate(e.len() - 3);
        assert!(decode(&e, "phonegate/v1/t", 2).is_err());
        assert!(split(&[0, 0, 1]).is_err());
    }

    #[test]
    fn rejects_trailing_garbage() {
        let mut e = Enc::new("phonegate/v1/t").bytes(b"x").finish();
        e.push(0);
        assert!(decode(&e, "phonegate/v1/t", 2).is_err());
    }

    #[test]
    fn rejects_wrong_count_and_label() {
        let e = Enc::new("phonegate/v1/t").bytes(b"x").finish();
        assert_eq!(decode(&e, "phonegate/v1/t", 3).unwrap_err(), Error::Decode("wrong field count"));
        assert_eq!(decode(&e, "phonegate/v1/u", 2).unwrap_err(), Error::Decode("label mismatch"));
    }

    #[test]
    fn rejects_oversize() {
        let big = vec![0u8; MAX_ENCODED + 1];
        assert!(split(&big).is_err());
    }

    #[test]
    fn rejects_bad_u64_and_long_string() {
        let e = Enc::new("phonegate/v1/t").bytes(&[1, 2, 3]).bytes(&[b'a'; 300]).finish();
        let f = decode(&e, "phonegate/v1/t", 3).unwrap();
        assert!(f.u64(1).is_err());
        assert!(f.string(2).is_err());
    }

    #[test]
    fn list_roundtrip() {
        let items = vec![b"one".to_vec(), vec![], b"three".to_vec()];
        let e = Enc::new("phonegate/v1/l").list(&items).finish();
        let f = decode(&e, "phonegate/v1/l", 2).unwrap();
        assert_eq!(f.list(1).unwrap(), items);
    }
}
