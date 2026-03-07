use std::collections::HashMap;
use std::io::{self, Write};

// TLV Tag definitions
// Authentication & Crypto
pub const TAG_PUBKEY: u8 = 0x01;
pub const TAG_SIGNATURE: u8 = 0x02;
pub const TAG_NONCE: u8 = 0x03;
pub const TAG_COUNTER: u8 = 0x04;

// Identifiers
pub const TAG_CHAT_ID: u8 = 0x10;
pub const TAG_MESSAGE_ID: u8 = 0x11;
pub const TAG_MESSAGE_GUID: u8 = 0x12;
pub const TAG_INVITE_ID: u8 = 0x13;
pub const TAG_SINCE_ID: u8 = 0x14;
pub const TAG_USER_PUBKEY: u8 = 0x15;

// Variable Data
pub const TAG_CHAT_NAME: u8 = 0x20;
pub const TAG_CHAT_DESC: u8 = 0x21;
pub const TAG_CHAT_AVATAR: u8 = 0x22;
pub const TAG_MESSAGE_BLOB: u8 = 0x23;
pub const TAG_MEMBER_INFO: u8 = 0x24;
pub const TAG_INVITE_DATA: u8 = 0x25;

// Scalars
pub const TAG_LIMIT: u8 = 0x30;
pub const TAG_COUNT: u8 = 0x31;
pub const TAG_TIMESTAMP: u8 = 0x32;
pub const TAG_PERMS: u8 = 0x33;
pub const TAG_ONLINE: u8 = 0x34;
pub const TAG_ACCEPTED: u8 = 0x35;
pub const TAG_LAST_UPDATE: u8 = 0x36;
pub const TAG_LAST_SEEN: u8 = 0x37;

pub type TlvMap = HashMap<u8, Vec<u8>>;

/// Write a varint (up to 4 bytes, 28 bits) using protobuf-style encoding.
pub fn write_varint<W: Write>(w: &mut W, mut value: u32) -> io::Result<()> {
    for _ in 0..4 {
        let mut b = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            b |= 0x80;
        }
        w.write_all(&[b])?;
        if value == 0 {
            return Ok(());
        }
    }
    Err(io::Error::new(io::ErrorKind::InvalidData, "varint overflow"))
}

/// Read a varint from a byte slice at offset, returns (value, bytes_consumed).
fn read_varint_from_bytes(data: &[u8], offset: usize) -> io::Result<(u32, usize)> {
    let mut result: u32 = 0;
    let mut shift: u32 = 0;
    for i in 0..4 {
        if offset + i >= data.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "varint: unexpected end of data"));
        }
        let b = data[offset + i];
        result |= ((b & 0x7F) as u32) << shift;
        if (b & 0x80) == 0 {
            return Ok((result, i + 1));
        }
        shift += 7;
    }
    Err(io::Error::new(io::ErrorKind::InvalidData, "varint overflow"))
}

/// Write a single TLV field.
pub fn write_tlv<W: Write>(w: &mut W, tag: u8, value: &[u8]) -> io::Result<()> {
    w.write_all(&[tag])?;
    write_varint(w, value.len() as u32)?;
    if !value.is_empty() {
        w.write_all(value)?;
    }
    Ok(())
}

/// Parse a TLV-encoded payload into a map of tag -> value.
pub fn parse_tlvs(payload: &[u8]) -> io::Result<TlvMap> {
    let mut result = TlvMap::new();
    let mut offset = 0;

    while offset < payload.len() {
        let tag = payload[offset];
        offset += 1;

        let (length, consumed) = read_varint_from_bytes(payload, offset)?;
        offset += consumed;

        let length = length as usize;
        if offset + length > payload.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("tag 0x{:02X} length {} exceeds payload bounds", tag, length),
            ));
        }
        let value = payload[offset..offset + length].to_vec();
        offset += length;

        result.insert(tag, value);
    }

    Ok(result)
}

// --- Extraction helpers ---

pub fn tlv_get_bytes(m: &TlvMap, tag: u8, expected_size: usize) -> Result<&[u8], String> {
    let val = m.get(&tag).ok_or_else(|| format!("missing required tag 0x{:02X}", tag))?;
    if expected_size > 0 && val.len() != expected_size {
        return Err(format!("tag 0x{:02X}: expected {} bytes, got {}", tag, expected_size, val.len()));
    }
    Ok(val)
}

pub fn tlv_get_bytes_optional(m: &TlvMap, tag: u8) -> Option<&[u8]> {
    m.get(&tag).map(|v| v.as_slice())
}

pub fn tlv_get_u64(m: &TlvMap, tag: u8) -> Result<u64, String> {
    let val = tlv_get_bytes(m, tag, 8)?;
    Ok(u64::from_be_bytes(val.try_into().unwrap()))
}

pub fn tlv_get_i64(m: &TlvMap, tag: u8) -> Result<i64, String> {
    tlv_get_u64(m, tag).map(|v| v as i64)
}

pub fn tlv_get_u32(m: &TlvMap, tag: u8) -> Result<u32, String> {
    let val = tlv_get_bytes(m, tag, 4)?;
    Ok(u32::from_be_bytes(val.try_into().unwrap()))
}

pub fn tlv_get_u8(m: &TlvMap, tag: u8) -> Result<u8, String> {
    let val = tlv_get_bytes(m, tag, 1)?;
    Ok(val[0])
}

pub fn tlv_get_string(m: &TlvMap, tag: u8) -> Result<String, String> {
    let val = m.get(&tag).ok_or_else(|| format!("missing required tag 0x{:02X}", tag))?;
    String::from_utf8(val.clone()).map_err(|e| format!("tag 0x{:02X}: invalid utf8: {}", tag, e))
}

#[allow(dead_code)]
pub fn tlv_get_string_optional(m: &TlvMap, tag: u8) -> Option<String> {
    m.get(&tag).and_then(|v| String::from_utf8(v.clone()).ok())
}

// --- Encoding helpers ---

pub fn tlv_encode_bytes<W: Write>(w: &mut W, tag: u8, value: &[u8]) -> io::Result<()> {
    write_tlv(w, tag, value)
}

pub fn tlv_encode_u64<W: Write>(w: &mut W, tag: u8, value: u64) -> io::Result<()> {
    write_tlv(w, tag, &value.to_be_bytes())
}

pub fn tlv_encode_i64<W: Write>(w: &mut W, tag: u8, value: i64) -> io::Result<()> {
    tlv_encode_u64(w, tag, value as u64)
}

pub fn tlv_encode_u32<W: Write>(w: &mut W, tag: u8, value: u32) -> io::Result<()> {
    write_tlv(w, tag, &value.to_be_bytes())
}

pub fn tlv_encode_u8<W: Write>(w: &mut W, tag: u8, value: u8) -> io::Result<()> {
    write_tlv(w, tag, &[value])
}

pub fn tlv_encode_string<W: Write>(w: &mut W, tag: u8, value: &str) -> io::Result<()> {
    write_tlv(w, tag, value.as_bytes())
}

/// Build a complete TLV payload using a closure that writes TLV fields.
pub fn build_tlv_payload<F>(build_fn: F) -> io::Result<Vec<u8>>
where
    F: FnOnce(&mut Vec<u8>) -> io::Result<()>,
{
    let mut buf = Vec::new();
    build_fn(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_roundtrip() {
        for &val in &[0u32, 1, 127, 128, 16383, 16384, 0x0FFFFFFF] {
            let mut buf = Vec::new();
            write_varint(&mut buf, val).unwrap();
            let (decoded, consumed) = read_varint_from_bytes(&buf, 0).unwrap();
            assert_eq!(decoded, val);
            assert_eq!(consumed, buf.len());
        }
    }

    #[test]
    fn test_tlv_roundtrip() {
        let mut buf = Vec::new();
        tlv_encode_u64(&mut buf, TAG_CHAT_ID, 42).unwrap();
        tlv_encode_string(&mut buf, TAG_CHAT_NAME, "hello").unwrap();
        tlv_encode_u8(&mut buf, TAG_PERMS, 0x90).unwrap();

        let map = parse_tlvs(&buf).unwrap();
        assert_eq!(tlv_get_u64(&map, TAG_CHAT_ID).unwrap(), 42);
        assert_eq!(tlv_get_string(&map, TAG_CHAT_NAME).unwrap(), "hello");
        assert_eq!(tlv_get_u8(&map, TAG_PERMS).unwrap(), 0x90);
    }

    #[test]
    fn test_parse_empty() {
        let map = parse_tlvs(&[]).unwrap();
        assert!(map.is_empty());
    }
}
