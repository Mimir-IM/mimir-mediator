pub const PERM_OWNER: u8 = 0x80;
pub const PERM_ADMIN: u8 = 0x40;
pub const PERM_MOD: u8 = 0x20;
pub const PERM_USER: u8 = 0x10;
pub const PERM_READ_ONLY: u8 = 0x08;
pub const PERM_BANNED: u8 = 0x01;

/// Returns true if `value` has any of the bits in `mask` set.
pub fn has_any(value: u8, mask: u8) -> bool {
    (value & mask) != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_any() {
        assert!(has_any(PERM_OWNER | PERM_USER, PERM_OWNER));
        assert!(has_any(PERM_ADMIN, PERM_OWNER | PERM_ADMIN));
        assert!(!has_any(PERM_USER, PERM_OWNER | PERM_ADMIN));
        assert!(!has_any(0, PERM_BANNED));
    }
}
