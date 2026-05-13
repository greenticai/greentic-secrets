//! Zeroizing fixed-size key material wrapper.

use zeroize::ZeroizeOnDrop;

/// 32-byte master key, zeroed on drop.
///
/// Constructed by `crate::kdf::derive_master_key`. Cannot be cloned (key
/// material should not proliferate).
#[derive(ZeroizeOnDrop)]
pub struct MasterKey {
    bytes: [u8; 32],
}

impl MasterKey {
    /// Construct from raw bytes. Caller is responsible for ensuring
    /// `bytes` was produced by a secure KDF.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Borrow the underlying bytes for cryptographic operations only.
    /// Do not store the returned slice beyond the immediate call.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroize;

    #[test]
    fn debug_does_not_leak_bytes() {
        let key = MasterKey::from_bytes([0xAB; 32]);
        let s = format!("{:?}", key);
        assert_eq!(s, "MasterKey([REDACTED])");
        assert!(!s.contains("AB"));
        assert!(!s.contains("ab"));
    }

    #[test]
    fn explicit_zeroize_clears_bytes() {
        let mut key = MasterKey::from_bytes([0xFF; 32]);
        key.bytes.zeroize();
        assert_eq!(key.bytes, [0u8; 32]);
    }

    #[test]
    fn as_bytes_returns_underlying_slice() {
        let key = MasterKey::from_bytes([0x42; 32]);
        assert_eq!(key.as_bytes(), &[0x42u8; 32]);
    }
}
