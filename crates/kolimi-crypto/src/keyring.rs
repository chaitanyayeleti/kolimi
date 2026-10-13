//! The keyring: wrapped copies of the user master key.
//!
//! The keyring is stored on the server but is useless to it: every copy
//! of the master key is wrapped under a key-encryption key derived from
//! a secret only the user has (passphrase, recovery code, or passkey
//! PRF output).

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::MasterKey;
pub use crate::keys::Argon2Params;
use crate::{
    CryptoError,
    keys::{
        KEY_LEN, RECOVERY_CODE_LEN, kek_from_passphrase, kek_from_prf, kek_from_recovery_code,
        random, unwrap, wrap,
    },
};

const PASSPHRASE_AAD: &[u8] = b"kolimi-keyring-v1:passphrase";
const RECOVERY_AAD: &[u8] = b"kolimi-keyring-v1:recovery";
const PRF_AAD: &[u8] = b"kolimi-keyring-v1:prf";

/// One wrapped copy of the master key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum Wrap {
    /// Wrapped under an Argon2id-derived key from a passphrase.
    Passphrase {
        /// Argon2id salt.
        #[serde(with = "base64_bytes")]
        salt: Vec<u8>,
        /// Argon2id memory cost in KiB.
        m_cost: u32,
        /// Argon2id iterations.
        t_cost: u32,
        /// Argon2id parallelism.
        p_cost: u32,
        /// `nonce || ciphertext`.
        #[serde(with = "base64_bytes")]
        wrapped: Vec<u8>,
    },
    /// Wrapped under an HKDF-derived key from the recovery code.
    Recovery {
        /// `nonce || ciphertext`.
        #[serde(with = "base64_bytes")]
        wrapped: Vec<u8>,
    },
    /// Wrapped under an HKDF-derived key from a WebAuthn PRF output.
    Prf {
        /// `nonce || ciphertext`.
        #[serde(with = "base64_bytes")]
        wrapped: Vec<u8>,
    },
}

impl Wrap {
    fn method(&self) -> &'static str {
        match self {
            Wrap::Passphrase { .. } => "passphrase",
            Wrap::Recovery { .. } => "recovery",
            Wrap::Prf { .. } => "prf",
        }
    }
}

/// A user's wrapped master key copies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Keyring {
    /// Keyring format version.
    pub version: u8,
    /// Wrapped copies, one per unlock method.
    pub wraps: Vec<Wrap>,
}

impl Keyring {
    /// Current keyring format version.
    pub const VERSION: u8 = 1;

    /// Creates a keyring with passphrase and recovery wraps.
    pub fn create(
        master_key: &MasterKey,
        passphrase: &str,
        params: &Argon2Params,
        recovery_code: &[u8; RECOVERY_CODE_LEN],
    ) -> Result<Self, CryptoError> {
        let mut keyring = Self {
            version: Self::VERSION,
            wraps: Vec::new(),
        };
        keyring.add_passphrase(master_key, passphrase, params)?;
        keyring.add_recovery(master_key, recovery_code)?;
        Ok(keyring)
    }

    /// Adds (or replaces) the passphrase wrap.
    pub fn add_passphrase(
        &mut self,
        master_key: &MasterKey,
        passphrase: &str,
        params: &Argon2Params,
    ) -> Result<(), CryptoError> {
        params.argon2_params()?;
        let salt = random::<16>()?;
        let kek = Zeroizing::new(kek_from_passphrase(passphrase, &salt, params)?);
        let wrapped = wrap(&kek, master_key.as_bytes(), PASSPHRASE_AAD)?;
        self.wraps.retain(|wrap| wrap.method() != "passphrase");
        self.wraps.push(Wrap::Passphrase {
            salt: salt.to_vec(),
            m_cost: params.m_cost,
            t_cost: params.t_cost,
            p_cost: params.p_cost,
            wrapped,
        });
        Ok(())
    }

    /// Adds (or replaces) the recovery-code wrap.
    pub fn add_recovery(
        &mut self,
        master_key: &MasterKey,
        recovery_code: &[u8; RECOVERY_CODE_LEN],
    ) -> Result<(), CryptoError> {
        let kek = Zeroizing::new(kek_from_recovery_code(recovery_code)?);
        let wrapped = wrap(&kek, master_key.as_bytes(), RECOVERY_AAD)?;
        self.wraps.retain(|wrap| wrap.method() != "recovery");
        self.wraps.push(Wrap::Recovery { wrapped });
        Ok(())
    }

    /// Adds (or replaces) the passkey-PRF wrap.
    pub fn add_prf(
        &mut self,
        master_key: &MasterKey,
        prf_output: &[u8; KEY_LEN],
    ) -> Result<(), CryptoError> {
        let kek = Zeroizing::new(kek_from_prf(prf_output)?);
        let wrapped = wrap(&kek, master_key.as_bytes(), PRF_AAD)?;
        self.wraps.retain(|wrap| wrap.method() != "prf");
        self.wraps.push(Wrap::Prf { wrapped });
        Ok(())
    }

    /// Unlocks the master key with a passphrase.
    pub fn unlock_with_passphrase(&self, passphrase: &str) -> Result<MasterKey, CryptoError> {
        let Some(Wrap::Passphrase {
            salt,
            m_cost,
            t_cost,
            p_cost,
            wrapped,
        }) = self.wraps.iter().find(|wrap| wrap.method() == "passphrase")
        else {
            return Err(CryptoError::Unlock);
        };
        let params = Argon2Params {
            m_cost: *m_cost,
            t_cost: *t_cost,
            p_cost: *p_cost,
        };
        let kek = Zeroizing::new(
            kek_from_passphrase(passphrase, salt, &params).map_err(|_| CryptoError::Unlock)?,
        );
        let bytes = unwrap(&kek, wrapped, PASSPHRASE_AAD).map_err(|_| CryptoError::Unlock)?;
        Ok(MasterKey::from_bytes(bytes))
    }

    /// Unlocks the master key with the recovery code.
    pub fn unlock_with_recovery(
        &self,
        recovery_code: &[u8; RECOVERY_CODE_LEN],
    ) -> Result<MasterKey, CryptoError> {
        let Some(Wrap::Recovery { wrapped }) =
            self.wraps.iter().find(|wrap| wrap.method() == "recovery")
        else {
            return Err(CryptoError::Unlock);
        };
        let kek =
            Zeroizing::new(kek_from_recovery_code(recovery_code).map_err(|_| CryptoError::Unlock)?);
        let bytes = unwrap(&kek, wrapped, RECOVERY_AAD).map_err(|_| CryptoError::Unlock)?;
        Ok(MasterKey::from_bytes(bytes))
    }

    /// Unlocks the master key with a passkey PRF output.
    pub fn unlock_with_prf(&self, prf_output: &[u8; KEY_LEN]) -> Result<MasterKey, CryptoError> {
        let Some(Wrap::Prf { wrapped }) = self.wraps.iter().find(|wrap| wrap.method() == "prf")
        else {
            return Err(CryptoError::Unlock);
        };
        let kek = Zeroizing::new(kek_from_prf(prf_output).map_err(|_| CryptoError::Unlock)?);
        let bytes = unwrap(&kek, wrapped, PRF_AAD).map_err(|_| CryptoError::Unlock)?;
        Ok(MasterKey::from_bytes(bytes))
    }

    /// Which unlock methods are available.
    pub fn methods(&self) -> Vec<&'static str> {
        self.wraps.iter().map(Wrap::method).collect()
    }

    /// Serializes the keyring (this is what the server stores).
    pub fn to_json(&self) -> Result<String, CryptoError> {
        serde_json::to_string(self).map_err(|error| CryptoError::Keyring(error.to_string()))
    }

    /// Parses a keyring produced by [`Self::to_json`].
    pub fn from_json(json: &str) -> Result<Self, CryptoError> {
        let keyring: Self =
            serde_json::from_str(json).map_err(|error| CryptoError::Keyring(error.to_string()))?;
        if keyring.version != Self::VERSION {
            return Err(CryptoError::Keyring(format!(
                "unsupported keyring version {}",
                keyring.version
            )));
        }
        Ok(keyring)
    }
}

/// Generates a fresh recovery code.
pub fn generate_recovery_code() -> Result<[u8; RECOVERY_CODE_LEN], CryptoError> {
    random::<RECOVERY_CODE_LEN>()
}

/// Formats a recovery code as eight groups of eight hex characters.
pub fn recovery_code_display(code: &[u8; RECOVERY_CODE_LEN]) -> String {
    let hex = hex_encode(code);
    hex.as_bytes()
        .chunks(8)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("-")
}

/// Parses a recovery code in any hex grouping (dashes/spaces optional).
pub fn recovery_code_parse(text: &str) -> Result<[u8; RECOVERY_CODE_LEN], CryptoError> {
    let cleaned: String = text
        .chars()
        .filter(|c| !matches!(c, '-' | ' ' | '\t'))
        .collect();
    if cleaned.len() != RECOVERY_CODE_LEN * 2 {
        return Err(CryptoError::Malformed("recovery code length".to_string()));
    }
    let bytes = hex_decode(&cleaned)?;
    bytes
        .try_into()
        .map_err(|_| CryptoError::Malformed("recovery code length".to_string()))
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

pub fn hex_decode(text: &str) -> Result<Vec<u8>, CryptoError> {
    if !text.len().is_multiple_of(2) {
        return Err(CryptoError::Malformed("hex length".to_string()));
    }
    (0..text.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&text[i..i + 2], 16)
                .map_err(|_| CryptoError::Malformed("hex digits".to_string()))
        })
        .collect()
}

mod base64_bytes {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        URL_SAFE_NO_PAD
            .decode(&text)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn fast_params() -> Argon2Params {
        Argon2Params {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
        }
    }

    #[test]
    fn unlock_roundtrip_all_methods() {
        let master = MasterKey::generate().unwrap();
        let recovery = generate_recovery_code().unwrap();
        let keyring = Keyring::create(&master, "correct horse", &fast_params(), &recovery).unwrap();
        assert_eq!(keyring.methods(), vec!["passphrase", "recovery"]);

        let unlocked = keyring.unlock_with_passphrase("correct horse").unwrap();
        assert_eq!(unlocked.as_bytes(), master.as_bytes());
        let unlocked = keyring.unlock_with_recovery(&recovery).unwrap();
        assert_eq!(unlocked.as_bytes(), master.as_bytes());

        let prf = [7u8; 32];
        let mut with_prf = keyring.clone();
        with_prf.add_prf(&master, &prf).unwrap();
        assert_eq!(
            with_prf.unlock_with_prf(&prf).unwrap().as_bytes(),
            master.as_bytes()
        );
        assert!(with_prf.methods().contains(&"prf"));
    }

    #[test]
    fn wrong_secrets_fail() {
        let master = MasterKey::generate().unwrap();
        let recovery = generate_recovery_code().unwrap();
        let keyring = Keyring::create(&master, "correct horse", &fast_params(), &recovery).unwrap();
        assert!(matches!(
            keyring.unlock_with_passphrase("wrong horse"),
            Err(CryptoError::Unlock)
        ));
        assert!(matches!(
            keyring.unlock_with_recovery(&[0u8; 32]),
            Err(CryptoError::Unlock)
        ));
        assert!(matches!(
            keyring.unlock_with_prf(&[0u8; 32]),
            Err(CryptoError::Unlock)
        ));
    }

    #[test]
    fn json_roundtrip_and_methods() {
        let master = MasterKey::generate().unwrap();
        let recovery = generate_recovery_code().unwrap();
        let passphrase = "leak-check-passphrase-9f3a";
        let keyring = Keyring::create(&master, passphrase, &fast_params(), &recovery).unwrap();
        let json = keyring.to_json().unwrap();
        assert!(
            !json.contains("leak-check"),
            "plaintext must not leak into the keyring"
        );
        let back = Keyring::from_json(&json).unwrap();
        assert_eq!(back.methods(), keyring.methods());
        assert_eq!(
            back.unlock_with_recovery(&recovery).unwrap().as_bytes(),
            master.as_bytes()
        );
    }

    #[test]
    fn recovery_code_format_roundtrips() {
        let code = generate_recovery_code().unwrap();
        let display = recovery_code_display(&code);
        assert_eq!(display.len(), 71);
        assert_eq!(recovery_code_parse(&display).unwrap(), code);
        assert_eq!(
            recovery_code_parse(&display.replace('-', "")).unwrap(),
            code
        );
        assert!(recovery_code_parse("nope").is_err());
    }

    #[test]
    fn file_keys_wrap_and_unwrap() {
        let master = MasterKey::generate().unwrap();
        let file_key = crate::FileKey::generate().unwrap();
        let wrapped = master.wrap_file_key(&file_key).unwrap();
        assert_ne!(wrapped.as_slice(), file_key.as_bytes());
        let unwrapped = master.unwrap_file_key(&wrapped).unwrap();
        assert_eq!(unwrapped.as_bytes(), file_key.as_bytes());

        let other = MasterKey::generate().unwrap();
        assert!(other.unwrap_file_key(&wrapped).is_err());
    }
}
