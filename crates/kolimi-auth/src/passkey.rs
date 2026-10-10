//! WebAuthn / passkey ceremonies (RFC-level: delegated to `webauthn-rs`).
//!
//! The [`Passkeys`] type owns the relying-party configuration and a
//! short-lived, single-use challenge store. Registration and login flows
//! are split into begin/finish halves: `begin_*` returns JSON options for
//! the browser plus a challenge id; `finish_*` consumes the challenge and
//! verifies the client's response.
//!
//! Challenges are bound to the user id and are removed on first use, so a
//! captured challenge cannot be replayed or crossed between accounts.

use std::{
    collections::HashMap,
    fmt::Display,
    sync::Mutex,
    time::{Duration, Instant},
};

use url::Url;

pub use webauthn_rs::prelude::{
    AuthenticationResult, CreationChallengeResponse, CredentialID, Passkey, PublicKeyCredential,
    RegisterPublicKeyCredential, RequestChallengeResponse,
};
use webauthn_rs::prelude::{
    PasskeyAuthentication, PasskeyRegistration, Uuid, Webauthn, WebauthnBuilder,
};

use crate::{AuthError, token};

const CHALLENGE_TTL: Duration = Duration::from_secs(300);
const MAX_CHALLENGES: usize = 1024;

/// WebAuthn ceremonies bound to one relying party (this server).
pub struct Passkeys {
    webauthn: Webauthn,
    challenges: Mutex<HashMap<String, Entry>>,
}

enum Challenge {
    Registration(PasskeyRegistration),
    Authentication(PasskeyAuthentication),
}

struct Entry {
    user_id: i64,
    challenge: Challenge,
    expires: Instant,
}

fn passkey_err(error: impl Display) -> AuthError {
    AuthError::Passkey(error.to_string())
}

impl Passkeys {
    /// Builds the relying party from an origin URL; `rp_id` is the origin's host.
    pub fn from_origin(origin: &str, rp_name: &str) -> Result<Self, AuthError> {
        let origin_url = Url::parse(origin).map_err(passkey_err)?;
        let rp_id = origin_url
            .host_str()
            .ok_or_else(|| passkey_err("origin has no host"))?;
        Self::new(rp_id, &origin_url, rp_name)
    }

    /// Builds the relying party from an explicit `rp_id` and origin.
    pub fn new(rp_id: &str, origin: &Url, rp_name: &str) -> Result<Self, AuthError> {
        let webauthn = WebauthnBuilder::new(rp_id, origin)
            .map_err(passkey_err)?
            .rp_name(rp_name)
            .build()
            .map_err(passkey_err)?;
        Ok(Self {
            webauthn,
            challenges: Mutex::new(HashMap::new()),
        })
    }

    /// Starts passkey registration, returning `(challenge_id, options_json_source)`.
    pub fn begin_registration(
        &self,
        user_id: i64,
        username: &str,
        exclude: Vec<CredentialID>,
    ) -> Result<(String, CreationChallengeResponse), AuthError> {
        let (options, state) = self
            .webauthn
            .start_passkey_registration(
                Uuid::from_u128(user_id as u128),
                username,
                username,
                Some(exclude),
            )
            .map_err(passkey_err)?;
        let challenge_id = self.store(user_id, Challenge::Registration(state))?;
        Ok((challenge_id, options))
    }

    /// Consumes a registration challenge and verifies the attestation response.
    pub fn finish_registration(
        &self,
        challenge_id: &str,
        user_id: i64,
        credential: &RegisterPublicKeyCredential,
    ) -> Result<Passkey, AuthError> {
        let Some(Challenge::Registration(state)) = self.take(challenge_id, user_id)? else {
            return Err(AuthError::PasskeyChallenge);
        };
        self.webauthn
            .finish_passkey_registration(credential, &state)
            .map_err(passkey_err)
    }

    /// Starts passkey authentication against the user's registered passkeys.
    pub fn begin_authentication(
        &self,
        user_id: i64,
        credentials: &[Passkey],
    ) -> Result<(String, RequestChallengeResponse), AuthError> {
        let (options, state) = self
            .webauthn
            .start_passkey_authentication(credentials)
            .map_err(passkey_err)?;
        let challenge_id = self.store(user_id, Challenge::Authentication(state))?;
        Ok((challenge_id, options))
    }

    /// Consumes an authentication challenge and verifies the assertion.
    pub fn finish_authentication(
        &self,
        challenge_id: &str,
        user_id: i64,
        credential: &PublicKeyCredential,
    ) -> Result<AuthenticationResult, AuthError> {
        let Some(Challenge::Authentication(state)) = self.take(challenge_id, user_id)? else {
            return Err(AuthError::PasskeyChallenge);
        };
        self.webauthn
            .finish_passkey_authentication(credential, &state)
            .map_err(passkey_err)
    }

    fn store(&self, user_id: i64, challenge: Challenge) -> Result<String, AuthError> {
        let challenge_id = token::random_hex(16)?;
        let Ok(mut map) = self.challenges.lock() else {
            return Err(passkey_err("challenge store is poisoned"));
        };
        let now = Instant::now();
        map.retain(|_, entry| entry.expires > now);
        if map.len() >= MAX_CHALLENGES {
            map.clear();
        }
        map.insert(
            challenge_id.clone(),
            Entry {
                user_id,
                challenge,
                expires: now + CHALLENGE_TTL,
            },
        );
        Ok(challenge_id)
    }

    fn take(&self, challenge_id: &str, user_id: i64) -> Result<Option<Challenge>, AuthError> {
        let Ok(mut map) = self.challenges.lock() else {
            return Err(passkey_err("challenge store is poisoned"));
        };
        match map.get(challenge_id) {
            Some(entry) if entry.user_id == user_id && entry.expires > Instant::now() => {
                Ok(map.remove(challenge_id).map(|entry| entry.challenge))
            }
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passkeys() -> Passkeys {
        Passkeys::from_origin("http://localhost:8080", "Kolimi Test").unwrap()
    }

    fn dummy_registration_credential() -> RegisterPublicKeyCredential {
        serde_json::from_value(serde_json::json!({
            "id": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "rawId": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "type": "public-key",
            "response": {
                "clientDataJSON": "e30",
                "attestationObject": "e30"
            }
        }))
        .unwrap()
    }

    #[test]
    fn rejects_bad_origin() {
        assert!(Passkeys::from_origin("not a url", "Kolimi").is_err());
    }

    #[test]
    fn begin_registration_issues_distinct_challenges() {
        let passkeys = passkeys();
        let (a, options_a) = passkeys.begin_registration(1, "alice", vec![]).unwrap();
        let (b, _) = passkeys.begin_registration(1, "alice", vec![]).unwrap();
        assert_ne!(a, b);
        assert_eq!(options_a.public_key.rp.id, "localhost");
    }

    #[test]
    fn finish_registration_rejects_unknown_challenge() {
        let passkeys = passkeys();
        assert!(matches!(
            passkeys.finish_registration("bogus", 1, &dummy_registration_credential()),
            Err(AuthError::PasskeyChallenge)
        ));
    }

    #[test]
    fn challenges_are_single_use_and_user_bound() {
        let passkeys = passkeys();
        let (challenge_id, _) = passkeys.begin_registration(1, "alice", vec![]).unwrap();

        // Wrong user cannot consume another user's challenge.
        assert!(matches!(
            passkeys.finish_registration(&challenge_id, 2, &dummy_registration_credential()),
            Err(AuthError::PasskeyChallenge)
        ));

        // The correct user consumes it; a garbage response fails verification...
        let result =
            passkeys.finish_registration(&challenge_id, 1, &dummy_registration_credential());
        assert!(matches!(result, Err(AuthError::Passkey(_))));

        // ...and the challenge is gone either way.
        assert!(matches!(
            passkeys.finish_registration(&challenge_id, 1, &dummy_registration_credential()),
            Err(AuthError::PasskeyChallenge)
        ));
    }

    #[test]
    fn begin_authentication_without_credentials_is_allowed_by_webauthn_rs() {
        // webauthn-rs supports discoverable-credential flows with an empty
        // allow-list. Kolimi's API layer rejects users without passkeys
        // before this point; this test pins the upstream behavior.
        let passkeys = passkeys();
        assert!(passkeys.begin_authentication(1, &[]).is_ok());
    }
}
