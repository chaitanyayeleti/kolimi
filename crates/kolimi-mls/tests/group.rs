#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Two-device MLS roundtrip: create, add via Welcome, application message,
//! and the epoch exporter that will key the share keyring.

use kolimi_mls::openmls::prelude::tls_codec::Deserialize;
use kolimi_mls::openmls::prelude::*;
use kolimi_mls::{CIPHERSUITE, SHARE_KEYRING_EXPORTER};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

fn credential(
    identity: &[u8],
    provider: &OpenMlsRustCrypto,
) -> (CredentialWithKey, SignatureKeyPair) {
    let credential = BasicCredential::new(identity.to_vec());
    let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).unwrap();
    signer.store(provider.storage()).unwrap();
    (
        CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.public().into(),
        },
        signer,
    )
}

#[test]
fn add_member_exchange_message_and_export_share_key() {
    let alice_provider = OpenMlsRustCrypto::default();
    let bob_provider = OpenMlsRustCrypto::default();
    let (alice_credential, alice_signer) = credential(b"alice@device-1", &alice_provider);
    let (bob_credential, bob_signer) = credential(b"bob@device-2", &bob_provider);

    let bob_key_package = KeyPackage::builder()
        .build(CIPHERSUITE, &bob_provider, &bob_signer, bob_credential)
        .unwrap();

    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build();

    let mut alice_group =
        MlsGroup::new(&alice_provider, &alice_signer, &config, alice_credential).unwrap();
    let (_, welcome, _) = alice_group
        .add_members(
            &alice_provider,
            &alice_signer,
            &[bob_key_package.key_package().clone()],
        )
        .unwrap();
    alice_group.merge_pending_commit(&alice_provider).unwrap();

    let welcome_bytes = welcome.to_bytes().unwrap();
    let welcome_in = MlsMessageIn::tls_deserialize_exact(welcome_bytes).unwrap();
    let welcome = match welcome_in.extract() {
        MlsMessageBodyIn::Welcome(welcome) => welcome,
        _ => panic!("expected a Welcome message"),
    };
    let mut bob_group = StagedWelcome::new_from_welcome(
        &bob_provider,
        config.join_config(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .unwrap()
    .into_group(&bob_provider)
    .unwrap();

    assert_eq!(alice_group.epoch(), bob_group.epoch());
    let message = alice_group
        .create_message(&alice_provider, &alice_signer, b"hello from alice")
        .unwrap();
    let message = MlsMessageIn::tls_deserialize_exact(message.to_bytes().unwrap()).unwrap();
    let processed = bob_group
        .process_message(&bob_provider, message.try_into_protocol_message().unwrap())
        .unwrap();
    let content = match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(application) => application.into_bytes(),
        other => panic!("expected an application message, got {other:?}"),
    };
    assert_eq!(content, b"hello from alice");

    // The exporter is epoch-bound and identical on both members. The
    // milestone will AES-GCM the share keyring with this secret.
    let alice_export = alice_group
        .export_secret(
            alice_provider.crypto(),
            SHARE_KEYRING_EXPORTER,
            b"kolimi",
            32,
        )
        .unwrap();
    let bob_export = bob_group
        .export_secret(bob_provider.crypto(), SHARE_KEYRING_EXPORTER, b"kolimi", 32)
        .unwrap();
    assert_eq!(alice_export, bob_export);
    assert_eq!(alice_export.len(), 32);

    // Add a third member: a new epoch and a different exporter secret.
    let charlie_provider = OpenMlsRustCrypto::default();
    let (charlie_credential, charlie_signer) = credential(b"carol@device-3", &charlie_provider);
    let charlie_key_package = KeyPackage::builder()
        .build(
            CIPHERSUITE,
            &charlie_provider,
            &charlie_signer,
            charlie_credential,
        )
        .unwrap();
    let (_, welcome, _) = alice_group
        .add_members(
            &alice_provider,
            &alice_signer,
            &[charlie_key_package.key_package().clone()],
        )
        .unwrap();
    alice_group.merge_pending_commit(&alice_provider).unwrap();
    let welcome_bytes = welcome.to_bytes().unwrap();
    let welcome = match MlsMessageIn::tls_deserialize_exact(welcome_bytes)
        .unwrap()
        .extract()
    {
        MlsMessageBodyIn::Welcome(welcome) => welcome,
        _ => panic!("expected a Welcome message"),
    };
    let charlie_group = StagedWelcome::new_from_welcome(
        &charlie_provider,
        config.join_config(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .unwrap()
    .into_group(&charlie_provider)
    .unwrap();
    let next_export = alice_group
        .export_secret(
            alice_provider.crypto(),
            SHARE_KEYRING_EXPORTER,
            b"kolimi",
            32,
        )
        .unwrap();
    assert_ne!(alice_export, next_export, "a new epoch must rotate the key");
    assert_eq!(
        next_export,
        charlie_group
            .export_secret(
                charlie_provider.crypto(),
                SHARE_KEYRING_EXPORTER,
                b"kolimi",
                32
            )
            .unwrap()
    );
}
