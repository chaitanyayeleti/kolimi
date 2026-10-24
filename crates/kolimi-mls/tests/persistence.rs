//! Device/group state survives a serialization roundtrip: the epoch
//! exporter keeps working and commits received after reload still advance
//! the group.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use kolimi_mls::SHARE_KEYRING_EXPORTER;
use kolimi_mls::client::{Device, Group};

#[test]
fn device_and_group_state_roundtrip() {
    let group_id = [4u8; 32];
    let alice = Device::new(b"alice@laptop").unwrap();
    let bob = Device::new(b"bob@phone").unwrap();
    let charlie = Device::new(b"carol@tablet").unwrap();

    let bob_key_package = bob.key_package().unwrap();
    let mut alice_group = Group::create(&alice, &group_id).unwrap();
    let (welcome, _commit) = alice_group.add(&alice, &bob_key_package).unwrap();
    let bob_group = Group::join(&bob, &welcome).unwrap();
    assert_eq!(alice_group.epoch(), 1);
    assert_eq!(bob_group.epoch(), 1);

    let alice_secret = alice_group
        .export(&alice, SHARE_KEYRING_EXPORTER, 32)
        .unwrap();
    assert_eq!(
        alice_secret,
        bob_group.export(&bob, SHARE_KEYRING_EXPORTER, 32).unwrap()
    );

    // Persist and restore both devices, then reload the group from the
    // restored key-value storage.
    let alice_state = alice.export_state(&[group_id.to_vec()]).unwrap();
    let bob_state = bob.export_state(&[group_id.to_vec()]).unwrap();
    let (alice2, alice_groups) = Device::import_state(&alice_state).unwrap();
    let (bob2, bob_groups) = Device::import_state(&bob_state).unwrap();
    let mut alice_group2 = Group::load(&alice2, &alice_groups[0]).unwrap();
    let mut bob_group2 = Group::load(&bob2, &bob_groups[0]).unwrap();
    assert_eq!(
        alice_group2
            .export(&alice2, SHARE_KEYRING_EXPORTER, 32)
            .unwrap(),
        alice_secret
    );
    assert_eq!(bob_group2.epoch(), 1);

    // Alice adds Charlie after the reload; Bob processes the commit after
    // his own reload and reaches the same new epoch/exporter.
    let charlie_key_package = charlie.key_package().unwrap();
    let (_welcome2, commit2) = alice_group2.add(&alice2, &charlie_key_package).unwrap();
    assert_eq!(alice_group2.epoch(), 2);
    bob_group2.process(&bob2, &commit2).unwrap();
    assert_eq!(bob_group2.epoch(), 2);
    let next = alice_group2
        .export(&alice2, SHARE_KEYRING_EXPORTER, 32)
        .unwrap();
    assert_ne!(next, alice_secret);
    assert_eq!(
        next,
        bob_group2
            .export(&bob2, SHARE_KEYRING_EXPORTER, 32)
            .unwrap()
    );

    // A tampered storage blob must not silently load.
    let mut bad = bob_state.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert!(Device::import_state(&bad).is_err());
}
