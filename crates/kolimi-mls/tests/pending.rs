//! Pending commits only advance the local group after the server accepts
//! them. A rejected commit must be discardable without changing the epoch.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use kolimi_mls::SHARE_KEYRING_EXPORTER;
use kolimi_mls::client::{Device, Group};

#[test]
fn pending_add_is_discarded_or_merged_explicitly() {
    let group_id = [9u8; 32];
    let alice = Device::new(b"alice@laptop").unwrap();
    let bob = Device::new(b"bob@phone").unwrap();
    let bob_package = bob.key_package().unwrap();

    let mut group = Group::create(&alice, &group_id).unwrap();
    assert_eq!(group.epoch(), 0);

    // Stage the add. The group must stay at epoch 0 until merge.
    let pending = group.add_pending(&alice, &bob_package).unwrap();
    assert_eq!(pending.epoch, 1);
    assert_eq!(group.epoch(), 0);
    assert!(group.has_pending_commit());
    assert_eq!(group.pending_epoch(), Some(1));

    // A losing committer discards its staged state and remains usable at the
    // old epoch.
    group.discard_pending(&alice).unwrap();
    assert_eq!(group.epoch(), 0);
    assert!(!group.has_pending_commit());

    // Re-staging and merging is the success path.
    let pending = group.add_pending(&alice, &bob_package).unwrap();
    assert_eq!(pending.epoch, 1);
    group.merge_pending(&alice).unwrap();
    assert_eq!(group.epoch(), 1);
    assert!(!group.has_pending_commit());

    let welcome = pending.welcome.unwrap();
    let bob_group = Group::join(&bob, &welcome).unwrap();
    assert_eq!(bob_group.epoch(), 1);
}

#[test]
fn processing_own_commit_merges_the_pending_epoch() {
    let group_id = [12u8; 32];
    let alice = Device::new(b"alice@laptop").unwrap();
    let bob = Device::new(b"bob@phone").unwrap();

    let mut group = Group::create(&alice, &group_id).unwrap();
    let pending = group
        .add_pending(&alice, &bob.key_package().unwrap())
        .unwrap();
    assert_eq!(group.epoch(), 0);
    // This is what a client sees after losing the HTTP response but finding
    // its own commit in the server log on the next pass.
    group
        .process_commit(&alice, &pending.commit, Some(&pending.commit))
        .unwrap();
    assert_eq!(group.epoch(), 1);
    assert!(!group.has_pending_commit());
}

#[test]
fn pending_commit_survives_a_state_roundtrip() {
    let group_id = [14u8; 32];
    let alice = Device::new(b"alice@laptop").unwrap();
    let bob = Device::new(b"bob@phone").unwrap();

    let mut group = Group::create(&alice, &group_id).unwrap();
    let pending = group
        .add_pending(&alice, &bob.key_package().unwrap())
        .unwrap();
    let pending_map = BTreeMap::from([(group_id.to_vec(), pending.commit.clone())]);
    let state = alice
        .export_state(&[group_id.to_vec()], &pending_map)
        .unwrap();

    let (restored, groups, pending_map2) = Device::import_state(&state).unwrap();
    assert_eq!(
        pending_map2.get(group_id.as_slice()).map(Vec::as_slice),
        Some(pending.commit.as_slice())
    );
    let mut group2 = Group::load(&restored, &groups[0]).unwrap();
    assert_eq!(group2.pending_epoch(), Some(1));
    group2.merge_pending(&restored).unwrap();
    assert_eq!(group2.epoch(), 1);
}

#[test]
fn unverified_own_private_commit_does_not_merge() {
    let group_id = [13u8; 32];
    let alice = Device::new(b"alice@laptop").unwrap();
    let bob = Device::new(b"bob@phone").unwrap();

    let mut group = Group::create(&alice, &group_id).unwrap();
    let pending = group
        .add_pending(&alice, &bob.key_package().unwrap())
        .unwrap();
    group.discard_pending(&alice).unwrap();

    // An own commit surfaced as a PrivateMessage cannot be authenticated
    // against a pending commit we no longer have.
    assert!(group.process_commit(&alice, &pending.commit, None).is_err());
    assert_eq!(group.epoch(), 0);
    assert!(
        group
            .process_commit(&alice, &pending.commit, Some(b"different commit"))
            .is_err()
    );
    assert_eq!(group.epoch(), 0);
}

#[test]
fn losing_committer_recovers_the_winning_epoch() {
    let group_id = [11u8; 32];
    let alice = Device::new(b"alice@laptop").unwrap();
    let bob = Device::new(b"bob@phone").unwrap();
    let carol = Device::new(b"carol@tablet").unwrap();
    let dave = Device::new(b"dave@laptop").unwrap();
    let eve = Device::new(b"eve@phone").unwrap();

    // Alice, Bob and Carol share epoch 2.
    let mut alice_group = Group::create(&alice, &group_id).unwrap();
    let bob_welcome = alice_group
        .add(&alice, &bob.key_package().unwrap())
        .unwrap()
        .0;
    let mut bob_group = Group::join(&bob, &bob_welcome).unwrap();
    let carol_pending = alice_group
        .add_pending(&alice, &carol.key_package().unwrap())
        .unwrap();
    alice_group.merge_pending(&alice).unwrap();
    bob_group.process(&bob, &carol_pending.commit).unwrap();
    let carol_group = Group::join(&carol, &carol_pending.welcome.unwrap()).unwrap();
    assert_eq!(alice_group.epoch(), 2);
    assert_eq!(bob_group.epoch(), 2);
    assert_eq!(carol_group.epoch(), 2);

    // Alice and Bob both stage an add for epoch 3. The server accepts
    // Alice's commit; Bob's loses and gets 409.
    let alice_pending = alice_group
        .add_pending(&alice, &dave.key_package().unwrap())
        .unwrap();
    let bob_pending = bob_group
        .add_pending(&bob, &eve.key_package().unwrap())
        .unwrap();
    assert_eq!(alice_pending.epoch, 3);
    assert_eq!(bob_pending.epoch, 3);
    alice_group.merge_pending(&alice).unwrap();
    bob_group.discard_pending(&bob).unwrap();
    assert_eq!(bob_group.epoch(), 2);

    // Bob replays the winning commit, then retries at epoch 4.
    bob_group.process(&bob, &alice_pending.commit).unwrap();
    assert_eq!(bob_group.epoch(), 3);
    let retry = bob_group
        .add_pending(&bob, &eve.key_package().unwrap())
        .unwrap();
    assert_eq!(retry.epoch, 4);
    bob_group.merge_pending(&bob).unwrap();
    alice_group.process(&alice, &retry.commit).unwrap();
    assert_eq!(alice_group.epoch(), 4);
    assert_eq!(bob_group.epoch(), 4);
    assert_eq!(
        alice_group
            .export(&alice, SHARE_KEYRING_EXPORTER, 32)
            .unwrap(),
        bob_group.export(&bob, SHARE_KEYRING_EXPORTER, 32).unwrap()
    );
}

#[test]
fn pending_remove_does_not_remove_before_merge() {
    let group_id = [10u8; 32];
    let alice = Device::new(b"alice@laptop").unwrap();
    let bob = Device::new(b"bob@phone").unwrap();
    let bob_package = bob.key_package().unwrap();

    let mut group = Group::create(&alice, &group_id).unwrap();
    group.add_pending(&alice, &bob_package).unwrap();
    group.merge_pending(&alice).unwrap();
    assert_eq!(group.epoch(), 1);

    let bob_index = group
        .members()
        .into_iter()
        .find(|member| member.identity == b"bob@phone")
        .unwrap()
        .index;
    let pending = group.remove_pending(&alice, &[bob_index]).unwrap();
    assert_eq!(pending.epoch, 2);
    assert_eq!(group.epoch(), 1);
    assert!(
        group
            .members()
            .iter()
            .any(|member| member.index == bob_index)
    );

    group.discard_pending(&alice).unwrap();
    assert_eq!(group.epoch(), 1);
    assert!(
        group
            .members()
            .iter()
            .any(|member| member.index == bob_index)
    );

    group.remove_pending(&alice, &[bob_index]).unwrap();
    group.merge_pending(&alice).unwrap();
    assert_eq!(group.epoch(), 2);
    assert!(
        !group
            .members()
            .iter()
            .any(|member| member.index == bob_index)
    );
}
