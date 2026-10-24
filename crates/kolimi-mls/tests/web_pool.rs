#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use kolimi_mls::client::{Device, Group};

#[test]
fn key_package_survives_export_before_welcome() {
    let bob = Device::new(b"bob").unwrap();
    let package = bob.key_package().unwrap();
    // Simulate a browser/sync pass that persists the device state after
    // publishing a package but before the owner's Welcome arrives.
    let state = bob.export_state(&[]).unwrap();
    let (bob2, _) = Device::import_state(&state).unwrap();

    let alice = Device::new(b"alice").unwrap();
    let mut group = Group::create(&alice, &[1u8; 32]).unwrap();
    let (welcome, _) = group.add(&alice, &package).unwrap();
    let joined = Group::join(&bob2, &welcome).unwrap();
    assert_eq!(joined.epoch(), 1);
}
