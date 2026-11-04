//! Shared assertion for the synthetic suites: every module exposes `self_test_cases()` and one
//! test asserts them, so the assertion lives here instead of being copied into each module.

/// Fails with the full list when any synthetic case of a module does not hold.
pub fn assert_cases(cases: Vec<(String, bool)>) {
    assert!(cases.iter().all(|(_, ok)| *ok), "{cases:?}");
}
