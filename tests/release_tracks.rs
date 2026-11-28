//! A consumer moves to a new engine major only when its own pin changes: the action serves the
//! release of its commit, and each major has its own track.

const ACTION: &str = include_str!("../.github/actions/stenio-check/action.yml");
const RELEASE: &str = include_str!("../.github/workflows/release.yml");

#[test]
fn the_action_defaults_to_the_release_of_its_commit_and_never_to_latest() {
    let wanted = format!("INPUT_VERSION:-v{}}}", env!("CARGO_PKG_VERSION"));
    assert!(
        ACTION.contains(&wanted),
        "action.yml must default to v{}",
        env!("CARGO_PKG_VERSION")
    );
    assert!(
        !ACTION.contains("INPUT_VERSION:-latest"),
        "the action floats"
    );
}

#[test]
fn each_major_moves_only_its_own_track() {
    let major = env!("CARGO_PKG_VERSION_MAJOR");
    assert!(
        RELEASE.contains(&format!("{major}) ACTION_MAJOR_TAG=v")),
        "release.yml declares no track for major {major}"
    );
    assert!(
        RELEASE.contains("4) ACTION_MAJOR_TAG=v1 ;;"),
        "4.x stays on v1"
    );
    assert!(RELEASE.contains("5) ACTION_MAJOR_TAG=v2 ;;"), "5.x is v2");
}
