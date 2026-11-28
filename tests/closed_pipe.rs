//! GB-415: a closed output pipe ends a command without a panic and never as a success.

use std::process::{Command, Stdio};

type Fallible = Result<(), Box<dyn std::error::Error>>;

#[test]
fn a_reader_that_leaves_early_causes_no_panic() -> Fallible {
    let dir = env!("CARGO_MANIFEST_DIR");
    for args in [
        &["--list"][..],
        &["--explain"],
        &["language", "report", "--path", "."],
        &["config", "show"],
        &["--path", "src", "--scope", "project"],
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_stenio"))
            .current_dir(dir)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        // The reader leaves before the first line is written.
        drop(child.stdout.take());
        let out = child.wait_with_output()?;
        let said = String::from_utf8_lossy(&out.stderr);
        assert!(!said.contains("panicked"), "{args:?}: {said}");
        assert!(!out.status.success(), "{args:?}: a cut report passed");
    }
    Ok(())
}
