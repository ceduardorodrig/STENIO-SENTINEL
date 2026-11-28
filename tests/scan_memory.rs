//! GB-403: a large binary file no rule reads is not loaded. Alone in its test binary, because the
//! peak memory of children is a figure of the whole process.

use std::fs;
use std::process::Command;

type Fallible = Result<(), Box<dyn std::error::Error>>;

const FILE_BYTES: u64 = 400 * 1024 * 1024;
const LIMIT_KB: i64 = 128 * 1024;

#[test]
fn a_large_binary_file_does_not_enter_memory() -> Fallible {
    let dir = std::env::temp_dir().join(format!("stenio-memory-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;
    // Sparse: it takes no disk space.
    fs::File::create(dir.join("archive.tar.gz"))?.set_len(FILE_BYTES)?;
    fs::write(dir.join("a.rs"), "fn a() {}\n")?;
    let out = Command::new(env!("CARGO_BIN_EXE_stenio"))
        .args(["--path", ".", "--scope", "project", "--compact"])
        .current_dir(&dir)
        .output()?;
    let _ = fs::remove_dir_all(&dir);
    assert!(out.status.success(), "scan failed: {out:?}");
    // SAFETY: `getrusage` only writes the structure it is given.
    let usage = unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        assert_eq!(libc::getrusage(libc::RUSAGE_CHILDREN, &mut usage), 0);
        usage
    };
    assert!(
        usage.ru_maxrss < LIMIT_KB,
        "peak memory {} KiB, limit {LIMIT_KB} KiB",
        usage.ru_maxrss
    );
    Ok(())
}
