// tests/pq_end_to_end.rs
// E2E (ikke-hermetisk): bruker eksisterende wallet (--wallet + --pass-env).
// Sett env: WALLET_PASS og ev. WALLET_NAME (default "ko").
// ref: 07_tests_formal-verify §4.2–4.3

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(target_os = "windows")]
const EXE: &str = ".exe";
#[cfg(not(target_os = "windows"))]
const EXE: &str = "";

fn ensure_bin_built(name: &str) -> PathBuf {
    if let Ok(p) = env::var(format!("CARGO_BIN_EXE_{}", name)) {
        return PathBuf::from(p);
    }
    let status = Command::new("cargo")
        .args(["build", "--quiet", "--bin", name])
        .status()
        .expect("spawn cargo build");
    assert!(status.success(), "cargo build --bin {} failed", name);
    let mut p = PathBuf::from(env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".into()));
    p.push("debug");
    p.push(format!("{}{}", name, EXE));
    assert!(p.exists(), "expected {}, not found", p.display());
    p
}

fn write_temp(contents: &[u8], suffix: &str) -> PathBuf {
    let mut p = env::temp_dir();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    p.push(format!(
        "opbnbq_{}_{}.{}",
        now,
        rand::random::<u64>(),
        suffix
    ));
    fs::write(&p, contents).expect("write temp");
    p
}

fn run_cmd(bin: &Path, args: &[&str]) -> (String, String, i32) {
    let out = Command::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

#[test]
fn e2e_sign_verify_ok() {
    // Forvent at disse er satt i miljøet
    let wallet = env::var("WALLET_NAME").unwrap_or_else(|_| "ko".to_string());
    let pass =
        env::var("WALLET_PASS").expect("Set env WALLET_PASS (passord for eksisterende wallet)");

    let sign = ensure_bin_built("sign");
    let verify = ensure_bin_built("verify");

    // melding → sign → fil
    let msg = write_temp(b"hello-e2e", "txt");
    let sig = {
        let mut p = msg.clone();
        p.set_extension("sig");
        p
    };

    env::set_var("WALLET_PASS", pass);

    let (s_out, s_err, s_code) = run_cmd(
        &sign,
        &[
            "--wallet",
            &wallet,
            "--pass-env",
            "WALLET_PASS",
            "-f",
            msg.to_str().unwrap(),
            "--out",
            sig.to_str().unwrap(),
        ],
    );
    assert_eq!(
        s_code, 0,
        "sign failed:\nSTDOUT:\n{}\nSTDERR:\n{}",
        s_out, s_err
    );
    assert!(sig.exists(), "sig file not created");
    assert!(s_out.contains("✅ Signature generated"));
    assert!(s_out.contains("Verify(original): OK"));

    let sig_hex = hex::encode(fs::read(&sig).expect("read sig"));

    // verify OK
    let (v_ok_out, v_ok_err, v_ok_code) = run_cmd(
        &verify,
        &[
            "--wallet",
            &wallet,
            "--pass-env",
            "WALLET_PASS",
            "--file",
            msg.to_str().unwrap(),
            "--sig",
            &sig_hex,
        ],
    );
    assert_eq!(
        v_ok_code, 0,
        "verify(OK) failed:\nSTDOUT:\n{}\nSTDERR:\n{}",
        v_ok_out, v_ok_err
    );
    assert!(v_ok_out.contains("✅ signature valid"));

    // verify BAD
    let mut bad = hex::decode(&sig_hex).unwrap();
    bad[0] ^= 1;
    let bad_hex = hex::encode(bad);
    let (v_bad_out, v_bad_err, v_bad_code) = run_cmd(
        &verify,
        &[
            "--wallet",
            &wallet,
            "--pass-env",
            "WALLET_PASS",
            "--file",
            msg.to_str().unwrap(),
            "--sig",
            &bad_hex,
        ],
    );
    assert_eq!(
        v_bad_code, 0,
        "verify(BAD) failed:\nSTDOUT:\n{}\nSTDERR:\n{}",
        v_bad_out, v_bad_err
    );
    assert!(v_bad_out.contains("❌ signature invalid"));
}
