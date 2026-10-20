//! The snapshot document `opendamp` reads is the published `snapshot/v1`
//! (DESIGN.md section 4), byte for byte the form openampd publishes and hands
//! out as `derive_snapshot`: declared `pi` and list roots, blacklist entries as
//! outpoint policy keys, `windows`, `issuer_sig`. These run the built binary.

use std::path::PathBuf;
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_opendamp")
}

fn example(name: &str) -> serde_json::Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join(name)
}

/// Run `opendamp derive` on a document; Ok(stdout) or Err(stderr).
fn derive(doc: &serde_json::Value) -> Result<String, String> {
    let dir = std::env::temp_dir().join(format!("opendamp-snapfmt-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{:016x}.json", rand_name(doc)));
    std::fs::write(&path, serde_json::to_vec(doc).unwrap()).unwrap();
    let out = Command::new(bin())
        .args(["derive", "--snapshot"])
        .arg(&path)
        .output()
        .unwrap();
    let _ = std::fs::remove_file(&path);
    if out.status.success() {
        Ok(String::from_utf8(out.stdout).unwrap())
    } else {
        Err(String::from_utf8(out.stderr).unwrap())
    }
}

fn rand_name(doc: &serde_json::Value) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    doc.to_string().hash(&mut h);
    h.finish()
}

fn line<'a>(out: &'a str, label: &str) -> &'a str {
    out.lines()
        .find(|l| l.starts_with(label))
        .map(|l| l[15..].trim())
        .unwrap_or_else(|| panic!("no {label} line in {out}"))
}

#[test]
fn reads_the_published_form_and_checks_its_declarations() {
    for name in ["snapshot-seq0.json", "snapshot-seq1.json"] {
        let doc = example(name);
        let out = derive(&doc).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(line(&out, "pi"), doc["pi"].as_str().unwrap(), "{name}");
        assert_eq!(
            line(&out, "whitelist root"),
            doc["predicates"]["whitelist"]["root"].as_str().unwrap()
        );
        assert_eq!(
            line(&out, "blacklist root"),
            doc["predicates"]["blacklist"]["root"].as_str().unwrap()
        );
    }
}

/// The documents openampd produced for a real issuance and a real policy
/// update (`derive_snapshot`, kept verbatim from openamp's e2e), read as they
/// are, with the pi openampd declared.
#[test]
fn reads_openampds_derive_snapshots_verbatim() {
    for name in ["openampd-derive-issue.json", "openampd-derive-update.json"] {
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(fixture(name)).unwrap()).unwrap();
        let out = derive(&doc).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(line(&out, "pi"), doc["pi"].as_str().unwrap(), "{name}");
    }
}

#[test]
fn refuses_a_snapshot_that_is_not_the_policy_it_declares() {
    let base = example("snapshot-seq0.json");

    let mut d = base.clone();
    d["pi"] = serde_json::json!("00".repeat(32));
    let e = derive(&d).unwrap_err();
    assert!(
        e.contains("declares pi") && e.contains("not the policy it claims"),
        "{e}"
    );

    let mut d = base.clone();
    d["predicates"]["whitelist"]["root"] = serde_json::json!("11".repeat(32));
    let e = derive(&d).unwrap_err();
    assert!(e.contains("declares a whitelist root"), "{e}");

    // A key added without the root moving: the root no longer covers it.
    let mut d = base.clone();
    d["predicates"]["blacklist"]["entries"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!("22".repeat(32)));
    let e = derive(&d).unwrap_err();
    assert!(e.contains("declares a blacklist root"), "{e}");
}

#[test]
fn refuses_what_it_would_not_enforce_or_cannot_recompute() {
    let base = example("snapshot-seq0.json");

    let mut d = base.clone();
    d["predicates"]["windows"] = serde_json::json!([{"class": "regs", "from": 0, "until": 100}]);
    let e = derive(&d).unwrap_err();
    assert!(
        e.contains("predicates.windows states rules no program enforces"),
        "{e}"
    );

    let mut d = base.clone();
    d["predicates"]["whitelist"]["url"] = serde_json::json!("https://example.invalid/wl");
    let e = derive(&d).unwrap_err();
    assert!(e.contains("published by url is not read"), "{e}");

    // An outpoint written as {txid, vout} is not the published entry shape.
    let mut d = base.clone();
    d["predicates"]["blacklist"]["entries"] =
        serde_json::json!([{"txid": "99".repeat(32), "vout": 0}]);
    let e = derive(&d).unwrap_err();
    assert!(
        e.contains("not an outpoint") && e.contains("opendamp outpoint-key --txid"),
        "{e}"
    );

    let mut d = base.clone();
    d["predicates"]["rate_limit"] = serde_json::json!(5);
    let e = derive(&d).unwrap_err();
    assert!(e.contains("unknown field"), "{e}");

    let mut d = base;
    d["v"] = serde_json::json!(2);
    let e = derive(&d).unwrap_err();
    assert!(e.contains("this build reads snapshot/v1"), "{e}");
}

#[test]
fn outpoint_key_prints_the_blacklist_entry() {
    let out = Command::new(bin())
        .args(["outpoint-key", "--txid", &"99".repeat(32), "--vout", "0"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let key = String::from_utf8(out.stdout).unwrap();
    let base = example("snapshot-seq0.json");
    assert_eq!(
        key.trim(),
        base["predicates"]["blacklist"]["entries"][0]
            .as_str()
            .unwrap()
    );
}
