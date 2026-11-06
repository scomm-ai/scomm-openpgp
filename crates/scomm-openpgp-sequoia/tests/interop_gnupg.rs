//! Interop with GnuPG, as a matrix of expected outcomes.
//!
//! A case is either expected to work or is a known gap named after its audit
//! finding (`docs/audits/e2ee-ecc-pqc-audit-2026-11-06.md` in secMail0). A gap
//! that starts working fails the run too, so the matrix stays true.
//!
//! The corpus tests read committed files and need no tools. The live tests run
//! `gpg`: they skip when it is missing unless SCOMM_INTEROP_REQUIRE_TOOLS is set,
//! as it is in CI. On Windows set SCOMM_INTEROP_GNUPGHOME to a short path gpg
//! understands, or they skip there too.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use scomm_openpgp_core::*;
use scomm_openpgp_sequoia::SequoiaOpenPgp;

const KEYS: [&str; 7] = [
    "ed25519",
    "nistp256",
    "nistp384",
    "nistp521",
    "brainpoolP256r1",
    "brainpoolP384r1",
    "rsa3072",
];

#[derive(Clone, Copy)]
enum Expect {
    Works,
    Gap(&'static str),
}
use Expect::*;

#[derive(Default)]
struct Matrix {
    rows: Vec<String>,
    mismatches: Vec<String>,
}

impl Matrix {
    fn case(&mut self, name: &str, expect: Expect, outcome: std::result::Result<(), String>) {
        let detail = outcome.as_ref().err().cloned().unwrap_or_default();
        match (expect, outcome.is_ok()) {
            (Works, true) => self.rows.push(format!("ok    {name}")),
            (Gap(id), false) => self.rows.push(format!("gap   {name} [{id}]: {detail}")),
            (Works, false) => {
                self.rows.push(format!("FAIL  {name}: {detail}"));
                self.mismatches.push(format!("{name} should work: {detail}"));
            }
            (Gap(id), true) => {
                self.rows.push(format!("FIXED {name} [{id}]"));
                self.mismatches
                    .push(format!("{name} now works, so remove gap {id}"));
            }
        }
    }

    fn finish(self, title: &str) {
        println!("\n== {title}\n{}", self.rows.join("\n"));
        assert!(self.mismatches.is_empty(), "{}", self.mismatches.join("\n"));
    }
}

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/gnupg")
}

fn file(name: &str) -> Vec<u8> {
    fs::read(fixtures().join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

fn pgp() -> SequoiaOpenPgp {
    SequoiaOpenPgp::new()
}

fn decrypts(message: &str, key: &str) -> std::result::Result<(), String> {
    let out = pgp()
        .decrypt(&file(message), &file(&format!("{key}.sec")), None)
        .map_err(|e| format!("{e:?}"))?;
    if out.plaintext == file("plaintext.bin") {
        Ok(())
    } else {
        Err("wrong plaintext".into())
    }
}

fn verifies(signature: &str, key: &str) -> std::result::Result<(), String> {
    let result = pgp()
        .verify(
            &file("plaintext.bin"),
            &file(signature),
            &file(&format!("{key}.pub")),
        )
        .map_err(|e| format!("{e:?}"))?;
    match result.validity {
        SignatureValidity::CryptographicallyValid => Ok(()),
        other => Err(format!("{other:?}")),
    }
}

#[test]
fn gnupg_corpus() {
    let mut m = Matrix::default();
    for key in KEYS {
        m.case(
            &format!("{key}: decrypt default (compressed)"),
            Works,
            decrypts(&format!("{key}.default.pgp"), key),
        );
        m.case(
            &format!("{key}: verify detached signature"),
            Works,
            verifies(&format!("{key}.sig"), key),
        );
    }
    for (variant, expect) in [
        ("rfc4880.pgp", Works),
        ("zip.pgp", Works),
        ("zlib.pgp", Works),
        ("bzip2.pgp", Works),
        ("uncompressed.pgp", Works),
        ("armored.asc", Works),
        ("signed.pgp", Works),
    ] {
        m.case(
            &format!("nistp256: decrypt {variant}"),
            expect,
            decrypts(&format!("nistp256.{variant}"), "nistp256"),
        );
    }
    m.case(
        "nistp256: verify armored signature",
        Works,
        verifies("nistp256.armored-sig.asc", "nistp256"),
    );
    m.case(
        "nistp256: signature inside an encrypted message",
        Works,
        (|| {
            let public = file("nistp256.pub");
            let out = pgp()
                .decrypt_and_verify(
                    &file("nistp256.signed.pgp"),
                    &file("nistp256.sec"),
                    None,
                    &[&public],
                )
                .map_err(|e| format!("{e:?}"))?;
            match out.signatures.first().map(|s| s.validity) {
                Some(SignatureValidity::CryptographicallyValid) => Ok(()),
                other => Err(format!("{other:?}")),
            }
        })(),
    );
    m.case(
        "LibrePGP OCB message (tag 20)",
        Gap("H4"),
        decrypts("ocb.tag20.pgp", "ocb"),
    );
    m.case(
        "LibrePGP v5 Ed448 key",
        Gap("H4"),
        pgp()
            .inspect_key(&file("ed448.pub"))
            .map(|_| ())
            .map_err(|e| format!("{e:?}")),
    );
    m.finish("GnuPG corpus");
}

#[test]
fn catalog_names_for_gnupg_keys() {
    for (key, primary, encryption) in [
        ("ed25519", "openpgp-ed25519", "openpgp-cv25519"),
        ("nistp256", "openpgp-ecdsa-p256", "openpgp-ecdh-p256"),
        ("nistp384", "openpgp-ecdsa-p384", "openpgp-ecdh-p384"),
        ("nistp521", "openpgp-ecdsa-p521", "openpgp-ecdh-p521"),
        ("brainpoolP256r1", "openpgp-ecdsa-brainpool-p256", "openpgp-ecdh-brainpool-p256"),
        ("brainpoolP384r1", "openpgp-ecdsa-brainpool-p384", "openpgp-ecdh-brainpool-p384"),
        ("rsa3072", "openpgp-rsa3072", "openpgp-rsa3072"),
    ] {
        let info = pgp().inspect_key(&file(&format!("{key}.pub"))).expect(key);
        assert_eq!(info.algorithm, primary, "{key}");
        assert!(
            info.subkeys.iter().any(|s| s.algorithm == encryption),
            "{key}: {:?}",
            info.subkeys.iter().map(|s| &s.algorithm).collect::<Vec<_>>()
        );
    }
}

struct Gpg {
    home: PathBuf,
    work: PathBuf,
}

impl Gpg {
    /// None when live tests should skip.
    fn start(test: &str) -> Option<Self> {
        let required = std::env::var_os("SCOMM_INTEROP_REQUIRE_TOOLS").is_some();
        let available = Command::new("gpg").arg("--version").output().is_ok();
        let configured = std::env::var_os("SCOMM_INTEROP_GNUPGHOME").map(PathBuf::from);
        if !available || (cfg!(windows) && configured.is_none()) {
            assert!(!required, "gpg is required but not usable");
            println!("skipped: gpg not usable here");
            return None;
        }
        let pid = std::process::id();
        let work = std::env::temp_dir().join(format!("scomm-interop-{test}-{pid}"));
        // gpg-agent sockets have a short path limit, so keep the home short.
        let home = configured.unwrap_or_else(|| PathBuf::from(format!("/tmp/sg{pid}{}", test.len())));
        let _ = fs::remove_dir_all(&work);
        fs::create_dir_all(&work).unwrap();
        let this = Self { home, work };
        if !cfg!(windows) {
            fs::create_dir_all(&this.home).unwrap();
            use_private_mode(&this.home);
        }
        println!("{}", String::from_utf8_lossy(&Command::new("gpg").arg("--version").output().unwrap().stdout).lines().next().unwrap_or(""));
        Some(this)
    }

    fn run(&self, args: &[&str]) -> std::result::Result<String, String> {
        let out = Command::new("gpg")
            .current_dir(&self.work)
            .env("MSYS_NO_PATHCONV", "1")
            .arg("--homedir")
            .arg(&self.home)
            .args(["--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", "", "--trust-model", "always"])
            .args(args)
            .output()
            .map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&out.stderr).to_string();
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).to_string())
        } else {
            Err(text.lines().next().unwrap_or("gpg failed").to_string())
        }
    }

    fn write(&self, name: &str, data: &[u8]) {
        fs::write(self.work.join(name), data).unwrap();
    }

    fn read(&self, name: &str) -> Vec<u8> {
        fs::read(self.work.join(name)).unwrap()
    }
}

impl Drop for Gpg {
    fn drop(&mut self) {
        let _ = Command::new("gpgconf")
            .env("MSYS_NO_PATHCONV", "1")
            .arg("--homedir")
            .arg(&self.home)
            .args(["--kill", "all"])
            .output();
        let _ = fs::remove_dir_all(&self.work);
        if std::env::var_os("SCOMM_INTEROP_GNUPGHOME").is_none() {
            let _ = fs::remove_dir_all(&self.home);
        }
    }
}

#[cfg(unix)]
fn use_private_mode(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[cfg(not(unix))]
fn use_private_mode(_path: &Path) {}

#[test]
fn scomm_to_and_from_live_gnupg() {
    let Some(gpg) = Gpg::start("live") else { return };
    let plaintext = file("plaintext.bin");
    gpg.write("plaintext.bin", &plaintext);
    let mut m = Matrix::default();

    for key in KEYS {
        let secret = file(&format!("{key}.sec"));
        gpg.write(&format!("{key}.sec"), &secret);
        gpg.run(&["--import", &format!("{key}.sec")]).expect("import corpus key");
        let public = file(&format!("{key}.pub"));

        m.case(
            &format!("{key}: Scomm encrypts, gpg decrypts"),
            Works,
            (|| {
                let ct = pgp()
                    .encrypt(&plaintext, &[&public], &EncryptOptions::default())
                    .map_err(|e| format!("{e:?}"))?;
                gpg.write("out.pgp", &ct);
                gpg.run(&["--output", "out.txt", "--decrypt", "out.pgp"])?;
                if gpg.read("out.txt") == plaintext {
                    Ok(())
                } else {
                    Err("wrong plaintext".into())
                }
            })(),
        );
        m.case(
            &format!("{key}: Scomm signs, gpg verifies"),
            Works,
            (|| {
                let sig = pgp()
                    .sign(&plaintext, &secret, None, &SignOptions::default())
                    .map_err(|e| format!("{e:?}"))?;
                gpg.write("out.sig", &sig.bytes);
                gpg.run(&["--verify", "out.sig", "plaintext.bin"]).map(|_| ())
            })(),
        );
        m.case(
            &format!("{key}: gpg encrypts by default, Scomm decrypts"),
            Works,
            (|| {
                gpg.run(&["-r", &format!("{key}@example.com"), "--output", "in.pgp", "--encrypt", "plaintext.bin"])?;
                let out = pgp()
                    .decrypt(&gpg.read("in.pgp"), &secret, None)
                    .map_err(|e| format!("{e:?}"))?;
                if out.plaintext == plaintext {
                    Ok(())
                } else {
                    Err("wrong plaintext".into())
                }
            })(),
        );
    }

    let generate = |profile| {
        pgp()
            .generate_key(&GenerateKeyOptions {
                userid: "Scomm <scomm@example.com>".into(),
                passphrase: None,
                profile,
            })
            .expect("generate")
    };
    let v4 = generate(KeyProfile::ClassicalCv25519);
    gpg.write("v4.sec", &v4.secret);
    gpg.run(&["--import", "v4.sec"]).expect("gpg takes a v4 key");
    m.case(
        "Scomm v4 key: Scomm encrypts, gpg decrypts",
        Gap("H4"),
        (|| {
            let ct = pgp()
                .encrypt(&plaintext, &[&v4.public], &EncryptOptions::default())
                .map_err(|e| format!("{e:?}"))?;
            gpg.write("v4.pgp", &ct);
            gpg.run(&["--output", "v4.txt", "--decrypt", "v4.pgp"]).map(|_| ())
        })(),
    );
    for (name, profile) in [
        ("Scomm v6 Curve25519 key: gpg imports", KeyProfile::Rfc9580Cv25519),
        ("Scomm RFC 9980 key: gpg imports", KeyProfile::Rfc9980MlDsa65),
    ] {
        let key = generate(profile);
        gpg.write("v6.pub", &key.public);
        m.case(name, Gap("H4"), gpg.run(&["--import", "v6.pub"]).map(|_| ()));
    }
    m.finish("Live GnuPG");
}
