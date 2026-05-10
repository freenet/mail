//! `web-container-sign` — keypair management and webapp signing for the
//! freenet-email web-container contract.
//!
//! This is the freenet-email equivalent of freenet-river's
//! `web-container-tool`, pared down to the minimum needed by our publish
//! pipeline. It has no dependency on river or river-core — it only needs
//! `freenet_email_core::web_container::WebContainerMetadata` (the same
//! struct the on-chain contract deserializes) and `ed25519-dalek`.
//!
//! Key format on disk (TOML):
//!
//! ```toml
//! [keys]
//! signing_key   = "<base58 32-byte ed25519 secret scalar>"
//! verifying_key = "<base58 32-byte ed25519 public key>"
//! ```
//!
//! Signed payload matches the on-chain contract at
//! `contracts/web-container/src/lib.rs`: `version (u32 BE) || webapp_bytes`.
//!
//! Output files produced by `sign`:
//!   * `<output>`        — CBOR-serialized `WebContainerMetadata`
//!   * `<parameters>`    — 32 raw bytes: the verifying key
//!
//! The metadata + parameters pair, together with the compressed webapp
//! archive, is what `fdev publish` uploads to the network.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use freenet_email_core::facade::{
    FACADE_MAX_PREV_APP_IDS, FacadeMetadata, FacadePointer, signed_payload as facade_signed_payload,
};
use freenet_email_core::web_container::WebContainerMetadata;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(name = "web-container-sign")]
#[command(about = "Sign the freenet-email webapp with an ed25519 key")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new ed25519 keypair and write it as a TOML key file.
    Generate {
        /// Destination path. Parent directories are created if missing.
        #[arg(long, short)]
        output: PathBuf,
        /// Refuse to overwrite an existing key file.
        #[arg(long, default_value_t = true)]
        no_clobber: bool,
    },
    /// Sign a compressed webapp archive.
    Sign {
        /// Input compressed webapp (typically a `.tar.xz`).
        #[arg(long, short)]
        input: PathBuf,
        /// Output path for the CBOR-serialized `WebContainerMetadata`.
        #[arg(long, short)]
        output: PathBuf,
        /// Output path for the 32-byte verifying key (contract parameters).
        #[arg(long)]
        parameters: PathBuf,
        /// Monotonic version number embedded in the signed payload.
        #[arg(long, short)]
        version: u32,
        /// Path to the TOML key file produced by `generate`.
        #[arg(long, short)]
        key_file: PathBuf,
    },
    /// Print the verifying key from a key file in base58.
    ShowPub {
        #[arg(long, short)]
        key_file: PathBuf,
    },
    /// Sign facade contract state (issue #200 / Phase 1).
    ///
    /// Produces a fully-formed facade state blob — `[meta_len][meta][web_len][web]`
    /// — where `web` is the loader bytes and `meta` carries the signed
    /// pointer to `current_app_id`. Outputs both the state blob and the
    /// 32-byte parameters file (the verifying key) so `fdev publish`
    /// (or update) has everything it needs.
    SignFacadeState {
        /// Loader webapp archive (typically `target/facade-webapp/loader.tar.xz`).
        /// Whatever the facade contract serves under its webapp slot.
        #[arg(long)]
        loader: PathBuf,
        /// Base58 contract id this facade should redirect to.
        #[arg(long)]
        current_app_id: String,
        /// Optional `version:base58_id` pair for rollback. Repeatable; the
        /// most-recent entry comes first. Caps at FACADE_MAX_PREV_APP_IDS.
        #[arg(long = "prev", value_name = "VERSION:APP_ID")]
        prev: Vec<String>,
        /// Monotonic version (typically the unix timestamp at signing).
        #[arg(long, short)]
        version: u64,
        /// Path to the TOML key file. Reuses the same ed25519 key the
        /// production web-container uses — the facade verifying key IS
        /// the freenet-email "publisher identity".
        #[arg(long, short)]
        key_file: PathBuf,
        /// Output path for the facade state blob.
        #[arg(long, short)]
        output: PathBuf,
        /// Output path for the 32-byte verifying key (contract parameters).
        #[arg(long)]
        parameters: PathBuf,
    },
}

#[derive(Serialize, Deserialize)]
struct KeyFile {
    keys: KeyFileInner,
}

#[derive(Serialize, Deserialize)]
struct KeyFileInner {
    /// Base58-encoded 32-byte ed25519 secret scalar.
    signing_key: String,
    /// Base58-encoded 32-byte ed25519 public key (stored for
    /// human-readable cross-checks; always re-derived on load).
    verifying_key: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Generate { output, no_clobber } => cmd_generate(&output, no_clobber),
        Commands::Sign {
            input,
            output,
            parameters,
            version,
            key_file,
        } => cmd_sign(&input, &output, &parameters, version, &key_file),
        Commands::ShowPub { key_file } => cmd_show_pub(&key_file),
        Commands::SignFacadeState {
            loader,
            current_app_id,
            prev,
            version,
            key_file,
            output,
            parameters,
        } => cmd_sign_facade_state(
            &loader,
            &current_app_id,
            &prev,
            version,
            &key_file,
            &output,
            &parameters,
        ),
    }
}

fn cmd_sign_facade_state(
    loader: &Path,
    current_app_id_b58: &str,
    prev: &[String],
    version: u64,
    key_file: &Path,
    output: &Path,
    parameters: &Path,
) -> Result<()> {
    if version == 0 {
        bail!("version must be > 0 (the on-chain contract rejects version 0)");
    }
    if prev.len() > FACADE_MAX_PREV_APP_IDS {
        bail!(
            "too many --prev entries: {} (cap is {FACADE_MAX_PREV_APP_IDS})",
            prev.len()
        );
    }

    let signing_key = load_signing_key(key_file)?;
    let verifying_key = signing_key.verifying_key();

    let current_app_id = decode_app_id(current_app_id_b58)
        .with_context(|| format!("decoding --current-app-id {current_app_id_b58}"))?;

    let mut prev_app_ids: Vec<(u64, [u8; 32])> = Vec::with_capacity(prev.len());
    for entry in prev {
        let (v_str, id_str) = entry
            .split_once(':')
            .ok_or_else(|| anyhow!("--prev '{entry}' must be VERSION:APP_ID"))?;
        let v: u64 = v_str
            .parse()
            .with_context(|| format!("parsing prev version '{v_str}'"))?;
        if v >= version {
            bail!("--prev version {v} must be strictly less than current version {version}");
        }
        let id =
            decode_app_id(id_str).with_context(|| format!("decoding --prev app_id {id_str}"))?;
        prev_app_ids.push((v, id));
    }

    let loader_bytes =
        fs::read(loader).with_context(|| format!("reading loader archive {}", loader.display()))?;

    // Best-effort consistency check: the loader is normally rendered by
    // scripts/build-loader.sh, which embeds `current_app_id` directly into
    // the HTML. If the loader bytes don't contain the id we're signing,
    // the operator probably forgot to re-render the loader before re-signing
    // — the signed pointer would then redirect users to a different app
    // than the loader does. Catch this silently-broken state here.
    if !loader_bytes
        .windows(current_app_id_b58.len())
        .any(|w| w == current_app_id_b58.as_bytes())
    {
        bail!(
            "loader at {} does not contain current_app_id '{current_app_id_b58}'. \
             Re-run scripts/build-loader.sh before signing, or pass --skip-loader-check (not implemented).",
            loader.display()
        );
    }

    let pointer = FacadePointer {
        version,
        current_app_id,
        prev_app_ids,
    };
    let payload = facade_signed_payload(&pointer, &loader_bytes);
    let signature = signing_key.sign(&payload);
    let metadata = FacadeMetadata { pointer, signature };

    // Serialize metadata then frame:
    // [meta_len: u64 BE][meta: CBOR][web_len: u64 BE][web: bytes]
    let mut metadata_bytes = Vec::new();
    ciborium::ser::into_writer(&metadata, &mut metadata_bytes)
        .map_err(|e| anyhow!("serialize facade metadata: {e}"))?;

    let mut state = Vec::with_capacity(8 + metadata_bytes.len() + 8 + loader_bytes.len());
    state.extend_from_slice(&(metadata_bytes.len() as u64).to_be_bytes());
    state.extend_from_slice(&metadata_bytes);
    state.extend_from_slice(&(loader_bytes.len() as u64).to_be_bytes());
    state.extend_from_slice(&loader_bytes);

    if let Some(parent) = output.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::write(output, &state).with_context(|| format!("writing {}", output.display()))?;

    if let Some(parent) = parameters.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::write(parameters, verifying_key.to_bytes())
        .with_context(|| format!("writing {}", parameters.display()))?;

    println!(
        "signed facade state: version={version} current_app_id={current_app_id_b58} prev={}",
        prev.len()
    );
    println!(
        "  loader:     {} ({} bytes)",
        loader.display(),
        loader_bytes.len()
    );
    println!("  state:      {} ({} bytes)", output.display(), state.len());
    println!("  parameters: {}", parameters.display());
    println!(
        "  pubkey:     {} (base58)",
        bs58::encode(verifying_key.to_bytes()).into_string()
    );
    Ok(())
}

fn decode_app_id(b58: &str) -> Result<[u8; 32]> {
    let bytes = bs58::decode(b58.trim())
        .into_vec()
        .context("base58 decode")?;
    if bytes.len() != 32 {
        bail!("expected 32 bytes after base58 decode, got {}", bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn cmd_generate(output: &Path, no_clobber: bool) -> Result<()> {
    if output.exists() && no_clobber {
        bail!(
            "refusing to overwrite existing key file at {}",
            output.display()
        );
    }
    if let Some(parent) = output.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let file = KeyFile {
        keys: KeyFileInner {
            signing_key: bs58::encode(signing_key.to_bytes()).into_string(),
            verifying_key: bs58::encode(verifying_key.to_bytes()).into_string(),
        },
    };
    let toml = toml::to_string_pretty(&file).context("serialize key file")?;
    fs::write(output, toml).with_context(|| format!("writing {}", output.display()))?;

    // Tighten permissions on Unix — 0600 — since this file holds a secret.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(output)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(output, perms)?;
    }

    println!("wrote {}", output.display());
    println!(
        "verifying key (base58): {}",
        bs58::encode(verifying_key.to_bytes()).into_string()
    );
    Ok(())
}

fn cmd_sign(
    input: &Path,
    output: &Path,
    parameters: &Path,
    version: u32,
    key_file: &Path,
) -> Result<()> {
    if version == 0 {
        bail!("version must be > 0 (the on-chain contract rejects version 0)");
    }

    let signing_key = load_signing_key(key_file)?;
    let verifying_key = signing_key.verifying_key();

    let webapp_bytes =
        fs::read(input).with_context(|| format!("reading webapp archive {}", input.display()))?;

    // Match the on-chain verifier: signed payload = version (u32 BE) || webapp.
    let mut message = Vec::with_capacity(4 + webapp_bytes.len());
    message.extend_from_slice(&version.to_be_bytes());
    message.extend_from_slice(&webapp_bytes);

    let signature = signing_key.sign(&message);
    let metadata = WebContainerMetadata { version, signature };

    // Write metadata as CBOR.
    if let Some(parent) = output.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let mut out_file =
        fs::File::create(output).with_context(|| format!("creating {}", output.display()))?;
    let mut cbor_bytes = Vec::new();
    ciborium::ser::into_writer(&metadata, &mut cbor_bytes)
        .map_err(|e| anyhow!("serialize metadata: {e}"))?;
    out_file.write_all(&cbor_bytes)?;

    // Write parameters as raw 32 verifying-key bytes (matches the contract's
    // expectation at contracts/web-container/src/lib.rs — `parameters` must
    // be exactly 32 bytes interpreted as an ed25519 public key).
    if let Some(parent) = parameters.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::write(parameters, verifying_key.to_bytes())
        .with_context(|| format!("writing {}", parameters.display()))?;

    println!("signed {} ({} bytes)", input.display(), webapp_bytes.len());
    println!("  version:    {version}");
    println!("  metadata:   {}", output.display());
    println!("  parameters: {}", parameters.display());
    println!(
        "  pubkey:     {} (base58)",
        bs58::encode(verifying_key.to_bytes()).into_string()
    );
    Ok(())
}

fn cmd_show_pub(key_file: &Path) -> Result<()> {
    let signing_key = load_signing_key(key_file)?;
    let verifying_key = signing_key.verifying_key();
    println!("{}", bs58::encode(verifying_key.to_bytes()).into_string());
    Ok(())
}

fn load_signing_key(key_file: &Path) -> Result<SigningKey> {
    let toml_str = fs::read_to_string(key_file)
        .with_context(|| format!("reading key file {}", key_file.display()))?;
    let parsed: KeyFile = toml::from_str(&toml_str).context("parsing key file TOML")?;

    let sk_bytes = bs58::decode(&parsed.keys.signing_key)
        .into_vec()
        .context("decoding signing_key base58")?;
    if sk_bytes.len() != 32 {
        bail!(
            "signing_key must decode to 32 bytes, got {}",
            sk_bytes.len()
        );
    }
    let mut sk_array = [0u8; 32];
    sk_array.copy_from_slice(&sk_bytes);
    let signing_key = SigningKey::from_bytes(&sk_array);

    // Sanity check: ensure the embedded verifying key matches.
    let vk_bytes = bs58::decode(&parsed.keys.verifying_key)
        .into_vec()
        .context("decoding verifying_key base58")?;
    if vk_bytes.len() != 32 {
        bail!(
            "verifying_key must decode to 32 bytes, got {}",
            vk_bytes.len()
        );
    }
    let mut vk_array = [0u8; 32];
    vk_array.copy_from_slice(&vk_bytes);
    let stored = VerifyingKey::from_bytes(&vk_array).context("parsing stored verifying_key")?;
    let derived = signing_key.verifying_key();
    if stored != derived {
        bail!("key file verifying_key does not match the derived value — file is corrupt");
    }
    Ok(signing_key)
}

#[cfg(test)]
mod tests {
    //! Round-trip regression tests. The on-chain contract lives in
    //! `contracts/web-container/src/lib.rs`; the checks here mirror the
    //! exact wire format so that any future divergence trips a test
    //! locally instead of on-chain.

    use super::*;
    use ed25519_dalek::{Verifier, VerifyingKey};
    use tempfile::tempdir;

    #[test]
    fn generate_then_load_roundtrip() {
        let dir = tempdir().unwrap();
        let key_file = dir.path().join("keys.toml");
        cmd_generate(&key_file, true).unwrap();

        // Re-reading must succeed and produce a key whose derived pubkey
        // matches the stored one (the load path asserts this itself, but
        // exercising it through the public entry point is the regression
        // test we actually care about).
        let sk = load_signing_key(&key_file).unwrap();
        assert_eq!(sk.verifying_key().to_bytes().len(), 32);
    }

    #[test]
    fn sign_produces_contract_compatible_payload() {
        let dir = tempdir().unwrap();
        let key_file = dir.path().join("keys.toml");
        let webapp = dir.path().join("webapp.tar.xz");
        let metadata = dir.path().join("webapp.metadata");
        let parameters = dir.path().join("webapp.parameters");

        cmd_generate(&key_file, true).unwrap();
        fs::write(&webapp, b"pretend this is a tar.xz").unwrap();

        cmd_sign(&webapp, &metadata, &parameters, 42, &key_file).unwrap();

        // Parameters file is exactly 32 raw bytes (the contract refuses
        // any other length: contracts/web-container/src/lib.rs:32).
        let param_bytes = fs::read(&parameters).unwrap();
        assert_eq!(param_bytes.len(), 32);

        // Metadata is CBOR-deserializable into WebContainerMetadata.
        let meta_bytes = fs::read(&metadata).unwrap();
        let decoded: WebContainerMetadata = ciborium::de::from_reader(&meta_bytes[..]).unwrap();
        assert_eq!(decoded.version, 42);

        // Signature over `version (u32 BE) || webapp_bytes` must verify
        // under the parameters pubkey — this is exactly what the on-chain
        // contract does in `validate_state`.
        let mut vk_array = [0u8; 32];
        vk_array.copy_from_slice(&param_bytes);
        let vk = VerifyingKey::from_bytes(&vk_array).unwrap();
        let webapp_bytes = fs::read(&webapp).unwrap();
        let mut message = 42u32.to_be_bytes().to_vec();
        message.extend_from_slice(&webapp_bytes);
        vk.verify(&message, &decoded.signature).unwrap();
    }

    #[test]
    fn rejects_version_zero() {
        let dir = tempdir().unwrap();
        let key_file = dir.path().join("keys.toml");
        let webapp = dir.path().join("webapp.tar.xz");
        cmd_generate(&key_file, true).unwrap();
        fs::write(&webapp, b"x").unwrap();
        let err = cmd_sign(
            &webapp,
            &dir.path().join("m"),
            &dir.path().join("p"),
            0,
            &key_file,
        )
        .unwrap_err();
        assert!(err.to_string().contains("version must be > 0"));
    }

    #[test]
    fn generate_refuses_to_clobber_by_default() {
        let dir = tempdir().unwrap();
        let key_file = dir.path().join("keys.toml");
        cmd_generate(&key_file, true).unwrap();
        let err = cmd_generate(&key_file, true).unwrap_err();
        assert!(err.to_string().contains("refusing to overwrite"));
    }

    /// `sign-facade-state` must produce a state blob that the on-chain
    /// `freenet-email-facade` contract accepts. We round-trip through the
    /// same `signed_payload()` helper both sides use so any future drift
    /// in field ordering trips a unit test.
    #[test]
    fn sign_facade_state_round_trip() {
        use ed25519_dalek::Verifier;

        fn read_u64_be(buf: &[u8], off: &mut usize) -> u64 {
            let v = u64::from_be_bytes(buf[*off..*off + 8].try_into().unwrap());
            *off += 8;
            v
        }

        let dir = tempdir().unwrap();
        let key_file = dir.path().join("keys.toml");
        let loader = dir.path().join("loader.tar.xz");
        let state = dir.path().join("facade.state");
        let parameters = dir.path().join("facade.parameters");

        cmd_generate(&key_file, true).unwrap();
        let app_id = [0xABu8; 32];
        let app_id_b58 = bs58::encode(app_id).into_string();
        // Loader must embed current_app_id (signer enforces this; mirrors
        // what scripts/build-loader.sh produces).
        fs::write(&loader, format!("<html>id={app_id_b58}</html>")).unwrap();
        let prev_id = [0xCDu8; 32];
        let prev_b58 = format!("100:{}", bs58::encode(prev_id).into_string());

        cmd_sign_facade_state(
            &loader,
            &app_id_b58,
            &[prev_b58],
            200,
            &key_file,
            &state,
            &parameters,
        )
        .unwrap();

        let param_bytes = fs::read(&parameters).unwrap();
        assert_eq!(param_bytes.len(), 32);
        let mut vk_array = [0u8; 32];
        vk_array.copy_from_slice(&param_bytes);
        let vk = VerifyingKey::from_bytes(&vk_array).unwrap();

        // Re-parse the state blob exactly the way the on-chain contract does.
        let blob = fs::read(&state).unwrap();
        let mut off = 0usize;
        let meta_len = read_u64_be(&blob, &mut off) as usize;
        let meta_bytes = &blob[off..off + meta_len];
        off += meta_len;
        let metadata: FacadeMetadata = ciborium::de::from_reader(meta_bytes).unwrap();
        let web_len = read_u64_be(&blob, &mut off) as usize;
        let loader_bytes = blob[off..off + web_len].to_vec();

        assert_eq!(metadata.pointer.version, 200);
        assert_eq!(metadata.pointer.current_app_id, app_id);
        assert_eq!(metadata.pointer.prev_app_ids, vec![(100u64, prev_id)]);
        assert_eq!(
            loader_bytes,
            format!("<html>id={app_id_b58}</html>").into_bytes()
        );

        let payload = facade_signed_payload(&metadata.pointer, &loader_bytes);
        vk.verify(&payload, &metadata.signature).unwrap();
    }

    #[test]
    fn sign_facade_state_rejects_prev_at_or_above_current_version() {
        let dir = tempdir().unwrap();
        let key_file = dir.path().join("keys.toml");
        let loader = dir.path().join("loader");
        cmd_generate(&key_file, true).unwrap();
        fs::write(&loader, b"x").unwrap();

        let id_b58 = bs58::encode([0u8; 32]).into_string();
        let prev = format!("5:{id_b58}");
        let err = cmd_sign_facade_state(
            &loader,
            &id_b58,
            &[prev],
            5,
            &key_file,
            &dir.path().join("s"),
            &dir.path().join("p"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("strictly less"));
    }

    /// Regression for review-finding B6: signer rejects when the loader
    /// bytes don't embed the current_app_id. Catches the silent
    /// inconsistency where operator passes mismatching --loader and
    /// --current-app-id (e.g. forgot to re-render the loader).
    #[test]
    fn sign_facade_state_rejects_loader_without_current_app_id() {
        let dir = tempdir().unwrap();
        let key_file = dir.path().join("keys.toml");
        let loader = dir.path().join("loader");
        cmd_generate(&key_file, true).unwrap();
        // Loader does NOT contain the app id we'll sign.
        fs::write(&loader, b"<html>stale loader</html>").unwrap();

        let app_id_b58 = bs58::encode([0xAAu8; 32]).into_string();
        let err = cmd_sign_facade_state(
            &loader,
            &app_id_b58,
            &[],
            42,
            &key_file,
            &dir.path().join("s"),
            &dir.path().join("p"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("does not contain current_app_id"));
    }
}
