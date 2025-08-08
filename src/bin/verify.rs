use std::{
    env, fs,
    io::{self, Write},
    path::PathBuf,
};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use dirs::home_dir;
use hkdf::Hkdf;
use opbnb_quantum::crypto::sig::verify_message;
use rpassword::read_password;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use zeroize::Zeroize;

const MAGIC: &[u8; 4] = b"QSW1";
const SUPPORTED_VERSION: u8 = 1;
const KDF_ID_ARGON2ID: u8 = 1;
const HKDF_INFO_V1: &[u8] = b"wallet-file-encryption v1";

#[derive(Deserialize)]
struct JsonEnvelope {
    salt: String,       // hex
    nonce: String,      // hex(12)
    ciphertext: String, // hex
}

#[derive(Deserialize)]
struct WalletJson {
    dilithium_public: String, // hex
}

#[derive(Deserialize)]
struct WalletBin {
    #[allow(dead_code)]
    kyber_public: Vec<u8>,
    #[allow(dead_code)]
    kyber_secret: Vec<u8>,
    #[allow(dead_code)]
    ntru_public: Vec<u8>,
    #[allow(dead_code)]
    ntru_secret: Vec<u8>,
    dilithium_public: Vec<u8>,
    #[allow(dead_code)]
    dilithium_secret: Vec<u8>,
}

struct Args {
    wallet: Option<String>,
    file: PathBuf,
    sig_hex: String,
    pass_env: Option<String>,
}

fn parse_args() -> Result<Args> {
    let mut it = env::args().skip(1);
    let mut wallet: Option<String> = None;
    let mut file: Option<PathBuf> = None;
    let mut sig_hex: Option<String> = None;
    let mut pass_env: Option<String> = None;

    while let Some(a) = it.next() {
        match a.as_str() {
            "--wallet" => {
                wallet = Some(it.next().ok_or_else(|| anyhow!("--wallet needs a value"))?)
            }
            "--pass-env" => {
                pass_env = Some(
                    it.next()
                        .ok_or_else(|| anyhow!("--pass-env needs VAR name"))?,
                )
            }
            "--file" | "-f" => {
                let p = it.next().ok_or_else(|| anyhow!("--file needs a path"))?;
                file = Some(PathBuf::from(p));
            }
            "--sig" => {
                sig_hex = Some(
                    it.next()
                        .ok_or_else(|| anyhow!("--sig needs a hex string"))?,
                )
            }
            s if s.starts_with('-') => return Err(anyhow!("unknown arg: {s}")),
            other => return Err(anyhow!("unexpected argument: {other}")),
        }
    }

    Ok(Args {
        wallet,
        file: file.ok_or_else(|| anyhow!("--file is required"))?,
        sig_hex: sig_hex.ok_or_else(|| anyhow!("--sig is required"))?,
        pass_env,
    })
}

fn load_public_key(wallet_name: &str, password: &SecretString) -> Result<Vec<u8>> {
    let wallet_path = home_dir()
        .ok_or_else(|| anyhow!("could not determine home directory"))?
        .join("wallets")
        .join(wallet_name)
        .join("wallet.json.enc");
    let data = fs::read(&wallet_path)
        .with_context(|| format!("failed to read {}", wallet_path.display()))?;

    // A) Binært QSW1-omslag
    if data.len() >= 46 && &data[0..4] == MAGIC {
        let version = data[4];
        if version != SUPPORTED_VERSION {
            return Err(anyhow!("unsupported wallet version: {}", version));
        }
        let kdf_id = data[5];
        if kdf_id != KDF_ID_ARGON2ID {
            return Err(anyhow!("unsupported KDF id: {}", kdf_id));
        }
        let m_cost_kib = u32::from_le_bytes(data[6..10].try_into().unwrap());
        let t_cost = u32::from_le_bytes(data[10..14].try_into().unwrap());
        let p_cost = u32::from_le_bytes(data[14..18].try_into().unwrap());
        let salt: [u8; 16] = data[18..34].try_into().unwrap();
        let nonce_bytes: [u8; 12] = data[34..46].try_into().unwrap();
        let ciphertext = &data[46..];

        let params = Params::new(m_cost_kib, t_cost, p_cost, None).expect("argon2 params");
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut mk = [0u8; 32];
        argon2
            .hash_password_into(password.expose_secret().as_bytes(), &salt, &mut mk)
            .map_err(|_| anyhow!("argon2 derivation failed"))?;

        let hk = Hkdf::<sha2::Sha256>::new(Some(&salt), &mk);
        let mut aes_key_bytes = [0u8; 32];
        hk.expand(HKDF_INFO_V1, &mut aes_key_bytes)
            .map_err(|_| anyhow!("HKDF expand failed"))?;
        mk.zeroize();

        let key = Key::<Aes256Gcm>::from_slice(&aes_key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let header_aad = &data[0..34];
        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: header_aad,
                },
            )
            .map_err(|_| anyhow!("decryption failed (bad password or corrupted file)"))?;
        aes_key_bytes.zeroize();

        let wb: WalletBin =
            serde_json::from_slice(&plaintext).context("corrupted plaintext JSON")?;
        return Ok(wb.dilithium_public);
    }

    // B) JSON-omslag
    let envlp: JsonEnvelope =
        serde_json::from_slice(&data).context("invalid encrypted wallet format")?;
    let salt = hex::decode(envlp.salt.trim()).context("bad salt hex")?;
    let nonce_bytes = hex::decode(envlp.nonce.trim()).context("bad nonce hex")?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = hex::decode(envlp.ciphertext.trim()).context("bad ciphertext hex")?;

    let params = Params::new(19_456, 2, 1, Some(32)).unwrap();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut mk = [0u8; 32];
    argon2
        .hash_password_into(password.expose_secret().as_bytes(), &salt, &mut mk)
        .map_err(|_| anyhow!("argon2 derivation failed"))?;

    let hk = Hkdf::<sha2::Sha256>::new(Some(&salt), &mk);
    let mut aes_key = [0u8; 32];
    hk.expand(HKDF_INFO_V1, &mut aes_key)
        .map_err(|_| anyhow!("hkdf expand failed"))?;
    mk.zeroize();

    let cipher = Aes256Gcm::new_from_slice(&aes_key).unwrap();
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &ciphertext,
                aad: b"wallet-v1",
            },
        )
        .map_err(|_| anyhow!("decryption failed (bad password or corrupted file)"))?;
    aes_key.zeroize();

    let wj: WalletJson = serde_json::from_slice(&plaintext).context("invalid wallet JSON")?;
    let pk = hex::decode(wj.dilithium_public.trim()).context("bad dilithium_public hex")?;
    Ok(pk)
}

fn main() -> Result<()> {
    let args = parse_args()?;

    let wallet_name = if let Some(w) = args.wallet {
        w
    } else {
        print!("Wallet name: ");
        io::stdout().flush()?;
        let mut wallet_name = String::new();
        io::stdin().read_line(&mut wallet_name)?;
        wallet_name.trim().to_owned()
    };

    let password = if let Some(var) = &args.pass_env {
        let val = std::env::var(var).context("missing env var for password")?;
        SecretString::new(val)
    } else {
        print!("Enter verification password: ");
        io::stdout().flush()?;
        SecretString::new(read_password().unwrap_or_default())
    };

    let message =
        fs::read(&args.file).with_context(|| format!("failed to read {}", args.file.display()))?;
    let sig_bytes = hex::decode(args.sig_hex.trim()).context("invalid hex in --sig")?;

    let pk = load_public_key(&wallet_name, &password)?;
    let ok = verify_message(&sig_bytes, &pk, &message);
    println!(
        "{}",
        if ok {
            "✅ signature valid"
        } else {
            "❌ signature invalid"
        }
    );

    Ok(())
}
