use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use opbnb_quantum::crypto::*;
use rand::RngCore;
use rpassword::read_password;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    fs,
    fs::OpenOptions,
    io::{self, Write},
    path::PathBuf,
};
use zeroize::Zeroize;

#[derive(Serialize, Deserialize)]
struct WalletFile {
    kyber_public: Vec<u8>,
    kyber_secret: Vec<u8>,
    ntru_public: Vec<u8>,
    ntru_secret: Vec<u8>,
    dilithium_public: Vec<u8>,
    dilithium_secret: Vec<u8>,
}

// Filformat v1:
// [0..4)  : magic "QSW1"
// [4]     : version (1)
// [5]     : kdf_id (1 = Argon2id)
// [6..10) : m_cost_kib (u32 LE)
// [10..14): t_cost (u32 LE)
// [14..18): p_cost (u32 LE)
// [18..34): salt (16B)
// [34..46): nonce (12B)
// [46..]  : ciphertext (AEAD: AES-256-GCM, AAD=header[0..34])
const MAGIC: &[u8; 4] = b"QSW1";
const VERSION: u8 = 1;
const KDF_ID_ARGON2ID: u8 = 1;

fn main() -> io::Result<()> {
    // 1) Wallet-navn
    print!("Wallet name: ");
    io::stdout().flush()?;
    let mut wallet_name = String::new();
    io::stdin().read_line(&mut wallet_name)?;
    let wallet_name = wallet_name.trim();

    // 2) Passord (hemmelig)
    print!("Enter encryption password: ");
    io::stdout().flush()?;
    let password = SecretString::new(read_password().unwrap());

    // 3) Generer PQC-nøkler
    let kyber_keys = kyber1024_keypair();
    let ntru_keys = ntru_keypair();
    let dilithium_keys = dilithium5_keypair();

    let wallet = WalletFile {
        kyber_public: kyber_keys.public_key.clone(),
        kyber_secret: kyber_keys.secret_key.clone(),
        ntru_public: ntru_keys.public_key.clone(),
        ntru_secret: ntru_keys.secret_key.clone(),
        dilithium_public: dilithium_keys.public_key.clone(),
        dilithium_secret: dilithium_keys.secret_key.clone(),
    };

    // NB: vi zeroizer denne etter kryptering
    let mut wallet_json = serde_json::to_vec(&wallet).unwrap();

    // 4) KDF (Argon2id) + HKDF → AES-256 nøkkel
    let m_cost_kib: u32 = 65_536; // 64 MiB
    let t_cost: u32 = 3;
    let p_cost: u32 = 1;

    let params = Params::new(m_cost_kib, t_cost, p_cost, None).expect("argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);

    let mut mk = [0u8; 32]; // master key fra Argon2id
    argon2
        .hash_password_into(password.expose_secret().as_bytes(), &salt, &mut mk)
        .expect("Argon2id failed");

    let hk = Hkdf::<Sha256>::new(Some(&salt), &mk);
    let mut aes_key_bytes = [0u8; 32];
    hk.expand(b"wallet-file-encryption v1", &mut aes_key_bytes)
        .expect("HKDF expand failed");
    mk.zeroize();

    // 5) Bygg header og krypter
    let mut header = Vec::with_capacity(34);
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.push(KDF_ID_ARGON2ID);
    header.extend_from_slice(&m_cost_kib.to_le_bytes());
    header.extend_from_slice(&t_cost.to_le_bytes());
    header.extend_from_slice(&p_cost.to_le_bytes());
    header.extend_from_slice(&salt);

    let key = Key::<Aes256Gcm>::from_slice(&aes_key_bytes);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let payload = Payload {
        msg: &wallet_json,
        aad: &header, // binder headeren kryptografisk
    };
    let ciphertext = cipher.encrypt(nonce, payload).expect("encryption failed");

    // Zeroize plaintext etter bruk
    wallet_json.zeroize();
    aes_key_bytes.zeroize();

    // 6) Lagre til disk (0o600 på Unix)
    let wallet_dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("wallets")
        .join(wallet_name);
    fs::create_dir_all(&wallet_dir)?;

    let mut out = Vec::with_capacity(header.len() + 12 + ciphertext.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);

    let output_path = wallet_dir.join("wallet.json.enc");

    #[cfg(unix)]
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600) // rw-------
            .open(&output_path)?;
        f.write_all(&out)?;
    }
    #[cfg(not(unix))]
    {
        // Fallback på ikke-Unix: standard ACL
        fs::write(&output_path, &out)?;
    }

    println!(
        "✅ Keys generated and stored encrypted in {:?}",
        output_path
    );
    Ok(())
}
