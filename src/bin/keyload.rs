use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rpassword::read_password;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
};
use zeroize::Zeroize;

#[derive(Deserialize)]
struct WalletFile {
    kyber_public: Vec<u8>,
    // Disse feltene skal aldri logges/vises (OPSEC). De deserialiseres kun.
    #[allow(dead_code)]
    kyber_secret: Vec<u8>,
    ntru_public: Vec<u8>,
    #[allow(dead_code)]
    ntru_secret: Vec<u8>,
    dilithium_public: Vec<u8>,
    #[allow(dead_code)]
    dilithium_secret: Vec<u8>,
}

// Filformat v1 (må matche keygen):
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
const SUPPORTED_VERSION: u8 = 1;
const KDF_ID_ARGON2ID: u8 = 1;

fn main() -> io::Result<()> {
    // 1) Velg wallet
    print!("Wallet name to load: ");
    io::stdout().flush()?;
    let mut wallet_name = String::new();
    io::stdin().read_line(&mut wallet_name)?;
    let wallet_name = wallet_name.trim();

    // 2) Passord
    print!("Enter decryption password: ");
    io::stdout().flush()?;
    let password = SecretString::new(read_password().unwrap());

    // 3) Les fil
    let wallet_path = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("wallets")
        .join(wallet_name)
        .join("wallet.json.enc");

    if !wallet_path.exists() {
        eprintln!("❌ Wallet file not found: {:?}", wallet_path);
        return Ok(());
    }

    let data = fs::read(&wallet_path)?;
    if data.len() < 46 {
        eprintln!("❌ File too short or corrupted");
        return Ok(());
    }

    // 4) Parse header
    let magic = &data[0..4];
    if magic != MAGIC {
        eprintln!("❌ Wrong magic");
        return Ok(());
    }
    let version = data[4];
    if version != SUPPORTED_VERSION {
        eprintln!("❌ Unsupported version: {}", version);
        return Ok(());
    }
    let kdf_id = data[5];
    if kdf_id != KDF_ID_ARGON2ID {
        eprintln!("❌ Unsupported KDF id: {}", kdf_id);
        return Ok(());
    }
    let m_cost_kib = u32::from_le_bytes(data[6..10].try_into().unwrap());
    let t_cost = u32::from_le_bytes(data[10..14].try_into().unwrap());
    let p_cost = u32::from_le_bytes(data[14..18].try_into().unwrap());
    let salt: [u8; 16] = data[18..34].try_into().unwrap();
    let nonce_bytes: [u8; 12] = data[34..46].try_into().unwrap();
    let ciphertext = &data[46..];

    // 5) Deriver nøkkel (Argon2id + HKDF)
    let params = Params::new(m_cost_kib, t_cost, p_cost, None).expect("argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut mk = [0u8; 32];
    argon2
        .hash_password_into(password.expose_secret().as_bytes(), &salt, &mut mk)
        .expect("Argon2id failed");

    let hk = Hkdf::<Sha256>::new(Some(&salt), &mk);
    let mut aes_key_bytes = [0u8; 32];
    hk.expand(b"wallet-file-encryption v1", &mut aes_key_bytes)
        .expect("HKDF expand failed");
    mk.zeroize();

    let key = Key::<Aes256Gcm>::from_slice(&aes_key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let header_aad = &data[0..34];
    let payload = Payload {
        msg: ciphertext,
        aad: header_aad,
    };

    let decrypted = match cipher.decrypt(nonce, payload) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("❌ Decryption failed: wrong password or corrupted file");
            aes_key_bytes.zeroize();
            return Ok(());
        }
    };
    aes_key_bytes.zeroize();

    // 6) Deserialize og vis *kun offentlige* fingerprints
    let wallet: WalletFile = match serde_json::from_slice(&decrypted) {
        Ok(w) => w,
        Err(_) => {
            eprintln!("❌ Corrupted plaintext after decryption");
            return Ok(());
        }
    };

    println!("\n✅ Wallet loaded successfully!\n");

    let fp = |label: &str, bytes: &[u8]| {
        let mut h = Sha256::new();
        h.update(bytes);
        let digest = h.finalize();
        println!(
            "{label:18} fp: {:02x}{:02x}{:02x}{:02x}…",
            digest[0], digest[1], digest[2], digest[3]
        );
    };

    // Kun PUBLIC keys – aldri private nøkler til stdout (OPSEC).
    fp("Kyber Public", &wallet.kyber_public);
    fp("NTRU Public", &wallet.ntru_public);
    fp("Dilithium Public", &wallet.dilithium_public);

    Ok(())
}
