use opbnb_quantum::crypto::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Serialize, Deserialize)]
struct KeyFile {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

fn save_keys(name: &str, keys: &KeyFile) {
    let dir = Path::new("keys");
    if !dir.exists() {
        fs::create_dir_all(dir).expect("Failed to create keys directory");
    }
    let path = dir.join(format!("{}.json", name));
    let json = serde_json::to_string_pretty(keys).expect("Failed to serialize keys");
    fs::write(&path, json).expect("Failed to write key file");
    println!("Saved {} keys to {:?}", name, path);
}

fn main() {
    println!("=== Generating Kyber1024 keys ===");
    let kyber = kyber1024_keypair();
    save_keys(
        "kyber1024",
        &KeyFile {
            public_key: kyber.public_key.clone(),
            secret_key: kyber.secret_key.clone(),
        },
    );

    println!("=== Generating NTRU keys ===");
    let ntru = ntru_keypair();
    save_keys(
        "ntru",
        &KeyFile {
            public_key: ntru.public_key.clone(),
            secret_key: ntru.secret_key.clone(),
        },
    );

    println!("=== Generating Dilithium5 keys ===");
    let dil = dilithium5_keypair();
    save_keys(
        "dilithium5",
        &KeyFile {
            public_key: dil.public_key.clone(),
            secret_key: dil.secret_key.clone(),
        },
    );

    println!("✅ All keys generated and saved in the 'keys/' directory.");
}
