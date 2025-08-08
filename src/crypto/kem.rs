use pqcrypto_kyber::kyber1024;
use pqcrypto_ntru::ntruhps4096821;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};

pub struct KemKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

pub struct KemCipher {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

pub fn generate_kyber_keys() -> KemKeyPair {
    let (pk, sk) = kyber1024::keypair();
    KemKeyPair {
        public_key: pk.as_bytes().to_vec(),
        secret_key: sk.as_bytes().to_vec(),
    }
}

pub fn kyber_encapsulate(pk: &[u8]) -> KemCipher {
    let public_key = kyber1024::PublicKey::from_bytes(pk).expect("Invalid Kyber public key bytes");
    let (ss, ct) = kyber1024::encapsulate(&public_key);
    KemCipher {
        ciphertext: ct.as_bytes().to_vec(),
        shared_secret: ss.as_bytes().to_vec(),
    }
}

pub fn kyber_decapsulate(ct: &[u8], sk: &[u8]) -> Vec<u8> {
    let ciphertext = kyber1024::Ciphertext::from_bytes(ct).expect("Invalid Kyber ciphertext bytes");
    let secret_key = kyber1024::SecretKey::from_bytes(sk).expect("Invalid Kyber secret key bytes");
    let ss = kyber1024::decapsulate(&ciphertext, &secret_key);
    ss.as_bytes().to_vec()
}

pub fn generate_ntru_keys() -> KemKeyPair {
    let (pk, sk) = ntruhps4096821::keypair();
    KemKeyPair {
        public_key: pk.as_bytes().to_vec(),
        secret_key: sk.as_bytes().to_vec(),
    }
}

pub fn ntru_encapsulate(pk: &[u8]) -> KemCipher {
    let public_key =
        ntruhps4096821::PublicKey::from_bytes(pk).expect("Invalid NTRU public key bytes");
    let (ss, ct) = ntruhps4096821::encapsulate(&public_key);
    KemCipher {
        ciphertext: ct.as_bytes().to_vec(),
        shared_secret: ss.as_bytes().to_vec(),
    }
}

pub fn ntru_decapsulate(ct: &[u8], sk: &[u8]) -> Vec<u8> {
    let ciphertext =
        ntruhps4096821::Ciphertext::from_bytes(ct).expect("Invalid NTRU ciphertext bytes");
    let secret_key =
        ntruhps4096821::SecretKey::from_bytes(sk).expect("Invalid NTRU secret key bytes");
    let ss = ntruhps4096821::decapsulate(&ciphertext, &secret_key);
    ss.as_bytes().to_vec()
}
