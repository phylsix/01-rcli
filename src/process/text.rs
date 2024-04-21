use crate::{process_genpass, CryptoAlgorithm, TextSignFormat};
use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chacha20poly1305::{
    self,
    aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use std::{collections::HashMap, io::Read};

pub trait TextSigner {
    // signer could sign any input data
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>>;
}

pub trait TextVerifier {
    // verifier could verify any input data
    fn verify(&self, reader: &mut dyn Read, sig: &[u8]) -> Result<bool>;
}

pub struct Blake3 {
    key: [u8; 32],
}

pub struct Ed25519Signer {
    key: SigningKey,
}

pub struct Ed25519Verifier {
    key: VerifyingKey,
}

impl TextSigner for Blake3 {
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let ret = blake3::keyed_hash(&self.key, &buf);
        Ok(ret.as_bytes().to_vec())
    }
}

impl TextVerifier for Blake3 {
    fn verify(&self, reader: &mut dyn Read, sig: &[u8]) -> Result<bool> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let ret = blake3::keyed_hash(&self.key, &buf);
        Ok(ret.as_bytes() == sig)
    }
}

impl TextSigner for Ed25519Signer {
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let signature = self.key.sign(&buf);
        Ok(signature.to_bytes().to_vec())
    }
}

impl TextVerifier for Ed25519Verifier {
    fn verify(&self, reader: &mut dyn Read, sig: &[u8]) -> Result<bool> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let sig = (&sig[..64]).try_into()?;
        let signature = Signature::from_bytes(sig);
        Ok(self.key.verify(&buf, &signature).is_ok())
    }
}

impl Blake3 {
    pub fn try_new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        // convert &[u8] to &[u8; 32]
        let key = (&key[..32]).try_into()?;
        Ok(Self::new(key))
    }

    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    fn generate() -> Result<HashMap<&'static str, Vec<u8>>> {
        let key = process_genpass(32, true, true, true, true)?;
        let mut map = HashMap::new();
        map.insert("blake3.txt", key.as_bytes().to_vec());
        Ok(map)
    }
}

impl Ed25519Signer {
    pub fn try_new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        let key = (&key[..32]).try_into()?;
        Ok(Self::new(key))
    }

    pub fn new(key: &[u8; 32]) -> Self {
        let key = SigningKey::from_bytes(key);
        Self { key }
    }

    fn generate() -> Result<HashMap<&'static str, Vec<u8>>> {
        let mut csprng = OsRng;
        let sk: SigningKey = SigningKey::generate(&mut csprng);
        let pk: VerifyingKey = (&sk).into();
        let mut map = HashMap::new();
        map.insert("ed25519.sk", sk.to_bytes().to_vec());
        map.insert("ed25519.pk", pk.to_bytes().to_vec());

        Ok(map)
    }
}

impl Ed25519Verifier {
    pub fn try_new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        let key = (&key[..32]).try_into()?;
        let key = VerifyingKey::from_bytes(key)?;
        Ok(Self { key })
    }
}

pub fn process_text_sign(
    reader: &mut dyn Read,
    key: &[u8], // (ptr, length)
    format: TextSignFormat,
) -> Result<Vec<u8>> {
    let signer: Box<dyn TextSigner> = match format {
        TextSignFormat::Blake3 => Box::new(Blake3::try_new(key)?),
        TextSignFormat::Ed25519 => Box::new(Ed25519Signer::try_new(key)?),
    };

    signer.sign(reader)
}

pub fn process_text_verify(
    reader: &mut dyn Read,
    key: &[u8],
    sig: &[u8],
    format: TextSignFormat,
) -> Result<bool> {
    let verifier: Box<dyn TextVerifier> = match format {
        TextSignFormat::Blake3 => Box::new(Blake3::try_new(key)?),
        TextSignFormat::Ed25519 => Box::new(Ed25519Verifier::try_new(key)?),
    };
    verifier.verify(reader, sig)
}

pub fn process_text_key_generate(format: TextSignFormat) -> Result<HashMap<&'static str, Vec<u8>>> {
    match format {
        TextSignFormat::Blake3 => Blake3::generate(),
        TextSignFormat::Ed25519 => Ed25519Signer::generate(),
    }
}

pub trait Cryptor {
    fn encrypt(&self, reader: &mut dyn Read) -> Result<String>;
    fn decrypt(&self, reader: &mut dyn Read) -> Result<String>;
}

pub struct Chacha20Poly1305 {
    key: [u8; 32],
}

impl Cryptor for Chacha20Poly1305 {
    fn encrypt(&self, reader: &mut dyn Read) -> Result<String> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;

        let cipher = chacha20poly1305::ChaCha20Poly1305::new(&self.key.into());

        let nonce =
            chacha20poly1305::ChaCha20Poly1305::generate_nonce(&mut chacha20poly1305::aead::OsRng);
        let encoded_nonce = URL_SAFE_NO_PAD.encode(nonce);

        let encrypted = cipher
            .encrypt(&nonce, buf.as_ref())
            .map_err(|_| anyhow::anyhow!("Failed to encrypt"))?;
        let encoded_msg = URL_SAFE_NO_PAD.encode(encrypted);

        Ok(format!("{}\n{}", encoded_nonce, encoded_msg))
    }

    fn decrypt(&self, reader: &mut dyn Read) -> Result<String> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;

        let nonce_and_msg = String::from_utf8_lossy(&buf);
        let nonce_and_msg: Vec<&str> = nonce_and_msg.split('\n').take(2).collect();
        let nonce = URL_SAFE_NO_PAD.decode(nonce_and_msg[0])?;
        let decoded_msg = URL_SAFE_NO_PAD.decode(nonce_and_msg[1])?;

        let cipher = chacha20poly1305::ChaCha20Poly1305::new(&self.key.into());

        let decrypted = cipher
            .decrypt(GenericArray::from_slice(&nonce), decoded_msg.as_ref())
            .map_err(|e| anyhow::anyhow!(format!("Failed to decrypt: {}", e)))?;

        Ok(format!("{}", String::from_utf8_lossy(&decrypted)))
    }
}

impl Chacha20Poly1305 {
    pub fn try_new(key: &[u8]) -> Result<Self> {
        let key = (&key[..32]).try_into()?;
        Ok(Self::new(key))
    }

    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }
}

pub fn process_text_encrypt(
    reader: &mut dyn Read,
    key: &[u8],
    algo: CryptoAlgorithm,
) -> Result<String> {
    let cryptor = match algo {
        CryptoAlgorithm::Chacha20Poly1305 => Box::new(Chacha20Poly1305::try_new(key)?),
    };
    cryptor.encrypt(reader)
}

pub fn process_text_decrypt(
    reader: &mut dyn Read,
    key: &[u8],
    algo: CryptoAlgorithm,
) -> Result<String> {
    let cryptor = match algo {
        CryptoAlgorithm::Chacha20Poly1305 => Box::new(Chacha20Poly1305::try_new(key)?),
    };
    cryptor.decrypt(reader)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    const KEY: &[u8] = include_bytes!("../../fixtures/blake3.txt");

    #[test]
    fn test_process_text_sign() -> Result<()> {
        let mut reader = "hello".as_bytes();
        let mut reader1 = "hello".as_bytes();
        let format = TextSignFormat::Blake3;
        let sig = process_text_sign(&mut reader, KEY, format)?;
        let ret = process_text_verify(&mut reader1, KEY, &sig, format)?;
        assert!(ret);
        Ok(())
    }

    #[test]
    fn test_process_text_verify() -> Result<()> {
        let mut reader = "hello".as_bytes();
        let format = TextSignFormat::Blake3;
        let sig = "33Ypo4rveYpWmJKAiGnnse-wHQhMVujjmcVkV4Tl43k";
        let sig = URL_SAFE_NO_PAD.decode(sig)?;
        let ret = process_text_verify(&mut reader, KEY, &sig, format)?;
        assert!(ret);
        Ok(())
    }

    #[test]
    fn test_process_text_encrypt() -> Result<()> {
        let mut reader = "hello".as_bytes();
        let algo = CryptoAlgorithm::Chacha20Poly1305;
        let encrypted = process_text_encrypt(&mut reader, KEY, algo);
        assert!(encrypted.is_ok());
        Ok(())
    }

    #[test]
    fn test_process_text_decrypt() -> Result<()> {
        let mut reader = "hello".as_bytes();
        let algo = CryptoAlgorithm::Chacha20Poly1305;
        let encrypted = process_text_encrypt(&mut reader, KEY, algo)?;
        let decrypted = process_text_decrypt(&mut encrypted.as_bytes(), KEY, algo)?;
        assert_eq!(decrypted, "hello");
        Ok(())
    }
}
