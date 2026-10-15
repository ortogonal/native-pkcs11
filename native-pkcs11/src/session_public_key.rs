// Copyright 2026 Erik Larsson <karl.erik.larsson@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use native_pkcs11_traits::{KeyAlgorithm, PublicKey, SignatureAlgorithm};
use p256::ecdsa::VerifyingKey;

const P256_EC_PARAMS_DER: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

#[derive(Debug)]
pub struct SessionPublicKey {
    point: Vec<u8>,
    #[allow(dead_code)]
    key: VerifyingKey,
    id: Vec<u8>,
    label: String,
}

impl SessionPublicKey {
    #[allow(dead_code)]
    pub fn from_sec1(point: Vec<u8>) -> Option<Self> {
        let key = VerifyingKey::from_sec1_bytes(&point).ok()?;
        // Accept either SEC1 form, but expose one canonical PKCS#11 value.
        let point = key.to_encoded_point(false).as_bytes().to_vec();
        Some(Self { id: point.clone(), label: "temporary-p256-public-key".to_owned(), point, key })
    }

    pub fn new(point: Vec<u8>, id: Vec<u8>, label: String) -> Option<Self> {
        let key = VerifyingKey::from_sec1_bytes(&point).ok()?;
        // CKA_EC_POINT and verification use the same validated P-256 key.
        let point = key.to_encoded_point(false).as_bytes().to_vec();
        Some(Self { point, key, id, label })
    }
}

impl PublicKey for SessionPublicKey {
    fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::Ecc
    }

    fn id(&self) -> Vec<u8> {
        self.id.clone()
    }

    fn label(&self) -> String {
        self.label.clone()
    }

    fn ec_params(&self) -> Option<Vec<u8>> {
        Some(P256_EC_PARAMS_DER.to_vec())
    }

    fn to_der(&self) -> Vec<u8> {
        self.point.clone()
    }

    fn verify(
        &self,
        _algorithm: &SignatureAlgorithm,
        _data: &[u8],
        _signature: &[u8],
    ) -> native_pkcs11_traits::Result<()> {
        Err("temporary public-key verification is not implemented".into())
    }

    fn delete(self: Box<Self>) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;

    fn key() -> (SessionPublicKey, SigningKey) {
        let signing_key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let point = signing_key.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        (SessionPublicKey::from_sec1(point).unwrap(), signing_key)
    }

    #[test]
    fn normalizes_valid_sec1_points_to_uncompressed_p256() {
        let (valid, _) = key();
        assert!(SessionPublicKey::from_sec1(valid.point.clone()).is_some());
        let signing_key = SigningKey::from_bytes((&[11u8; 32]).into()).unwrap();
        let compressed = signing_key.verifying_key().to_encoded_point(true).as_bytes().to_vec();
        let normalized = SessionPublicKey::from_sec1(compressed).unwrap();
        assert_eq!(normalized.point.len(), 65);
        assert_eq!(normalized.point[0], 0x04);
        assert_eq!(
            normalized.point,
            signing_key.verifying_key().to_encoded_point(false).as_bytes()
        );
    }

    #[test]
    fn rejects_invalid_sec1_points() {
        assert!(SessionPublicKey::from_sec1(vec![0x04; 65]).is_none());
        assert!(SessionPublicKey::from_sec1(vec![0x02; 32]).is_none());
        assert!(SessionPublicKey::from_sec1(vec![0x04; 64]).is_none());
        assert!(SessionPublicKey::from_sec1(vec![0x04; 66]).is_none());
    }

    #[test]
    fn verification_uses_the_normalized_public_key() {
        let signing_key = SigningKey::from_bytes((&[13u8; 32]).into()).unwrap();
        let compressed = signing_key.verifying_key().to_encoded_point(true).as_bytes().to_vec();
        let public_key = SessionPublicKey::from_sec1(compressed).unwrap();
        let digest = [0xA5; 32];
        let signature: p256::ecdsa::Signature = signing_key.sign_prehash(&digest).unwrap();

        assert!(
            public_key.verify(&SignatureAlgorithm::Ecdsa, &digest, &signature.to_bytes()).is_ok()
        );
        assert_eq!(
            public_key.to_der(),
            signing_key.verifying_key().to_encoded_point(false).as_bytes()
        );
    }

    #[test]
    fn verifies_a_prehashed_ecdsa_signature() {
        let (public_key, signing_key) = key();
        let digest = [0xA5; 32];
        let signature: p256::ecdsa::Signature = signing_key.sign_prehash(&digest).unwrap();
        let signature_bytes = signature.to_bytes();

        assert!(public_key.verify(&SignatureAlgorithm::Ecdsa, &digest, &signature_bytes).is_ok());
    }

    #[test]
    fn rejects_invalid_signature_data_and_mechanisms() {
        let (public_key, signing_key) = key();
        let digest = [0xA5; 32];
        let signature: p256::ecdsa::Signature = signing_key.sign_prehash(&digest).unwrap();
        let signature_bytes = signature.to_bytes();
        let mut invalid_digest = digest;
        invalid_digest[0] ^= 1;

        assert!(
            public_key
                .verify(&SignatureAlgorithm::Ecdsa, &invalid_digest, &signature_bytes)
                .is_err()
        );
        assert!(public_key.verify(&SignatureAlgorithm::Ecdsa, &digest, &[0; 63]).is_err());
        assert!(public_key.verify(&SignatureAlgorithm::RsaRaw, &digest, &signature_bytes).is_err());
    }
}
