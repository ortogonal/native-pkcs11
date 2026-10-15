// Copyright 2022 Google LLC
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

use std::{ffi::CString, fmt::Debug, sync::Arc};

use der::{
    Decode as DerDecode, Encode,
    asn1::{Any, BitString, OctetString},
};
use native_pkcs11_traits::{
    Certificate, CertificateExt, KeyAlgorithm, PrivateKey, PublicKey, backend,
};
use pkcs1::{RsaPublicKey, der::Decode};
use pkcs11_sys::{
    CK_CERTIFICATE_CATEGORY_UNSPECIFIED, CK_PROFILE_ID, CKC_X_509, CKK_EC, CKK_RSA,
    CKO_CERTIFICATE, CKO_PRIVATE_KEY, CKO_PROFILE, CKO_PUBLIC_KEY,
};
use tracing::debug;

use crate::attribute::{Attribute, AttributeType, Attributes};

const ID_EC_PUBLIC_KEY: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const P256_OID: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

fn validated_sec1_point(public_key: &dyn PublicKey) -> Option<Vec<u8>> {
    if public_key.algorithm() != KeyAlgorithm::Ecc {
        return None;
    }
    let point = public_key.to_der();
    if point.len() < 3 || point[0] != 0x04 || !(point.len() - 1).is_multiple_of(2) {
        return None;
    }
    Some(point)
}

fn validated_p256_point(public_key: &dyn PublicKey) -> Option<Vec<u8>> {
    let params = public_key.ec_params()?;
    if pkcs8::ObjectIdentifier::from_der(&params).ok()? != P256_OID {
        return None;
    }
    let point = validated_sec1_point(public_key)?;
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).ok()?;
    Some(key.to_encoded_point(false).as_bytes().to_vec())
}

fn p256_subject_public_key_info(public_key: &dyn PublicKey) -> Option<Vec<u8>> {
    let point = validated_p256_point(public_key)?;
    let parameters = Any::from_der(&P256_OID.to_der().ok()?).ok()?;
    let algorithm =
        spki::AlgorithmIdentifierOwned { oid: ID_EC_PUBLIC_KEY, parameters: Some(parameters) };
    let subject_public_key = BitString::from_bytes(&point).ok()?;
    spki::SubjectPublicKeyInfoOwned { algorithm, subject_public_key }.to_der().ok()
}

fn rsa_public_key_attributes(public_key: &dyn PublicKey) -> Option<(Vec<u8>, Vec<u8>)> {
    if public_key.algorithm() != KeyAlgorithm::Rsa {
        return None;
    }
    let der = public_key.to_der();
    let key = RsaPublicKey::from_der(&der).ok()?;
    Some((key.modulus.as_bytes().to_vec(), key.public_exponent.as_bytes().to_vec()))
}

#[derive(Debug)]
pub struct DataObject {
    pub application: CString,
    pub label: String,
    pub value: Vec<u8>,
}

// Usage of generics is a workaround for the following issue:
// https://github.com/rust-lang/rust/issues/78808#issuecomment-1664416547
#[derive(Debug, PartialEq, Hash, Eq)]
pub enum Object<
    DynCertificate: ?Sized + PartialEq = dyn Certificate,
    DynPrivateKey: ?Sized + PartialEq = dyn PrivateKey,
    DynPublicKey: ?Sized + PartialEq = dyn PublicKey,
> {
    Certificate(Arc<DynCertificate>),
    PrivateKey(Arc<DynPrivateKey>),
    Profile(CK_PROFILE_ID),
    PublicKey(Arc<DynPublicKey>),
}

impl Clone for Object {
    fn clone(&self) -> Self {
        match self {
            Object::Certificate(cert) => Object::Certificate(cert.clone()),
            Object::PrivateKey(private_key) => Object::PrivateKey(private_key.clone()),
            Object::Profile(id) => Object::Profile(*id),
            Object::PublicKey(public_key) => Object::PublicKey(public_key.clone()),
        }
    }
}

impl Object {
    pub fn attribute(&self, type_: AttributeType) -> Option<Attribute> {
        match self {
            Object::Certificate(cert) => match type_ {
                AttributeType::CertificateCategory => {
                    Some(Attribute::CertificateCategory(CK_CERTIFICATE_CATEGORY_UNSPECIFIED))
                }
                AttributeType::CertificateType => Some(Attribute::CertificateType(CKC_X_509)),
                AttributeType::Class => Some(Attribute::Class(CKO_CERTIFICATE)),
                AttributeType::Id => Some(Attribute::Id(cert.id())),
                AttributeType::Issuer => Some(Attribute::Issuer(cert.issuer())),
                AttributeType::Label => Some(Attribute::Label(cert.label())),
                AttributeType::Token => Some(Attribute::Token(true)),
                AttributeType::Trusted => Some(Attribute::Trusted(false)),
                AttributeType::SerialNumber => Some(Attribute::SerialNumber(cert.serial_number())),
                AttributeType::Subject => Some(Attribute::Subject(cert.subject())),
                AttributeType::Value => Some(Attribute::Value(cert.to_der())),
                _ => {
                    debug!("certificate: type_ unimplemented: {:?}", type_);
                    None
                }
            },
            Object::PrivateKey(private_key) => match type_ {
                AttributeType::AlwaysSensitive => Some(Attribute::AlwaysSensitive(true)),
                AttributeType::AlwaysAuthenticate => Some(Attribute::AlwaysAuthenticate(false)),
                AttributeType::Class => Some(Attribute::Class(CKO_PRIVATE_KEY)),
                AttributeType::Decrypt => Some(Attribute::Decrypt(false)),
                AttributeType::Derive => Some(Attribute::Derive(false)),
                AttributeType::EcParams => private_key
                    .find_public_key(backend())
                    .ok()
                    .flatten()
                    .and_then(|public_key| public_key.ec_params())
                    .map(Attribute::EcParams),
                AttributeType::Extractable => Some(Attribute::Extractable(false)),
                AttributeType::Id => Some(Attribute::Id(private_key.id())),
                AttributeType::KeyType => Some(Attribute::KeyType(match private_key.algorithm() {
                    native_pkcs11_traits::KeyAlgorithm::Rsa => CKK_RSA,
                    native_pkcs11_traits::KeyAlgorithm::Ecc => CKK_EC,
                })),
                AttributeType::Label => Some(Attribute::Label(private_key.label())),
                AttributeType::Local => Some(Attribute::Local(false)),
                AttributeType::Modulus => {
                    let modulus = private_key.find_public_key(backend()).ok().flatten().and_then(
                        |public_key| {
                            rsa_public_key_attributes(public_key.as_ref())
                                .map(|(modulus, _)| modulus)
                        },
                    );
                    modulus.map(Attribute::Modulus)
                }
                AttributeType::NeverExtractable => Some(Attribute::NeverExtractable(true)),
                AttributeType::Private => Some(Attribute::Private(true)),
                AttributeType::PublicExponent => {
                    let public_exponent =
                        private_key.find_public_key(backend()).ok().flatten().and_then(
                            |public_key| {
                                rsa_public_key_attributes(public_key.as_ref())
                                    .map(|(_, public_exponent)| public_exponent)
                            },
                        );
                    public_exponent.map(Attribute::PublicExponent)
                }
                AttributeType::PublicKeyInfo => private_key
                    .find_public_key(backend())
                    .ok()
                    .flatten()
                    .and_then(|public_key| p256_subject_public_key_info(public_key.as_ref()))
                    .map(Attribute::PublicKeyInfo),
                AttributeType::Sensitive => Some(Attribute::Sensitive(true)),
                AttributeType::Sign => Some(Attribute::Sign(true)),
                AttributeType::SignRecover => Some(Attribute::SignRecover(false)),
                AttributeType::Token => Some(Attribute::Token(true)),
                AttributeType::Unwrap => Some(Attribute::Unwrap(false)),
                _ => {
                    debug!("private_key: type_ unimplemented: {:?}", type_);
                    None
                }
            },
            Object::Profile(id) => match type_ {
                AttributeType::Class => Some(Attribute::Class(CKO_PROFILE)),
                AttributeType::ProfileId => Some(Attribute::ProfileId(*id)),
                AttributeType::Token => Some(Attribute::Token(true)),
                _ => {
                    debug!("profile: type_ unimplemented: {:?}", type_);
                    None
                }
            },
            Object::PublicKey(pk) => match type_ {
                AttributeType::Class => Some(Attribute::Class(CKO_PUBLIC_KEY)),
                AttributeType::Derive => Some(Attribute::Derive(false)),
                AttributeType::Label => Some(Attribute::Label(pk.label())),
                AttributeType::Local => Some(Attribute::Local(false)),
                AttributeType::Modulus => {
                    let (modulus, _) = rsa_public_key_attributes(pk.as_ref())?;
                    Some(Attribute::Modulus(modulus))
                }
                AttributeType::PublicExponent => {
                    let (_, public_exponent) = rsa_public_key_attributes(pk.as_ref())?;
                    Some(Attribute::PublicExponent(public_exponent))
                }
                AttributeType::KeyType => Some(Attribute::KeyType(match pk.algorithm() {
                    native_pkcs11_traits::KeyAlgorithm::Rsa => CKK_RSA,
                    native_pkcs11_traits::KeyAlgorithm::Ecc => CKK_EC,
                })),
                AttributeType::Id => Some(Attribute::Id(pk.id())),
                AttributeType::EcPoint => {
                    let point = validated_sec1_point(pk.as_ref())?;
                    let wrapped = OctetString::new(point).ok()?;
                    Some(Attribute::EcPoint(wrapped.to_der().ok()?))
                }
                AttributeType::EcParams => pk.ec_params().map(Attribute::EcParams),
                AttributeType::PublicKeyInfo => {
                    p256_subject_public_key_info(pk.as_ref()).map(Attribute::PublicKeyInfo)
                }
                _ => {
                    debug!("public_key: type_ unimplemented: {:?}", type_);
                    None
                }
            },
        }
    }

    pub fn matches(&self, others: &Attributes) -> bool {
        if let Some(class) = others.get(AttributeType::Class)
            && *class != self.attribute(AttributeType::Class).unwrap()
        {
            return false;
        }
        for other in others {
            if let Some(attr) = self.attribute(other.attribute_type()) {
                if *other != attr {
                    return false;
                }
            } else {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use native_pkcs11_traits::{KeyAlgorithm, SignatureAlgorithm};
    use p256::ecdsa::SigningKey;

    #[derive(Debug, PartialEq)]
    struct TestPublicKey {
        point: Vec<u8>,
        params: Option<Vec<u8>>,
    }

    impl PublicKey for TestPublicKey {
        fn id(&self) -> Vec<u8> {
            self.point.clone()
        }

        fn label(&self) -> String {
            "test-public-key".to_owned()
        }

        fn ec_params(&self) -> Option<Vec<u8>> {
            self.params.clone()
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
            Ok(())
        }

        fn delete(self: Box<Self>) {}

        fn algorithm(&self) -> KeyAlgorithm {
            KeyAlgorithm::Ecc
        }
    }

    fn generated_p256_key() -> (Vec<u8>, Vec<u8>) {
        let signing_key = SigningKey::from_bytes((&[0x42; 32]).into()).unwrap();
        (
            signing_key.verifying_key().to_encoded_point(false).as_bytes().to_vec(),
            P256_OID.to_der().unwrap(),
        )
    }

    fn object(key: TestPublicKey) -> Object {
        Object::PublicKey(Arc::new(key) as Arc<dyn PublicKey>)
    }

    #[test]
    fn ec_point_and_public_key_info_are_distinct_and_round_trip() {
        let (point, params) = generated_p256_key();
        let object = object(TestPublicKey { point: point.clone(), params: Some(params.clone()) });

        let ec_point = match object.attribute(AttributeType::EcPoint).unwrap() {
            Attribute::EcPoint(value) => OctetString::from_der(&value).unwrap(),
            other => panic!("unexpected attribute: {other:?}"),
        };
        assert_eq!(ec_point.as_bytes(), point.as_slice());

        let public_key_info = match object.attribute(AttributeType::PublicKeyInfo).unwrap() {
            Attribute::PublicKeyInfo(value) => value,
            other => panic!("unexpected attribute: {other:?}"),
        };
        let spki = spki::SubjectPublicKeyInfoOwned::from_der(&public_key_info).unwrap();
        assert_eq!(spki.algorithm.oid, ID_EC_PUBLIC_KEY);
        assert_eq!(spki.algorithm.parameters.as_ref().unwrap().to_der().unwrap(), params);
        assert_eq!(spki.subject_public_key.as_bytes().unwrap(), point.as_slice());
        assert_eq!(spki.to_der().unwrap(), public_key_info);
    }

    #[test]
    fn rejects_invalid_points_and_missing_curve_metadata() {
        let (point, params) = generated_p256_key();
        for invalid_point in [vec![], vec![0x00], vec![0x02; 33], vec![0x04; 64]] {
            let invalid =
                object(TestPublicKey { point: invalid_point, params: Some(params.clone()) });
            assert!(invalid.attribute(AttributeType::EcPoint).is_none());
            assert!(invalid.attribute(AttributeType::PublicKeyInfo).is_none());
        }

        let missing_params = object(TestPublicKey { point: point.clone(), params: None });
        assert!(missing_params.attribute(AttributeType::EcPoint).is_some());
        assert!(missing_params.attribute(AttributeType::EcParams).is_none());
        assert!(missing_params.attribute(AttributeType::PublicKeyInfo).is_none());
    }

    #[test]
    fn rejects_unsupported_curve_metadata_instead_of_assuming_p256() {
        let (point, _) = generated_p256_key();
        let p384 = pkcs8::ObjectIdentifier::new_unwrap("1.3.132.0.34").to_der().unwrap();
        let object = object(TestPublicKey { point, params: Some(p384) });

        assert!(object.attribute(AttributeType::EcPoint).is_some());
        assert!(object.attribute(AttributeType::EcParams).is_some());
        assert!(object.attribute(AttributeType::PublicKeyInfo).is_none());
    }

    #[test]
    fn preserves_generic_ec_point_without_inventing_curve_metadata() {
        let (point, _) = generated_p256_key();
        let object = object(TestPublicKey { point: point.clone(), params: None });

        let value = match object.attribute(AttributeType::EcPoint).unwrap() {
            Attribute::EcPoint(value) => value,
            other => panic!("unexpected attribute: {other:?}"),
        };
        assert_eq!(OctetString::from_der(&value).unwrap().as_bytes(), point.as_slice());
        assert!(object.attribute(AttributeType::EcParams).is_none());
        assert!(object.attribute(AttributeType::PublicKeyInfo).is_none());
    }

    #[test]
    fn rejects_non_ec_keys_even_when_bytes_look_like_a_point() {
        let (point, params) = generated_p256_key();
        let key = TestPublicKey { point, params: Some(params) };
        let object = Object::PublicKey(Arc::new(RsaTestPublicKey(key)) as Arc<dyn PublicKey>);
        assert!(object.attribute(AttributeType::EcPoint).is_none());
        assert!(object.attribute(AttributeType::EcParams).is_none());
        assert!(object.attribute(AttributeType::PublicKeyInfo).is_none());
    }

    fn rsa_public_key_der() -> Vec<u8> {
        // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
        vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x03]
    }

    fn rsa_object(der: Vec<u8>) -> Object {
        let key = RsaTestPublicKey(TestPublicKey { point: der, params: None });
        Object::PublicKey(Arc::new(key) as Arc<dyn PublicKey>)
    }

    #[test]
    fn reports_rsa_modulus_and_public_exponent() {
        let object = rsa_object(rsa_public_key_der());

        assert_eq!(object.attribute(AttributeType::Modulus), Some(Attribute::Modulus(vec![1])));
        assert_eq!(
            object.attribute(AttributeType::PublicExponent),
            Some(Attribute::PublicExponent(vec![3]))
        );
    }

    #[test]
    fn rsa_attributes_are_unavailable_for_ec_keys() {
        let (point, params) = generated_p256_key();
        let object = object(TestPublicKey { point, params: Some(params) });

        assert!(object.attribute(AttributeType::Modulus).is_none());
        assert!(object.attribute(AttributeType::PublicExponent).is_none());
    }

    #[test]
    fn malformed_rsa_attributes_do_not_panic() {
        let object = rsa_object(vec![0x04, 0x01, 0x02]);

        assert!(object.attribute(AttributeType::Modulus).is_none());
        assert!(object.attribute(AttributeType::PublicExponent).is_none());
    }

    #[test]
    fn ec_discovery_survives_rsa_attribute_queries() {
        let (point, params) = generated_p256_key();
        let object = object(TestPublicKey { point, params: Some(params) });

        assert!(object.attribute(AttributeType::Modulus).is_none());
        assert!(object.attribute(AttributeType::PublicExponent).is_none());
        assert!(object.attribute(AttributeType::EcPoint).is_some());
        assert!(object.attribute(AttributeType::EcParams).is_some());
        assert!(object.attribute(AttributeType::PublicKeyInfo).is_some());
    }

    #[derive(Debug, PartialEq)]
    struct RsaTestPublicKey(TestPublicKey);

    impl PublicKey for RsaTestPublicKey {
        fn id(&self) -> Vec<u8> {
            self.0.id()
        }
        fn label(&self) -> String {
            self.0.label()
        }
        fn to_der(&self) -> Vec<u8> {
            self.0.to_der()
        }
        fn verify(
            &self,
            algorithm: &SignatureAlgorithm,
            data: &[u8],
            signature: &[u8],
        ) -> native_pkcs11_traits::Result<()> {
            self.0.verify(algorithm, data, signature)
        }
        fn delete(self: Box<Self>) {}
        fn algorithm(&self) -> KeyAlgorithm {
            KeyAlgorithm::Rsa
        }
    }
}
