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

use native_pkcs11_traits::{DigestType, SignatureAlgorithm};
use pkcs11_sys::*;

use crate::Error;

pub const SUPPORTED_SIGNATURE_MECHANISMS: &[CK_MECHANISM_TYPE] = &[
    CKM_RSA_PKCS,
    CKM_SHA1_RSA_PKCS,
    CKM_SHA256_RSA_PKCS,
    CKM_SHA384_RSA_PKCS,
    CKM_SHA512_RSA_PKCS,
    CKM_ECDSA,
    CKM_RSA_PKCS_PSS,
];

pub fn mechanism_flags(mechanism: CK_MECHANISM_TYPE) -> Option<CK_FLAGS> {
    SUPPORTED_SIGNATURE_MECHANISMS.contains(&mechanism).then_some(if mechanism == CKM_ECDSA {
        CKF_SIGN | CKF_VERIFY
    } else {
        CKF_SIGN
    })
}

pub enum Mechanism {
    Ecdsa,
    RsaPkcs,
    RsaPkcsSha1,
    RsaPkcsSha256,
    RsaPkcsSha384,
    RsaPkcsSha512,
    RsaPss {
        digest_algorithm: native_pkcs11_traits::DigestType,
        mask_generation_function: native_pkcs11_traits::DigestType,
        salt_length: u64,
    },
}

impl Mechanism {
    pub fn supports_verify(&self) -> bool {
        matches!(self, Self::Ecdsa)
    }
}

#[allow(clippy::missing_safety_doc)]
pub unsafe fn parse_mechanism(mechanism: CK_MECHANISM) -> Result<Mechanism, Error> {
    match mechanism.mechanism {
        CKM_ECDSA => {
            if !mechanism.pParameter.is_null() || mechanism.ulParameterLen != 0 {
                return Err(Error::MechanismParamInvalid(CKM_ECDSA));
            }
            Ok(Mechanism::Ecdsa)
        }
        CKM_RSA_PKCS => Ok(Mechanism::RsaPkcs),
        CKM_SHA1_RSA_PKCS => Ok(Mechanism::RsaPkcsSha1),
        CKM_SHA256_RSA_PKCS => Ok(Mechanism::RsaPkcsSha256),
        CKM_SHA384_RSA_PKCS => Ok(Mechanism::RsaPkcsSha384),
        CKM_SHA512_RSA_PKCS => Ok(Mechanism::RsaPkcsSha512),
        CKM_RSA_PKCS_PSS => {
            //  Bind to locals to prevent unaligned reads https://github.com/rust-lang/rust/issues/82523
            let mechanism_type = mechanism.mechanism;
            let parameter_ptr = mechanism.pParameter;
            let parameter_len = mechanism.ulParameterLen;
            if parameter_ptr.is_null() {
                tracing::error!("pParameter null");
                return Err(Error::MechanismParamInvalid(mechanism_type));
            }
            if (parameter_len as usize) != std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() {
                tracing::error!(
                    "pParameter incorrect: {} != {}",
                    parameter_len,
                    std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>()
                );
                return Err(Error::MechanismParamInvalid(mechanism_type));
            }
            //  TODO(kcking): check alignment as well?
            let params: CK_RSA_PKCS_PSS_PARAMS =
                unsafe { (parameter_ptr as *const CK_RSA_PKCS_PSS_PARAMS).read_unaligned() };
            let mgf = params.mgf;
            let hash_alg = params.hashAlg;
            let salt_len = params.sLen;

            let mgf = match mgf {
                CKG_MGF1_SHA1 => DigestType::Sha1,
                CKG_MGF1_SHA224 => DigestType::Sha224,
                CKG_MGF1_SHA256 => DigestType::Sha256,
                CKG_MGF1_SHA384 => DigestType::Sha384,
                CKG_MGF1_SHA512 => DigestType::Sha512,
                _ => {
                    tracing::error!("Unsupported mgf: {}", mgf);
                    return Err(Error::MechanismParamInvalid(mechanism_type));
                }
            };

            let hash_alg = match hash_alg {
                CKM_SHA_1 => DigestType::Sha1,
                CKM_SHA224 => DigestType::Sha224,
                CKM_SHA256 => DigestType::Sha256,
                CKM_SHA384 => DigestType::Sha384,
                CKM_SHA512 => DigestType::Sha512,
                _ => {
                    tracing::error!("Unsupported hashAlg: {}", hash_alg);
                    return Err(Error::MechanismParamInvalid(mechanism_type));
                }
            };

            #[allow(clippy::unnecessary_cast)]
            Ok(Mechanism::RsaPss {
                digest_algorithm: hash_alg,
                mask_generation_function: mgf,
                //  Cast needed on windows
                salt_length: salt_len as u64,
            })
        }
        _ => Err(Error::MechanismInvalid(mechanism.mechanism)),
    }
}

impl From<Mechanism> for CK_MECHANISM_TYPE {
    fn from(mechanism: Mechanism) -> Self {
        match mechanism {
            Mechanism::Ecdsa => CKM_ECDSA,
            Mechanism::RsaPkcs => CKM_RSA_PKCS,
            Mechanism::RsaPkcsSha1 => CKM_SHA1_RSA_PKCS,
            Mechanism::RsaPkcsSha256 => CKM_SHA256_RSA_PKCS,
            Mechanism::RsaPkcsSha384 => CKM_SHA384_RSA_PKCS,
            Mechanism::RsaPkcsSha512 => CKM_SHA512_RSA_PKCS,
            Mechanism::RsaPss { .. } => CKM_RSA_PKCS_PSS,
        }
    }
}

impl From<Mechanism> for SignatureAlgorithm {
    fn from(mechanism: Mechanism) -> Self {
        match mechanism {
            Mechanism::Ecdsa => SignatureAlgorithm::Ecdsa,
            Mechanism::RsaPkcs => SignatureAlgorithm::RsaPkcs1v15Raw,
            Mechanism::RsaPkcsSha1 => SignatureAlgorithm::RsaPkcs1v15Sha1,
            Mechanism::RsaPkcsSha256 => SignatureAlgorithm::RsaPkcs1v15Sha256,
            Mechanism::RsaPkcsSha384 => SignatureAlgorithm::RsaPkcs1v15Sha384,
            Mechanism::RsaPkcsSha512 => SignatureAlgorithm::RsaPkcs1v15Sha512,
            Mechanism::RsaPss { digest_algorithm, mask_generation_function, salt_length } => {
                SignatureAlgorithm::RsaPss {
                    digest: digest_algorithm,
                    mask_generation_function,
                    salt_length,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_raw_ecdsa_and_rejects_combined_sha256() {
        let raw = CK_MECHANISM {
            mechanism: CKM_ECDSA,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        assert!(matches!(unsafe { parse_mechanism(raw) }, Ok(Mechanism::Ecdsa)));

        let combined = CK_MECHANISM {
            mechanism: CKM_ECDSA_SHA256,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        assert!(unsafe { parse_mechanism(combined) }.is_err());
    }

    #[test]
    fn rejects_parameters_for_raw_ecdsa() {
        let parameter = 0u8;
        for mechanism in [
            CK_MECHANISM {
                mechanism: CKM_ECDSA,
                pParameter: &parameter as *const _ as *mut _,
                ulParameterLen: 0,
            },
            CK_MECHANISM {
                mechanism: CKM_ECDSA,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 1,
            },
        ] {
            assert!(matches!(
                unsafe { parse_mechanism(mechanism) },
                Err(Error::MechanismParamInvalid(CKM_ECDSA))
            ));
        }
    }

    #[test]
    fn advertises_verification_only_for_raw_ecdsa() {
        assert_eq!(mechanism_flags(CKM_ECDSA), Some(CKF_SIGN | CKF_VERIFY));
        assert_eq!(mechanism_flags(CKM_RSA_PKCS), Some(CKF_SIGN));
        assert_eq!(mechanism_flags(CKM_ECDSA_SHA256), None);
        assert!(Mechanism::Ecdsa.supports_verify());
        assert!(!Mechanism::RsaPkcs.supports_verify());
    }
}
