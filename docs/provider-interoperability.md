# OpenSSL provider interoperability

This document describes the EC interoperability path exercised with OpenSSL's
[`pkcs11-provider`](https://github.com/latchset/pkcs11-provider). It documents a
targeted compatibility path, not a claim of full PKCS#11 or OpenSSL
compatibility.

## Why this path is needed

An OpenSSL provider can use a PKCS#11 module for private-key operations while
OpenSSL performs TLS protocol processing. In the tested configuration, the
provider loads a private-key reference, obtains the corresponding public-key
attributes from the module, and calls the module for ECDSA signing. During peer
certificate verification it may also import the peer's public key into a
temporary PKCS#11 object and use that object for signature verification.

The compatibility work addresses four related boundary failures observed while
bringing up this path:

1. Without `CKA_PUBLIC_KEY_INFO`, an EC public key could not be discovered by
   provider versions that request the DER SubjectPublicKeyInfo representation.
   `CKA_PUBLIC_KEY_INFO` is distinct from `CKA_EC_POINT`, which contains the
   DER-wrapped SEC1 point.
2. A write-protected token prevented the provider from obtaining the session it
   needed to materialize temporary public-key data. The provider needs a
   writable session for this operation even though the resulting object is not
   persistent.
3. Without `C_CreateObject`, an imported public key had no usable PKCS#11
   handle. A handle-less provider object cannot be passed to
   `C_VerifyInit`.
4. Without `C_VerifyInit` and `C_Verify`, the provider could not complete the
   PKCS#11 public-key verification path after it had obtained a valid temporary
   object handle.

The handle-less imported-key failure is described by
[pkcs11-provider issue #769](https://github.com/openssl-projects/pkcs11-provider/issues/769).
In the original failure, the provider reported `CKR_KEY_HANDLE_INVALID` before
`C_VerifyInit` or `C_Verify` was reached. The complete interoperability path
therefore requires both provider-side temporary-object materialization and the
module-side object and verification operations described below.

## How the operations fit together

The tested flow is:

1. `pkcs11-provider` opens a read/write serial session.
2. It discovers the EC key using attributes including `CKA_EC_PARAMS`,
   `CKA_EC_POINT`, and, where requested, `CKA_PUBLIC_KEY_INFO`.
3. For peer verification, it calls `C_CreateObject` with the peer's validated
   P-256 public point. The module creates a non-persistent public-key session
   object and returns a handle.
4. The provider calls `C_VerifyInit` with `CKM_ECDSA` and that handle.
5. It calls `C_Verify` with the precomputed digest and the raw ECDSA signature
   (`r || s`). The module verifies using the validated P-256 public key.
6. The provider calls `C_DestroyObject`, or the session closes and the module
   removes the temporary object automatically.

Private-key signing is separate from this imported-public-key flow. The
provider selects a private key by PKCS#11 URI and calls `C_SignInit` followed by
`C_Sign`. For `CKM_ECDSA`, the signing input is an already-computed digest; the
module does not hash it again. In the tested TLS configuration the provider
first probes `CKM_ECDSA_SHA256`, receives an unsupported-mechanism result, and
falls back to raw `CKM_ECDSA`.

## Supported interoperability scope

The EC path covered here supports:

- P-256 (`secp256r1`) public keys only;
- validated uncompressed SEC1 public points;
- DER `CKA_EC_POINT` and DER `CKA_PUBLIC_KEY_INFO` representations;
- non-persistent public-key session objects created with `C_CreateObject`;
- raw `CKM_ECDSA` signing and verification;
- precomputed digests for `CKM_ECDSA`; and
- raw, fixed-width P-256 ECDSA signatures (`r || s`).

`CKM_ECDSA_SHA256` is not implemented. It is not interchangeable with
`CKM_ECDSA`: it accepts a message and hashes it, whereas this implementation
expects the digest to have been computed by the caller. This restriction avoids
double hashing in the provider's signing and verification paths.

The module is not a general-purpose PKCS#11 token. Private-key import remains
unsupported, persistent object creation remains unsupported, and arbitrary EC
curves are not supported by this interoperability path. Public session objects
are temporary and non-persistent; they are not restored after module restart or
session closure.

## Session-object lifetime

Session public-key objects are visible to live sessions in the same in-process
PKCS#11 application, as required for the provider's multi-session operation.
Ownership controls cleanup rather than lookup visibility. Explicit
`C_DestroyObject` removes the object immediately. Closing the creating session
also removes its session objects, and a verification operation that retains the
old handle then fails instead of continuing to use a destroyed PKCS#11 object.

This lifetime is intentional: imported public keys provide temporary material
for one provider operation and must not become persistent token objects.

## Tested configuration and test boundaries

The external compatibility spike used:

- Mosquitto 2.1.2;
- Alpine Linux 3.23.3;
- OpenSSL 3.5.x;
- Google `native-pkcs11` 0.2.27 as the starting point;
- `pkcs11-provider`; and
- P-256 ECDSA credentials.

For the clean run, the provider source was pinned to upstream commit
`e5ff476f1d1d5efef035c6e3127107a3b9f41f85`. The provider was rebuilt for the
Alpine/OpenSSL environment, without diagnostic provider-source instrumentation.
The clean external run passed TLS 1.2 and TLS 1.3 provider-backed MQTT
connections, including authenticated publish/subscribe round trips. It
observed `C_VerifyInit`, `C_Verify`, and temporary-object cleanup. The provider
also exercised the expected unsupported `CKM_ECDSA_SHA256` probe before using
raw `CKM_ECDSA`.

These external Mosquitto/OpenSSL tests are spike validation, not tests included
in this repository's native-pkcs11 CI. The repository's tests cover the
PKCS#11 boundary with deterministic keys, including EC metadata, template
validation, session-object lifetime, mechanism and permission errors, raw
ECDSA verification, and malformed inputs. The external test requires its own
Alpine image, OpenSSL, provider build, Mosquitto instance, and generated test
credentials.

The results demonstrate interoperability for the versions and P-256 scenario
listed above. They do not establish automatic compatibility with every
`pkcs11-provider` or OpenSSL version, every TLS application, or production
readiness.
