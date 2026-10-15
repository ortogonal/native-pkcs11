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

#![allow(non_snake_case)]
#![allow(clippy::missing_safety_doc)]
#![deny(unsafe_op_in_unsafe_fn)]

pub use native_pkcs11_core::Error;
use native_pkcs11_traits::{SignatureAlgorithm, backend};
use tracing::metadata::LevelFilter;
use tracing_error::ErrorLayer;
use tracing_subscriber::{EnvFilter, Registry, fmt::format::FmtSpan, prelude::*};
mod object_store;
mod session_public_key;
mod sessions;
mod utils;

use std::{
    cmp,
    collections::HashSet,
    slice,
    sync::{
        Once,
        atomic::{AtomicBool, Ordering},
    },
};

use der::{Decode, asn1::OctetString};
use native_pkcs11_core::{
    attribute::{Attribute, AttributeType, Attributes},
    mechanism::{SUPPORTED_SIGNATURE_MECHANISMS, mechanism_flags, parse_mechanism},
    object::{self, Object},
};
use pkcs11_sys::*;

use crate::{
    session_public_key::SessionPublicKey,
    sessions::{FindContext, SignContext, VerifyContext},
    utils::right_pad_string_to_array,
};

const LIBRARY_DESCRIPTION: &[u8; 32] = b"                                ";
const MANUFACTURER_ID: &[u8; 32] = b"google                          ";
const SLOT_DESCRIPTION: &[u8; 64] =
    b"Platform Cryptography Support                                   ";
const SLOT_ID: CK_SLOT_ID = 1;
const TOKEN_MODEL: &[u8; 16] = b"software        ";
const TOKEN_SERIAL_NUMBER: &[u8; 16] = b"0000000000000000";
const P256_EC_PARAMS_DER: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

static INITIALIZED: AtomicBool = AtomicBool::new(false);

type Result = std::result::Result<(), Error>;

fn result_to_rv<F>(f: F) -> CK_RV
where
    F: FnOnce() -> Result,
{
    match f() {
        Ok(()) => CKR_OK,
        Err(e) => {
            match e {
                // Some PKCS #11 return values indicate routine conditions that
                // should not be logged at the default log level.
                Error::AttributeTypeInvalid(_) => tracing::debug!(%e),
                _ => tracing::error!(%e),
            }
            e.into()
        }
    }
}

macro_rules! cryptoki_fn {
    (fn $name:ident ( $($arg:ident : $type:ty),* $(,)?) $body:block) => {
        #[tracing::instrument]
        #[unsafe(no_mangle)]
        pub extern "C" fn $name($($arg: $type),*) -> CK_RV {
            // TODO(bweeks): should this be `expr` instead of `block`?
            result_to_rv(|| $body)
        }
    };
    (unsafe fn $name:ident ( $($arg:ident : $type:ty),* $(,)?) $body:block) => {
        #[tracing::instrument]
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name($($arg: $type),*) -> CK_RV {
            // TODO(bweeks): should this be `expr` instead of `block`?
            result_to_rv(|| $body)
        }
    };
}

macro_rules! cryptoki_fn_not_supported {
    ($name:ident, $($arg:ident: $type:ty),*) => {
        cryptoki_fn!(fn $name($($arg: $type),*) {Err(Error::FunctionNotSupported)});
    };
}

macro_rules! not_null {
    ($ptr:expr) => {
        if $ptr.is_null() {
            return Err(Error::ArgumentsBad);
        }
    };
}

macro_rules! initialized {
    () => {
        if INITIALIZED.load(Ordering::SeqCst) == false {
            return Err(Error::CryptokiNotInitialized);
        }
    };
}

macro_rules! valid_session {
    ($handle:expr) => {
        if !sessions::exists($handle) {
            return Err(Error::SessionHandleInvalid($handle));
        }
    };
}

macro_rules! valid_slot {
    ($id:expr) => {
        if $id != SLOT_ID {
            return Err(Error::SlotIdInvalid($id));
        }
    };
}

//  Export necessary items for registering a custom Backend.
pub use pkcs11_sys::{CK_FUNCTION_LIST, CK_FUNCTION_LIST_PTR_PTR, CK_RV, CKR_OK};
pub static mut FUNC_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    // In this structure ‘version’ is the cryptoki specification version number. The major and minor
    // versions must be set to 0x02 and 0x28 indicating a version 2.40 compatible structure.
    version: CK_VERSION { major: 2, minor: 4 },
    C_Initialize: Some(C_Initialize),
    C_Finalize: Some(C_Finalize),
    C_GetInfo: Some(C_GetInfo),
    C_GetFunctionList: Some(C_GetFunctionList),
    C_GetSlotList: Some(C_GetSlotList),
    C_GetSlotInfo: Some(C_GetSlotInfo),
    C_GetTokenInfo: Some(C_GetTokenInfo),
    C_GetMechanismList: Some(C_GetMechanismList),
    C_GetMechanismInfo: Some(C_GetMechanismInfo),
    C_InitToken: Some(C_InitToken),
    C_InitPIN: Some(C_InitPIN),
    C_SetPIN: Some(C_SetPIN),
    C_OpenSession: Some(C_OpenSession),
    C_CloseSession: Some(C_CloseSession),
    C_CloseAllSessions: Some(C_CloseAllSessions),
    C_GetSessionInfo: Some(C_GetSessionInfo),
    C_GetOperationState: Some(C_GetOperationState),
    C_SetOperationState: Some(C_SetOperationState),
    C_Login: Some(C_Login),
    C_Logout: Some(C_Logout),
    C_CreateObject: Some(C_CreateObject),
    C_CopyObject: Some(C_CopyObject),
    C_DestroyObject: Some(C_DestroyObject),
    C_GetObjectSize: Some(C_GetObjectSize),
    C_GetAttributeValue: Some(C_GetAttributeValue),
    C_SetAttributeValue: Some(C_SetAttributeValue),
    C_FindObjectsInit: Some(C_FindObjectsInit),
    C_FindObjects: Some(C_FindObjects),
    C_FindObjectsFinal: Some(C_FindObjectsFinal),
    C_EncryptInit: Some(C_EncryptInit),
    C_Encrypt: Some(C_Encrypt),
    C_EncryptUpdate: Some(C_EncryptUpdate),
    C_EncryptFinal: Some(C_EncryptFinal),
    C_DecryptInit: Some(C_DecryptInit),
    C_Decrypt: Some(C_Decrypt),
    C_DecryptUpdate: Some(C_DecryptUpdate),
    C_DecryptFinal: Some(C_DecryptFinal),
    C_DigestInit: Some(C_DigestInit),
    C_Digest: Some(C_Digest),
    C_DigestUpdate: Some(C_DigestUpdate),
    C_DigestKey: Some(C_DigestKey),
    C_DigestFinal: Some(C_DigestFinal),
    C_SignInit: Some(C_SignInit),
    C_Sign: Some(C_Sign),
    C_SignUpdate: Some(C_SignUpdate),
    C_SignFinal: Some(C_SignFinal),
    C_SignRecoverInit: Some(C_SignRecoverInit),
    C_SignRecover: Some(C_SignRecover),
    C_VerifyInit: Some(C_VerifyInit),
    C_Verify: Some(C_Verify),
    C_VerifyUpdate: Some(C_VerifyUpdate),
    C_VerifyFinal: Some(C_VerifyFinal),
    C_VerifyRecoverInit: Some(C_VerifyRecoverInit),
    C_VerifyRecover: Some(C_VerifyRecover),
    C_DigestEncryptUpdate: Some(C_DigestEncryptUpdate),
    C_DecryptDigestUpdate: Some(C_DecryptDigestUpdate),
    C_SignEncryptUpdate: Some(C_SignEncryptUpdate),
    C_DecryptVerifyUpdate: Some(C_DecryptVerifyUpdate),
    C_GenerateKey: Some(C_GenerateKey),
    C_GenerateKeyPair: Some(C_GenerateKeyPair),
    C_WrapKey: Some(C_WrapKey),
    C_UnwrapKey: Some(C_UnwrapKey),
    C_DeriveKey: Some(C_DeriveKey),
    C_SeedRandom: Some(C_SeedRandom),
    C_GenerateRandom: Some(C_GenerateRandom),
    C_GetFunctionStatus: Some(C_GetFunctionStatus),
    C_CancelFunction: Some(C_CancelFunction),
    C_WaitForSlotEvent: Some(C_WaitForSlotEvent),
};

static TRACING_INIT: Once = Once::new();

#[derive(Debug)]
struct SessionPublicKeyTemplate {
    id: Vec<u8>,
    label: String,
    point: Vec<u8>,
}

unsafe fn copy_template_attributes(
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
) -> std::result::Result<Vec<(CK_ATTRIBUTE_TYPE, Vec<u8>)>, Error> {
    let count: usize = ulCount.try_into()?;
    if count == 0 {
        return Ok(Vec::new());
    }
    if pTemplate.is_null() {
        return Err(Error::ArgumentsBad);
    }
    let attrs = unsafe { slice::from_raw_parts(pTemplate, count) };
    attrs
        .iter()
        .map(|attr| {
            let len: usize = attr.ulValueLen.try_into()?;
            if len > 0 && attr.pValue.is_null() {
                return Err(Error::ArgumentsBad);
            }
            let value = if len == 0 {
                Vec::new()
            } else {
                unsafe { slice::from_raw_parts(attr.pValue.cast::<u8>(), len) }.to_vec()
            };
            Ok((attr.type_, value))
        })
        .collect()
}

fn parse_ulong(value: &[u8], type_: AttributeType) -> std::result::Result<CK_ULONG, Error> {
    value.try_into().map(CK_ULONG::from_ne_bytes).map_err(|_| Error::AttributeValueInvalid(type_))
}

fn parse_bool(value: &[u8], type_: AttributeType) -> std::result::Result<bool, Error> {
    let value: [u8; std::mem::size_of::<CK_BBOOL>()] = match value.try_into() {
        Ok(value) => value,
        Err(_) => return Err(Error::AttributeValueInvalid(type_)),
    };
    match CK_BBOOL::from_ne_bytes(value) {
        CK_FALSE => Ok(false),
        CK_TRUE => Ok(true),
        _ => Err(Error::AttributeValueInvalid(type_)),
    }
}

fn parse_session_public_key_template(
    attrs: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
) -> std::result::Result<SessionPublicKeyTemplate, Error> {
    let mut seen = HashSet::new();
    let mut class = None;
    let mut key_type = None;
    let mut token = false;
    let mut private = false;
    let mut verify = true;
    let mut params = None;
    let mut point = None;
    let mut id = Vec::new();
    let mut label = String::new();

    for (type_, value) in attrs {
        if !seen.insert(*type_) {
            return Err(Error::TemplateInconsistent);
        }
        let attr_type = match (*type_).try_into() {
            Ok(type_) => type_,
            Err(_) => return Err(Error::AttributeTypeInvalid(*type_)),
        };
        match attr_type {
            AttributeType::Class => class = Some(parse_ulong(value, attr_type)?),
            AttributeType::KeyType => key_type = Some(parse_ulong(value, attr_type)?),
            AttributeType::Token => token = parse_bool(value, attr_type)?,
            AttributeType::Private => private = parse_bool(value, attr_type)?,
            AttributeType::Verify => verify = parse_bool(value, attr_type)?,
            AttributeType::Derive => {
                if parse_bool(value, attr_type)? {
                    return Err(Error::TemplateInconsistent);
                }
            }
            AttributeType::EcParams => {
                if value.as_slice() != P256_EC_PARAMS_DER {
                    return Err(Error::AttributeValueInvalid(attr_type));
                }
                params = Some(value.clone());
            }
            AttributeType::EcPoint => {
                let point_der = OctetString::from_der(value)
                    .map_err(|_| Error::AttributeValueInvalid(attr_type))?;
                point = Some(point_der.as_bytes().to_vec());
            }
            AttributeType::Id => id = value.clone(),
            AttributeType::Label => {
                label = String::from_utf8(value.clone())
                    .map_err(|_| Error::AttributeValueInvalid(attr_type))?;
            }
            _ => return Err(Error::AttributeTypeInvalid(*type_)),
        }
    }

    if token || private || !verify {
        return Err(Error::TemplateInconsistent);
    }
    if class.is_none() || key_type.is_none() || params.is_none() || point.is_none() {
        return Err(Error::TemplateIncomplete);
    }
    if class != Some(CKO_PUBLIC_KEY as CK_ULONG) {
        return Err(Error::AttributeValueInvalid(AttributeType::Class));
    }
    if key_type != Some(CKK_EC as CK_ULONG) {
        return Err(Error::AttributeValueInvalid(AttributeType::KeyType));
    }
    Ok(SessionPublicKeyTemplate { id, label, point: point.unwrap() })
}

cryptoki_fn!(
    fn C_Initialize(pInitArgs: CK_VOID_PTR) {
        TRACING_INIT.call_once(|| {
            let env_filter = EnvFilter::builder()
                .with_default_directive(LevelFilter::WARN.into())
                .from_env_lossy();
            let force_stderr = std::env::var("NATIVE_PKCS11_LOG_STDERR").is_ok();
            if !force_stderr && let Ok(journald_layer) = tracing_journald::layer() {
                _ = Registry::default()
                    .with(journald_layer.with_syslog_identifier("native-pkcs11".into()))
                    .with(env_filter)
                    .with(ErrorLayer::default())
                    .try_init();
                return;
            }
            _ = Registry::default()
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_writer(std::io::stderr)
                        .with_span_events(FmtSpan::ENTER),
                )
                .with(env_filter)
                .with(ErrorLayer::default())
                .try_init();
        });
        if !pInitArgs.is_null() {
            let args = unsafe { *(pInitArgs as CK_C_INITIALIZE_ARGS_PTR) };
            if !args.pReserved.is_null() {
                return Err(Error::ArgumentsBad);
            }
        }
        if INITIALIZED.swap(true, Ordering::SeqCst) {
            return Err(Error::CryptokiAlreadyInitialized);
        }
        Ok(())
    }
);

cryptoki_fn!(
    fn C_Finalize(pReserved: CK_VOID_PTR) {
        initialized!();
        if !pReserved.is_null() {
            return Err(Error::ArgumentsBad);
        }
        sessions::close_all();
        sessions::OBJECT_STORE.lock().unwrap().clear_session_objects();
        INITIALIZED.store(false, Ordering::SeqCst);
        Ok(())
    }
);

cryptoki_fn!(
    unsafe fn C_GetInfo(pInfo: CK_INFO_PTR) {
        initialized!();
        not_null!(pInfo);
        let info = CK_INFO {
            cryptokiVersion: CK_VERSION {
                major: CRYPTOKI_VERSION_MAJOR,
                minor: CRYPTOKI_VERSION_MINOR,
            },
            manufacturerID: *MANUFACTURER_ID,
            flags: 0,
            libraryDescription: *LIBRARY_DESCRIPTION,
            libraryVersion: CK_VERSION { major: 0, minor: 1 },
        };
        unsafe { *pInfo = info };
        Ok(())
    }
);

#[cfg(not(feature = "custom-function-list"))]
cryptoki_fn!(
    unsafe fn C_GetFunctionList(ppFunctionList: CK_FUNCTION_LIST_PTR_PTR) {
        not_null!(ppFunctionList);
        unsafe { *ppFunctionList = std::ptr::addr_of_mut!(FUNC_LIST) };

        #[cfg(target_os = "macos")]
        native_pkcs11_traits::register_backend(Box::new(
            native_pkcs11_keychain::KeychainBackend {},
        ));

        #[cfg(target_os = "windows")]
        native_pkcs11_traits::register_backend(Box::new(native_pkcs11_windows::WindowsBackend {}));

        Ok(())
    }
);

cryptoki_fn!(
    unsafe fn C_GetSlotList(
        _tokenPresent: CK_BBOOL,
        pSlotList: CK_SLOT_ID_PTR,
        pulCount: CK_ULONG_PTR,
    ) {
        initialized!();
        not_null!(pulCount);
        if !pSlotList.is_null() {
            if unsafe { *pulCount } < 1 {
                return Err(Error::BufferTooSmall);
            }
            // TODO: this should be an array.
            unsafe { *pSlotList = SLOT_ID };
        }
        unsafe { *pulCount = 1 };
        Ok(())
    }
);

cryptoki_fn!(
    unsafe fn C_GetSlotInfo(slotID: CK_SLOT_ID, pInfo: CK_SLOT_INFO_PTR) {
        initialized!();
        valid_slot!(slotID);
        not_null!(pInfo);
        let info = CK_SLOT_INFO {
            slotDescription: *SLOT_DESCRIPTION,
            manufacturerID: *MANUFACTURER_ID,
            flags: CKF_TOKEN_PRESENT,
            // TODO: populate all fields.
            ..Default::default()
        };
        unsafe { *pInfo = info };
        Ok(())
    }
);

cryptoki_fn!(
    unsafe fn C_GetTokenInfo(slotID: CK_SLOT_ID, pInfo: CK_TOKEN_INFO_PTR) {
        initialized!();
        valid_slot!(slotID);
        not_null!(pInfo);
        let label = right_pad_string_to_array(backend().name());

        let info = CK_TOKEN_INFO {
            label,
            manufacturerID: *MANUFACTURER_ID,
            model: *TOKEN_MODEL,
            serialNumber: *TOKEN_SERIAL_NUMBER,
            // Temporary public-key session objects are required by the
            // provider's peer-certificate verification path. Do not advertise
            // write protection; persistent and private-key object creation
            // remain rejected below.
            flags: CKF_TOKEN_INITIALIZED | CKF_PROTECTED_AUTHENTICATION_PATH,
            ulMaxSessionCount: CK_UNAVAILABLE_INFORMATION,
            ulSessionCount: CK_UNAVAILABLE_INFORMATION,
            ulMaxRwSessionCount: CK_UNAVAILABLE_INFORMATION,
            ulRwSessionCount: CK_UNAVAILABLE_INFORMATION,
            ulTotalPublicMemory: CK_UNAVAILABLE_INFORMATION,
            ulFreePublicMemory: CK_UNAVAILABLE_INFORMATION,
            ulTotalPrivateMemory: CK_UNAVAILABLE_INFORMATION,
            ulFreePrivateMemory: CK_UNAVAILABLE_INFORMATION,
            // TODO: populate all fields.
            ..Default::default()
        };
        unsafe { *pInfo = info };
        Ok(())
    }
);

cryptoki_fn!(
    unsafe fn C_GetMechanismList(
        slotID: CK_SLOT_ID,
        pMechanismList: CK_MECHANISM_TYPE_PTR,
        pulCount: CK_ULONG_PTR,
    ) {
        initialized!();
        not_null!(pulCount);
        valid_slot!(slotID);
        if !pMechanismList.is_null() {
            if (unsafe { *pulCount } as usize) < SUPPORTED_SIGNATURE_MECHANISMS.len() {
                unsafe { *pulCount = SUPPORTED_SIGNATURE_MECHANISMS.len() as CK_ULONG };
                return Err(Error::BufferTooSmall);
            }
            unsafe {
                slice::from_raw_parts_mut(pMechanismList, SUPPORTED_SIGNATURE_MECHANISMS.len())
            }
            .copy_from_slice(SUPPORTED_SIGNATURE_MECHANISMS);
        }
        unsafe { *pulCount = SUPPORTED_SIGNATURE_MECHANISMS.len() as CK_ULONG };
        Ok(())
    }
);

cryptoki_fn!(
    unsafe fn C_GetMechanismInfo(
        slotID: CK_SLOT_ID,
        mechType: CK_MECHANISM_TYPE,
        pInfo: CK_MECHANISM_INFO_PTR,
    ) {
        initialized!();
        valid_slot!(slotID);
        not_null!(pInfo);
        let flags = mechanism_flags(mechType).ok_or(Error::MechanismInvalid(mechType))?;
        let info = CK_MECHANISM_INFO { flags, ..Default::default() };
        unsafe { *pInfo = info };
        Ok(())
    }
);

cryptoki_fn!(
    fn C_InitToken(
        slotID: CK_SLOT_ID,
        _pPin: CK_UTF8CHAR_PTR,
        _ulPinLen: CK_ULONG,
        _pLabel: CK_UTF8CHAR_PTR,
    ) {
        initialized!();
        valid_slot!(slotID);
        Err(Error::TokenWriteProtected)
    }
);

cryptoki_fn!(
    fn C_InitPIN(hSession: CK_SESSION_HANDLE, _pPin: CK_UTF8CHAR_PTR, _ulPinLen: CK_ULONG) {
        initialized!();
        valid_session!(hSession);
        Err(Error::TokenWriteProtected)
    }
);

cryptoki_fn!(
    fn C_SetPIN(
        hSession: CK_SESSION_HANDLE,
        _pOldPin: CK_UTF8CHAR_PTR,
        _ulOldLen: CK_ULONG,
        _pNewPin: CK_UTF8CHAR_PTR,
        _ulNewLen: CK_ULONG,
    ) {
        initialized!();
        valid_session!(hSession);
        Err(Error::TokenWriteProtected)
    }
);

cryptoki_fn!(
    unsafe fn C_OpenSession(
        slotID: CK_SLOT_ID,
        flags: CK_FLAGS,
        _pApplication: CK_VOID_PTR,
        _Notify: CK_NOTIFY,
        phSession: CK_SESSION_HANDLE_PTR,
    ) {
        initialized!();
        valid_slot!(slotID);
        not_null!(phSession);
        if flags & CKF_SERIAL_SESSION == 0 {
            return Err(Error::SessionParallelNotSupported);
        }
        unsafe { *phSession = sessions::create(flags) };
        Ok(())
    }
);

cryptoki_fn!(
    fn C_CloseSession(hSession: CK_SESSION_HANDLE) {
        initialized!();
        if sessions::close(hSession) {
            sessions::OBJECT_STORE.lock().unwrap().destroy_session_objects(hSession);
            return Ok(());
        }
        Err(Error::SessionHandleInvalid(hSession))
    }
);

cryptoki_fn!(
    fn C_CloseAllSessions(slotID: CK_SLOT_ID) {
        initialized!();
        valid_slot!(slotID);
        sessions::close_all();
        sessions::OBJECT_STORE.lock().unwrap().clear_session_objects();
        Ok(())
    }
);

cryptoki_fn!(
    unsafe fn C_GetSessionInfo(hSession: CK_SESSION_HANDLE, pInfo: CK_SESSION_INFO_PTR) {
        initialized!();
        valid_session!(hSession);
        not_null!(pInfo);
        let flags = sessions::flags(hSession);
        let state =
            if flags & CKF_RW_SESSION == 0 { CKS_RO_USER_FUNCTIONS } else { CKS_RW_USER_FUNCTIONS };
        let info = CK_SESSION_INFO { slotID: SLOT_ID, state, flags, ulDeviceError: 0 };
        unsafe { *pInfo = info };
        Ok(())
    }
);

cryptoki_fn_not_supported!(
    C_GetOperationState,
    hSession: CK_SESSION_HANDLE,
    pOperationState: CK_BYTE_PTR,
    pulOperationStateLen: CK_ULONG_PTR
);

cryptoki_fn_not_supported!(
    C_SetOperationState,
    hSession: CK_SESSION_HANDLE,
    pOperationState: CK_BYTE_PTR,
    ulOperationStateLen: CK_ULONG,
    hEncryptionKey: CK_OBJECT_HANDLE,
    hAuthenticationKey: CK_OBJECT_HANDLE
);

cryptoki_fn!(
    fn C_Login(
        hSession: CK_SESSION_HANDLE,
        _userType: CK_USER_TYPE,
        _pPin: CK_UTF8CHAR_PTR,
        _ulPinLen: CK_ULONG,
    ) {
        initialized!();
        valid_session!(hSession);
        Ok(())
    }
);

cryptoki_fn!(
    fn C_Logout(hSession: CK_SESSION_HANDLE) {
        initialized!();
        valid_session!(hSession);
        Ok(())
    }
);

cryptoki_fn!(
    unsafe fn C_CreateObject(
        hSession: CK_SESSION_HANDLE,
        pTemplate: CK_ATTRIBUTE_PTR,
        ulCount: CK_ULONG,
        phObject: CK_OBJECT_HANDLE_PTR,
    ) {
        initialized!();
        valid_session!(hSession);
        not_null!(phObject);
        let attrs = unsafe { copy_template_attributes(pTemplate, ulCount)? };
        let template = parse_session_public_key_template(&attrs)?;
        let key = SessionPublicKey::new(template.point, template.id, template.label)
            .ok_or(Error::AttributeValueInvalid(AttributeType::EcPoint))?;
        let handle = sessions::OBJECT_STORE
            .lock()
            .unwrap()
            .insert_session_object(hSession, Object::SessionPublicKey(std::sync::Arc::new(key)))?;
        unsafe { *phObject = handle };
        tracing::info!(session = hSession, handle, "created temporary public key");
        Ok(())
    }
);

cryptoki_fn_not_supported!(
    C_CopyObject,
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
    phNewObject: CK_OBJECT_HANDLE_PTR
);

cryptoki_fn!(
    fn C_DestroyObject(hSession: CK_SESSION_HANDLE, hObject: CK_OBJECT_HANDLE) {
        initialized!();
        valid_session!(hSession);
        sessions::OBJECT_STORE.lock().unwrap().destroy_session_object(hSession, hObject)
    }
);

cryptoki_fn_not_supported!(
    C_GetObjectSize,
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pulSize: CK_ULONG_PTR
);

cryptoki_fn!(
    unsafe fn C_GetAttributeValue(
        hSession: CK_SESSION_HANDLE,
        hObject: CK_OBJECT_HANDLE,
        pTemplate: CK_ATTRIBUTE_PTR,
        ulCount: CK_ULONG,
    ) {
        initialized!();
        valid_session!(hSession);
        not_null!(pTemplate);
        sessions::session(hSession, |_session| -> Result {
            let object_store = sessions::OBJECT_STORE.lock().unwrap();
            let object = match object_store.get(&hObject) {
                Some(object) => object,
                None => {
                    return Err(Error::ObjectHandleInvalid(hObject));
                }
            };
            let template = if ulCount > 0 {
                if pTemplate.is_null() {
                    return Err(Error::ArgumentsBad);
                }
                unsafe { slice::from_raw_parts_mut(pTemplate, ulCount as usize) }
            } else {
                &mut []
            };
            let mut result = Ok(());
            for attribute in template.iter_mut() {
                let type_ = attribute
                    .type_
                    .try_into()
                    .map_err(|_| Error::AttributeTypeInvalid(attribute.type_))?;
                if let Some(value) = object.attribute(type_) {
                    let value = value.as_raw_value();
                    attribute.ulValueLen = value.len() as CK_ULONG;
                    if attribute.pValue.is_null() {
                        continue;
                    }
                    if (attribute.ulValueLen as usize) < value.len() {
                        result = Err(Error::BufferTooSmall);
                        continue;
                    }
                    unsafe { slice::from_raw_parts_mut(attribute.pValue as *mut u8, value.len()) }
                        .copy_from_slice(&value);
                } else {
                    attribute.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    result = Err(Error::AttributeTypeInvalid(attribute.type_));
                }
            }
            result
        })
    }
);

cryptoki_fn_not_supported!(
    C_SetAttributeValue,
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG
);

cryptoki_fn!(
    unsafe fn C_FindObjectsInit(
        hSession: CK_SESSION_HANDLE,
        pTemplate: CK_ATTRIBUTE_PTR,
        ulCount: CK_ULONG,
    ) {
        initialized!();
        valid_session!(hSession);
        let template_attrs: &[CK_ATTRIBUTE] = if ulCount == 0 {
            &[]
        } else {
            not_null!(pTemplate);
            let count: usize = ulCount.try_into()?;
            unsafe { slice::from_raw_parts(pTemplate, count) }
        };
        let template: Attributes = template_attrs
            .iter()
            .map(|attr| (*attr).try_into())
            .collect::<native_pkcs11_core::Result<Vec<Attribute>>>()?
            .into();
        sessions::session(hSession, |session| -> Result {
            session.find_ctx = Some(FindContext {
                objects: sessions::OBJECT_STORE.lock().unwrap().find(template)?,
            });
            Ok(())
        })
    }
);

cryptoki_fn!(
    unsafe fn C_FindObjects(
        hSession: CK_SESSION_HANDLE,
        phObject: CK_OBJECT_HANDLE_PTR,
        ulMaxObjectCount: CK_ULONG,
        pulObjectCount: CK_ULONG_PTR,
    ) {
        initialized!();
        valid_session!(hSession);
        not_null!(phObject);
        not_null!(pulObjectCount);
        sessions::session(hSession, |session| -> Result {
            let find_ctx = match &mut session.find_ctx {
                Some(find_ctx) => find_ctx,
                None => {
                    unsafe { *pulObjectCount = 0 };
                    return Err(Error::OperationNotInitialized);
                }
            };
            if find_ctx.objects.is_empty() {
                unsafe { *pulObjectCount = 0 };
                return Ok(());
            }
            let max_objects = cmp::min(find_ctx.objects.len(), ulMaxObjectCount as usize);
            let output = unsafe { slice::from_raw_parts_mut(phObject, max_objects) };
            output.copy_from_slice(
                &find_ctx.objects.drain(0..max_objects).collect::<Vec<CK_OBJECT_HANDLE>>(),
            );
            unsafe { *pulObjectCount = max_objects as CK_ULONG };
            Ok(())
        })
    }
);

cryptoki_fn!(
    fn C_FindObjectsFinal(hSession: CK_SESSION_HANDLE) {
        initialized!();
        valid_session!(hSession);
        sessions::session(hSession, |session| -> Result {
            if session.find_ctx.is_none() {
                return Err(Error::OperationNotInitialized);
            }
            session.find_ctx = None;
            Ok(())
        })
    }
);

cryptoki_fn_not_supported!(
    C_EncryptInit,
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE
);

cryptoki_fn_not_supported!(
    C_Encrypt,
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pEncryptedData: CK_BYTE_PTR,
    pulEncryptedDataLen: CK_ULONG_PTR
);

cryptoki_fn_not_supported!(
    C_EncryptUpdate,
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
    pEncryptedPart: CK_BYTE_PTR,
    pulEncryptedPartLen: CK_ULONG_PTR
);

cryptoki_fn_not_supported!(
    C_EncryptFinal,
    hSession: CK_SESSION_HANDLE,
    pLastEncryptedPart: CK_BYTE_PTR,
    pulLastEncryptedPartLen: CK_ULONG_PTR
);

cryptoki_fn_not_supported!(
    C_DecryptInit,
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE
);

cryptoki_fn_not_supported!(
    C_Decrypt,
    hSession: CK_SESSION_HANDLE,
    pEncryptedData: CK_BYTE_PTR,
    ulEncryptedDataLen: CK_ULONG,
    pData: CK_BYTE_PTR,
    pulDataLen: CK_ULONG_PTR
);

cryptoki_fn_not_supported!(
    C_DecryptUpdate,
    hSession: CK_SESSION_HANDLE,
    pEncryptedPart: CK_BYTE_PTR,
    ulEncryptedPartLen: CK_ULONG,
    pPart: CK_BYTE_PTR,
    pulPartLen: CK_ULONG_PTR
);

cryptoki_fn_not_supported!(
    C_DecryptFinal,
    hSession: CK_SESSION_HANDLE,
    pLastPart: CK_BYTE_PTR,
    pulLastPartLen: CK_ULONG_PTR
);

cryptoki_fn_not_supported!(
    C_DigestInit,
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR
);

cryptoki_fn_not_supported!(
    C_Digest,
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pDigest: CK_BYTE_PTR,
    pulDigestLen: CK_ULONG_PTR
);

cryptoki_fn_not_supported!(
    C_DigestUpdate,
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG
);

cryptoki_fn_not_supported!(
    C_DigestKey,
    hSession: CK_SESSION_HANDLE,
    hKey: CK_OBJECT_HANDLE
);

cryptoki_fn_not_supported!(
    C_DigestFinal,
    hSession: CK_SESSION_HANDLE,
    pDigest: CK_BYTE_PTR,
    pulDigestLen: CK_ULONG_PTR
);

cryptoki_fn!(
    unsafe fn C_SignInit(
        hSession: CK_SESSION_HANDLE,
        pMechanism: CK_MECHANISM_PTR,
        hKey: CK_OBJECT_HANDLE,
    ) {
        initialized!();
        valid_session!(hSession);
        not_null!(pMechanism);
        sessions::session(hSession, |session| -> Result {
            let object_store = sessions::OBJECT_STORE.lock().unwrap();
            let private_key = match object_store.get(&hKey) {
                Some(Object::PrivateKey(private_key)) => private_key,
                Some(_) | None => return Err(Error::KeyHandleInvalid(hKey)),
            };
            let mechanism = unsafe { parse_mechanism(pMechanism.read()) }?;
            session.sign_ctx = Some(SignContext {
                algorithm: mechanism.into(),
                private_key: private_key.clone(),
                payload: None,
            });
            Ok(())
        })
    }
);

cryptoki_fn!(
    unsafe fn C_Sign(
        hSession: CK_SESSION_HANDLE,
        pData: CK_BYTE_PTR,
        ulDataLen: CK_ULONG,
        pSignature: CK_BYTE_PTR,
        pulSignatureLen: CK_ULONG_PTR,
    ) {
        initialized!();
        valid_session!(hSession);
        not_null!(pData);
        not_null!(pulSignatureLen);
        sessions::session(hSession, |session| -> Result {
            let data = unsafe { slice::from_raw_parts(pData, ulDataLen as usize) };
            unsafe { session.sign(Some(data), pSignature, pulSignatureLen) }?;
            Ok(())
        })
    }
);

cryptoki_fn!(
    unsafe fn C_SignUpdate(hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG) {
        initialized!();
        valid_session!(hSession);
        not_null!(pPart);
        sessions::session(hSession, |session| -> Result {
            let sign_ctx = match session.sign_ctx.as_mut() {
                None => return Err(Error::OperationNotInitialized),
                Some(sign_ctx) => sign_ctx,
            };
            sign_ctx
                .payload
                .get_or_insert(vec![])
                .extend_from_slice(unsafe { slice::from_raw_parts(pPart, ulPartLen as usize) });
            Ok(())
        })
    }
);

cryptoki_fn!(
    unsafe fn C_SignFinal(
        hSession: CK_SESSION_HANDLE,
        pSignature: CK_BYTE_PTR,
        pulSignatureLen: CK_ULONG_PTR,
    ) {
        initialized!();
        valid_session!(hSession);
        not_null!(pSignature);
        not_null!(pulSignatureLen);
        sessions::session(hSession, |session| -> Result {
            unsafe { session.sign(None, pSignature, pulSignatureLen) }?;
            Ok(())
        })
    }
);

cryptoki_fn_not_supported!(
    C_SignRecoverInit,
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE
);

cryptoki_fn_not_supported!(
    C_SignRecover,
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pSignature: CK_BYTE_PTR,
    pulSignatureLen: CK_ULONG_PTR
);

cryptoki_fn!(
    unsafe fn C_VerifyInit(
        hSession: CK_SESSION_HANDLE,
        pMechanism: CK_MECHANISM_PTR,
        hKey: CK_OBJECT_HANDLE,
    ) {
        initialized!();
        valid_session!(hSession);
        not_null!(pMechanism);
        sessions::session(hSession, |session| -> Result {
            if session.verify_ctx.is_some() {
                return Err(Error::OperationActive);
            }
            let mechanism = unsafe { parse_mechanism(pMechanism.read()) }?;
            if !mechanism.supports_verify() {
                return Err(Error::MechanismInvalid(mechanism.into()));
            }
            let object_store = sessions::OBJECT_STORE.lock().unwrap();
            let object = object_store
                .get_for_session(hSession, &hKey)
                .ok_or(Error::KeyHandleInvalid(hKey))?;
            let public_key = object.public_key().cloned().ok_or(Error::KeyHandleInvalid(hKey))?;
            let key_type =
                object.attribute(AttributeType::KeyType).ok_or(Error::KeyHandleInvalid(hKey))?;
            let key_type = match key_type {
                Attribute::KeyType(key_type) => key_type,
                _ => return Err(Error::KeyTypeInconsistent),
            };
            if key_type != CKK_EC {
                return Err(Error::KeyTypeInconsistent);
            }
            if object.attribute(AttributeType::EcParams)
                != Some(Attribute::EcParams(P256_EC_PARAMS_DER.to_vec()))
            {
                return Err(Error::KeyTypeInconsistent);
            }
            if object.attribute(AttributeType::Verify) != Some(Attribute::Verify(true)) {
                return Err(Error::KeyFunctionNotPermitted);
            }
            session.verify_ctx =
                Some(VerifyContext { algorithm: mechanism.into(), public_key, key_handle: hKey });
            Ok(())
        })
    }
);

cryptoki_fn!(
    unsafe fn C_Verify(
        hSession: CK_SESSION_HANDLE,
        pData: CK_BYTE_PTR,
        ulDataLen: CK_ULONG,
        pSignature: CK_BYTE_PTR,
        ulSignatureLen: CK_ULONG,
    ) {
        initialized!();
        valid_session!(hSession);
        if ulDataLen != 0 {
            not_null!(pData);
        }
        if ulSignatureLen != 0 {
            not_null!(pSignature);
        }
        sessions::session(hSession, |session| -> Result {
            let verify_ctx = session.verify_ctx.take().ok_or(Error::OperationNotInitialized)?;
            if sessions::OBJECT_STORE
                .lock()
                .unwrap()
                .get(&verify_ctx.key_handle)
                .and_then(Object::public_key)
                .is_none()
            {
                return Err(Error::KeyHandleInvalid(verify_ctx.key_handle));
            }
            let data = if ulDataLen == 0 {
                &[]
            } else {
                unsafe { slice::from_raw_parts(pData, ulDataLen as usize) }
            };
            let signature = if ulSignatureLen == 0 {
                &[]
            } else {
                unsafe { slice::from_raw_parts(pSignature, ulSignatureLen as usize) }
            };
            if matches!(verify_ctx.algorithm, SignatureAlgorithm::Ecdsa) {
                // RustCrypto's P-256 prehash adapter accepts digests of at least
                // half the field size and truncates longer inputs to 32 bytes.
                if data.len() < 16 {
                    return Err(Error::DataLenRange);
                }
                if signature.len() != 64 {
                    return Err(Error::SignatureLenRange);
                }
                p256::ecdsa::Signature::from_slice(signature)
                    .map_err(|_| Error::SignatureInvalid)?;
            }
            verify_ctx.public_key.verify(&verify_ctx.algorithm, data, signature).map_err(|error| {
                if matches!(verify_ctx.algorithm, SignatureAlgorithm::Ecdsa) {
                    Error::SignatureInvalid
                } else {
                    Error::Backend(error)
                }
            })
        })
    }
);

cryptoki_fn_not_supported!(
    C_VerifyUpdate,
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG
);

cryptoki_fn_not_supported!(
    C_VerifyFinal,
    hSession: CK_SESSION_HANDLE,
    pSignature: CK_BYTE_PTR,
    ulSignatureLen: CK_ULONG
);

cryptoki_fn_not_supported!(
    C_VerifyRecoverInit,
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE
);

cryptoki_fn_not_supported!(
    C_VerifyRecover,
    hSession: CK_SESSION_HANDLE,
    pSignature: CK_BYTE_PTR,
    ulSignatureLen: CK_ULONG,
    pData: CK_BYTE_PTR,
    pulDataLen: CK_ULONG_PTR
);

cryptoki_fn_not_supported!(
    C_DigestEncryptUpdate,
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
    pEncryptedPart: CK_BYTE_PTR,
    pulEncryptedPartLen: CK_ULONG_PTR
);

cryptoki_fn_not_supported!(
    C_DecryptDigestUpdate,
    hSession: CK_SESSION_HANDLE,
    pEncryptedPart: CK_BYTE_PTR,
    ulEncryptedPartLen: CK_ULONG,
    pPart: CK_BYTE_PTR,
    pulPartLen: CK_ULONG_PTR
);

cryptoki_fn_not_supported!(
    C_SignEncryptUpdate,
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
    pEncryptedPart: CK_BYTE_PTR,
    pulEncryptedPartLen: CK_ULONG_PTR
);

cryptoki_fn_not_supported!(
    C_DecryptVerifyUpdate,
    hSession: CK_SESSION_HANDLE,
    pEncryptedPart: CK_BYTE_PTR,
    ulEncryptedPartLen: CK_ULONG,
    pPart: CK_BYTE_PTR,
    pulPartLen: CK_ULONG_PTR
);

cryptoki_fn_not_supported!(
    C_GenerateKey,
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
    phKey: CK_OBJECT_HANDLE_PTR
);

cryptoki_fn_not_supported!(
    C_GenerateKeyPair,
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    pPublicKeyTemplate: CK_ATTRIBUTE_PTR,
    ulPublicKeyAttributeCount: CK_ULONG,
    pPrivateKeyTemplate: CK_ATTRIBUTE_PTR,
    ulPrivateKeyAttributeCount: CK_ULONG,
    phPublicKey: CK_OBJECT_HANDLE_PTR,
    phPrivateKey: CK_OBJECT_HANDLE_PTR
);

cryptoki_fn_not_supported!(
    C_WrapKey,
    hSession: CK_SESSION_HANDLE,
    _pMechanism: CK_MECHANISM_PTR,
    _hWrappingKey: CK_OBJECT_HANDLE,
    _hKey: CK_OBJECT_HANDLE,
    _pWrappedKey: CK_BYTE_PTR,
    _pulWrappedKeyLen: CK_ULONG_PTR
);

cryptoki_fn_not_supported!(
    C_UnwrapKey,
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hUnwrappingKey: CK_OBJECT_HANDLE,
    pWrappedKey: CK_BYTE_PTR,
    ulWrappedKeyLen: CK_ULONG,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulAttributeCount: CK_ULONG,
    phKey: CK_OBJECT_HANDLE_PTR
);

cryptoki_fn_not_supported!(
    C_DeriveKey,
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hBaseKey: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulAttributeCount: CK_ULONG,
    phKey: CK_OBJECT_HANDLE_PTR
);

cryptoki_fn!(
    fn C_SeedRandom(hSession: CK_SESSION_HANDLE, pSeed: CK_BYTE_PTR, _ulSeedLen: CK_ULONG) {
        initialized!();
        valid_session!(hSession);
        not_null!(pSeed);
        Err(Error::RandomNoRng)
    }
);

cryptoki_fn!(
    fn C_GenerateRandom(
        hSession: CK_SESSION_HANDLE,
        pRandomData: CK_BYTE_PTR,
        _ulRandomLen: CK_ULONG,
    ) {
        initialized!();
        valid_session!(hSession);
        not_null!(pRandomData);
        Err(Error::RandomNoRng)
    }
);

cryptoki_fn!(
    fn C_GetFunctionStatus(hSession: CK_SESSION_HANDLE) {
        initialized!();
        valid_session!(hSession);
        Err(Error::FunctionNotParallel)
    }
);

cryptoki_fn!(
    fn C_CancelFunction(hSession: CK_SESSION_HANDLE) {
        initialized!();
        valid_session!(hSession);
        Err(Error::FunctionNotParallel)
    }
);

cryptoki_fn_not_supported!(
    C_WaitForSlotEvent,
    flags: CK_FLAGS,
    pSlot: CK_SLOT_ID_PTR,
    pReserved: CK_VOID_PTR
);

#[cfg(test)]
pub mod tests {
    use std::ptr;

    use der::Encode;
    use serial_test::serial;

    use super::*;

    pub fn test_init() {
        if !INITIALIZED.load(std::sync::atomic::Ordering::SeqCst) {
            let mut func_list: &mut CK_FUNCTION_LIST =
                &mut CK_FUNCTION_LIST { ..Default::default() };
            unsafe { C_GetFunctionList((&mut func_list) as *mut _ as *mut _) };
        }
    }

    fn open_test_session() -> CK_SESSION_HANDLE {
        let mut session = CK_INVALID_HANDLE;
        assert_eq!(
            unsafe {
                C_OpenSession(
                    SLOT_ID,
                    CKF_SERIAL_SESSION | CKF_RW_SESSION,
                    ptr::null_mut(),
                    None,
                    &mut session,
                )
            },
            CKR_OK
        );
        session
    }

    fn raw_ecdsa_mechanism() -> CK_MECHANISM {
        CK_MECHANISM { mechanism: CKM_ECDSA, pParameter: ptr::null_mut(), ulParameterLen: 0 }
    }

    fn create_test_public_key(
        session: CK_SESSION_HANDLE,
        signing_key: &p256::ecdsa::SigningKey,
    ) -> CK_OBJECT_HANDLE {
        let point = signing_key.verifying_key().to_encoded_point(false);
        let point_der =
            der::asn1::OctetString::new(point.as_bytes().to_vec()).unwrap().to_der().unwrap();
        let mut class = CKO_PUBLIC_KEY as CK_ULONG;
        let mut key_type = CKK_EC as CK_ULONG;
        let mut params = P256_EC_PARAMS_DER.to_vec();
        let mut template = [
            CK_ATTRIBUTE {
                type_: CKA_CLASS,
                pValue: (&mut class as *mut CK_ULONG).cast(),
                ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_KEY_TYPE,
                pValue: (&mut key_type as *mut CK_ULONG).cast(),
                ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_EC_PARAMS,
                pValue: params.as_mut_ptr().cast(),
                ulValueLen: params.len() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_EC_POINT,
                pValue: point_der.as_ptr() as *mut _,
                ulValueLen: point_der.len() as CK_ULONG,
            },
        ];
        let mut handle = CK_INVALID_HANDLE;
        assert_eq!(
            unsafe {
                C_CreateObject(
                    session,
                    template.as_mut_ptr(),
                    template.len() as CK_ULONG,
                    &mut handle,
                )
            },
            CKR_OK
        );
        handle
    }

    #[test]
    #[serial]
    fn get_initialize() {
        test_init();
        assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
        assert_eq!(C_Initialize(ptr::null_mut()), CKR_CRYPTOKI_ALREADY_INITIALIZED);
        assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
        let mut args = CK_C_INITIALIZE_ARGS::default();
        assert_eq!(
            C_Initialize(&mut args as CK_C_INITIALIZE_ARGS_PTR as *mut std::ffi::c_void),
            CKR_OK
        );
        assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
        // Expect CKR_ARGUMENTS_BAD if pReserved is not null.
        args.pReserved = std::ptr::dangling_mut::<u32>() as *mut std::ffi::c_void;
        assert_eq!(
            C_Initialize(&mut args as CK_C_INITIALIZE_ARGS_PTR as *mut std::ffi::c_void),
            CKR_ARGUMENTS_BAD
        );
    }

    #[test]
    #[serial]
    fn finalize() {
        test_init();
        assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
        // Expect CKR_ARGUMENTS_BAD if pReserved is not null.
        assert_eq!(
            C_Finalize(std::ptr::dangling_mut::<u32>() as *mut std::ffi::c_void),
            CKR_ARGUMENTS_BAD
        );
        assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
        assert_eq!(C_Finalize(ptr::null_mut()), CKR_CRYPTOKI_NOT_INITIALIZED);
    }

    #[test]
    #[serial]
    fn get_info() {
        test_init();
        assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
        let mut info = CK_INFO::default();
        assert_eq!(unsafe { C_GetInfo(&mut info) }, CKR_OK);
        // Expect CKR_ARGUMENTS_BAD if pInfo is null.
        assert_eq!(unsafe { C_GetInfo(ptr::null_mut()) }, CKR_ARGUMENTS_BAD);
        // Expect CKR_CRYPTOKI_NOT_INITIALIZED if token is not initialized.
        assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
        assert_eq!(unsafe { C_GetInfo(&mut info) }, CKR_CRYPTOKI_NOT_INITIALIZED);
    }

    #[test]
    #[serial]
    fn get_function_list() {
        test_init();
        let mut function_list = CK_FUNCTION_LIST::default();
        let mut function_list_pointer: *mut CK_FUNCTION_LIST = &mut function_list;
        assert_eq!(unsafe { C_GetFunctionList(&mut function_list_pointer) }, CKR_OK);
        // Expect CKR_ARGUMENTS_BAD if ppFunctionList is null.
        assert_eq!(unsafe { C_GetFunctionList(ptr::null_mut()) }, CKR_ARGUMENTS_BAD);
    }

    #[test]
    #[serial]
    fn get_slot_list() {
        test_init();
        assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
        let mut count = 0;
        assert_eq!(unsafe { C_GetSlotList(CK_FALSE, std::ptr::null_mut(), &mut count) }, CKR_OK);
        assert_eq!(count, 1);
        // Expect CKR_ARGUMENTS_BAD if pulCount is null.
        assert_eq!(
            unsafe { C_GetSlotList(CK_FALSE, ptr::null_mut(), ptr::null_mut()) },
            CKR_ARGUMENTS_BAD
        );
        // Expect CKR_BUFFER_TOO_SMALL if pulCount is less than the number of
        // slots.
        let mut count = 0;
        let mut slot_list = vec![0; 0];
        assert_eq!(
            unsafe { C_GetSlotList(CK_FALSE, slot_list.as_mut_ptr(), &mut count) },
            CKR_BUFFER_TOO_SMALL
        );
        // Expect CKR_CRYPTOKI_NOT_INITIALIZED if token is not initialized.
        assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
        assert_eq!(
            unsafe { C_GetSlotList(CK_FALSE, std::ptr::null_mut(), &mut count) },
            CKR_CRYPTOKI_NOT_INITIALIZED
        )
    }

    #[test]
    #[serial]
    fn get_slot_info() {
        test_init();
        assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
        let mut slot_info = CK_SLOT_INFO::default();
        assert_eq!(unsafe { C_GetSlotInfo(SLOT_ID, &mut slot_info) }, CKR_OK);
        // Expect CKR_ARGUMENTS_BAD if pInfo is null.
        assert_eq!(unsafe { C_GetSlotInfo(SLOT_ID, ptr::null_mut()) }, CKR_ARGUMENTS_BAD);
        // Expect CKR_SLOT_ID_INVALID if slotID references a nonexistent slot.
        assert_eq!(unsafe { C_GetSlotInfo(SLOT_ID + 1, ptr::null_mut()) }, CKR_SLOT_ID_INVALID);
        // Expect CKR_CRYPTOKI_NOT_INITIALIZED if token is not initialized.
        assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
        assert_eq!(unsafe { C_GetSlotInfo(SLOT_ID, &mut slot_info) }, CKR_CRYPTOKI_NOT_INITIALIZED);
    }

    #[test]
    #[serial]
    fn get_token_info() {
        test_init();
        assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
        assert_eq!(unsafe { C_GetTokenInfo(SLOT_ID, &mut CK_TOKEN_INFO::default()) }, CKR_OK);
        // Expect CKR_SLOT_ID_INVALID if slotID references a nonexistent slot.
        assert_eq!(unsafe { C_GetTokenInfo(SLOT_ID + 1, ptr::null_mut()) }, CKR_SLOT_ID_INVALID);
        // Expect CKR_ARGUMENTS_BAD if pInfo is null.
        assert_eq!(unsafe { C_GetSlotInfo(SLOT_ID, ptr::null_mut()) }, CKR_ARGUMENTS_BAD);
        // Expect CKR_CRYPTOKI_NOT_INITIALIZED if token is not initialized.
        assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
        assert_eq!(
            unsafe { C_GetTokenInfo(SLOT_ID, &mut CK_TOKEN_INFO::default()) },
            CKR_CRYPTOKI_NOT_INITIALIZED
        );
    }

    #[test]
    #[serial]
    fn get_mechanism_list() {
        test_init();
        assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
        let mut count = 0;
        assert_eq!(unsafe { C_GetMechanismList(SLOT_ID, ptr::null_mut(), &mut count) }, CKR_OK);
        assert_ne!(count, 0);
        let mut mechanisms = Vec::<CK_MECHANISM_TYPE>::with_capacity(count as usize);
        assert_eq!(
            unsafe { C_GetMechanismList(SLOT_ID, mechanisms.as_mut_ptr(), &mut count) },
            CKR_OK
        );
        unsafe {
            mechanisms.set_len(count as usize);
        }
        assert_eq!(mechanisms, *SUPPORTED_SIGNATURE_MECHANISMS);
        // Expect CKR_SLOT_ID_INVALID if slotID references a nonexistent slot.
        assert_eq!(
            unsafe { C_GetMechanismList(SLOT_ID + 1, ptr::null_mut(), &mut count) },
            CKR_SLOT_ID_INVALID
        );
        // Expect CKR_ARGUMENTS_BAD if pulCount is null.
        assert_eq!(
            unsafe { C_GetMechanismList(SLOT_ID, ptr::null_mut(), ptr::null_mut()) },
            CKR_ARGUMENTS_BAD
        );
        // Expect CKR_BUFFER_TOO_SMALL if pulCount is less than the number of
        // mechanisms.
        assert_eq!(
            unsafe { C_GetMechanismList(SLOT_ID, mechanisms.as_mut_ptr(), &mut (count - 1)) },
            CKR_BUFFER_TOO_SMALL
        );
        // Expect CKR_CRYPTOKI_NOT_INITIALIZED if token is not initialized.
        assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
        assert_eq!(
            unsafe { C_GetMechanismList(SLOT_ID, ptr::null_mut(), ptr::null_mut()) },
            CKR_CRYPTOKI_NOT_INITIALIZED
        );
    }

    #[test]
    #[serial]
    fn get_mechanism_info() {
        test_init();
        assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
        let mut info = CK_MECHANISM_INFO::default();
        assert_eq!(
            unsafe { C_GetMechanismInfo(SLOT_ID, SUPPORTED_SIGNATURE_MECHANISMS[0], &mut info) },
            CKR_OK
        );
        assert_eq!(info.flags, CKF_SIGN);
        assert_eq!(unsafe { C_GetMechanismInfo(SLOT_ID, CKM_ECDSA, &mut info) }, CKR_OK);
        assert_eq!(info.flags, CKF_SIGN | CKF_VERIFY);
        for mechanism in SUPPORTED_SIGNATURE_MECHANISMS {
            unsafe { C_GetMechanismInfo(SLOT_ID, *mechanism, &mut info) };
            if *mechanism == CKM_ECDSA {
                assert_eq!(info.flags, CKF_SIGN | CKF_VERIFY);
            } else {
                assert_eq!(info.flags, CKF_SIGN);
                assert_eq!(info.flags & CKF_VERIFY, 0);
            }
        }
        // Expect CKR_MECHANISM_INVALID if type is an unsupported mechanism.
        assert_eq!(
            unsafe { C_GetMechanismInfo(SLOT_ID, CKM_DSA, &mut info) },
            CKR_MECHANISM_INVALID
        );
        // Expect CKR_ARGUMENTS_BAD if pInfo is null.
        assert_eq!(
            unsafe {
                C_GetMechanismInfo(SLOT_ID, SUPPORTED_SIGNATURE_MECHANISMS[0], ptr::null_mut())
            },
            CKR_ARGUMENTS_BAD
        );
        // Expect CKR_CRYPTOKI_NOT_INITIALIZED if token is not initialized.
        assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
        assert_eq!(
            unsafe {
                C_GetMechanismInfo(SLOT_ID, SUPPORTED_SIGNATURE_MECHANISMS[0], ptr::null_mut())
            },
            CKR_CRYPTOKI_NOT_INITIALIZED
        );
    }

    #[test]
    #[serial]
    fn open_session() {
        test_init();
        assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
        let flags = CKF_SERIAL_SESSION;
        let mut handle = CK_INVALID_HANDLE;
        assert_eq!(
            unsafe { C_OpenSession(SLOT_ID, flags, ptr::null_mut(), None, &mut handle) },
            CKR_OK
        );
        // Expect CKR_SLOT_ID_INVALID if slotID references a nonexistent slot.
        assert_eq!(
            unsafe { C_OpenSession(SLOT_ID + 1, flags, ptr::null_mut(), None, &mut handle) },
            CKR_SLOT_ID_INVALID
        );
        // Expect CKR_SESSION_PARALLEL_NOT_SUPPORTED if CKF_SERIAL_SESSION flag
        // is not set.
        assert_eq!(
            unsafe { C_OpenSession(SLOT_ID, 0, ptr::null_mut(), None, &mut handle) },
            CKR_SESSION_PARALLEL_NOT_SUPPORTED
        );
        // Expect CKR_ARGUMENTS_BAD if phSession is null.
        assert_eq!(
            unsafe { C_OpenSession(SLOT_ID, flags, ptr::null_mut(), None, ptr::null_mut()) },
            CKR_ARGUMENTS_BAD
        );
        assert_eq!(C_CloseSession(handle), CKR_OK);
        assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
    }

    #[test]
    #[serial]
    fn close_sesson() {
        test_init();
        assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
        let mut handle = CK_INVALID_HANDLE;
        assert_eq!(
            unsafe {
                C_OpenSession(SLOT_ID, CKF_SERIAL_SESSION, ptr::null_mut(), None, &mut handle)
            },
            CKR_OK
        );
        assert_eq!(C_CloseSession(handle), CKR_OK);
        // Expect CKR_SESSION_HANDLE_INVALID if the session has already been
        // closed.
        assert_eq!(C_CloseSession(handle), CKR_SESSION_HANDLE_INVALID);
        // Expect CKR_SESSION_HANDLE_INVALID if hSession is not a valid handle.
        assert_eq!(C_CloseSession(CK_INVALID_HANDLE), CKR_SESSION_HANDLE_INVALID);
        assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
    }

    #[test]
    #[serial]
    fn get_session_info() {
        test_init();
        assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
        let mut handle = CK_INVALID_HANDLE;
        assert_eq!(
            unsafe {
                C_OpenSession(SLOT_ID, CKF_SERIAL_SESSION, ptr::null_mut(), None, &mut handle)
            },
            CKR_OK
        );
        let mut session_info = CK_SESSION_INFO::default();
        assert_eq!(unsafe { C_GetSessionInfo(handle, &mut session_info) }, CKR_OK);
        // Expect CKR_SESSION_HANDLE_INVALID if hSession is not a valid handle.
        assert_eq!(
            unsafe { C_GetSessionInfo(CK_INVALID_HANDLE, &mut session_info) },
            CKR_SESSION_HANDLE_INVALID
        );
        // Expect CKR_ARGUMENTS_BAD if pInfo is null.
        assert_eq!(unsafe { C_GetSessionInfo(handle, ptr::null_mut()) }, CKR_ARGUMENTS_BAD);
        assert_eq!(C_CloseSession(handle), CKR_OK);
        assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
    }

    #[test]
    #[serial]
    fn get_attribute_value() {
        test_init();
        assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
        let mut session_h = CK_INVALID_HANDLE;
        assert_eq!(
            unsafe {
                C_OpenSession(SLOT_ID, CKF_SERIAL_SESSION, ptr::null_mut(), None, &mut session_h)
            },
            CKR_OK
        );
        let mut template = vec![CK_ATTRIBUTE::default()];
        // Expect CKR_OBJECT_HANDLE_INVALID if hObject is not a valid handle.
        assert_eq!(
            unsafe {
                C_GetAttributeValue(
                    session_h,
                    CK_INVALID_HANDLE,
                    template.as_mut_ptr(),
                    template.len() as CK_ULONG,
                )
            },
            CKR_OBJECT_HANDLE_INVALID
        );
        assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
        assert_eq!(
            unsafe { C_GetAttributeValue(session_h, 0, template.as_mut_ptr(), 0) },
            CKR_CRYPTOKI_NOT_INITIALIZED
        );
    }

    #[test]
    #[serial]
    fn find_objects_init() {
        test_init();
        assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
        let mut handle = CK_INVALID_HANDLE;
        assert_eq!(
            unsafe {
                C_OpenSession(SLOT_ID, CKF_SERIAL_SESSION, ptr::null_mut(), None, &mut handle)
            },
            CKR_OK
        );
        let mut template = vec![];
        assert_eq!(
            unsafe { C_FindObjectsInit(handle, template.as_mut_ptr(), template.len() as CK_ULONG) },
            CKR_OK
        );
        assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
        assert_eq!(
            unsafe { C_FindObjectsInit(handle, template.as_mut_ptr(), template.len() as CK_ULONG) },
            CKR_CRYPTOKI_NOT_INITIALIZED
        );
    }

    #[test]
    #[serial]
    fn find_objects() {
        test_init();
        assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
        let mut handle = CK_INVALID_HANDLE;
        assert_eq!(
            unsafe {
                C_OpenSession(SLOT_ID, CKF_SERIAL_SESSION, ptr::null_mut(), None, &mut handle)
            },
            CKR_OK
        );
        let mut template = vec![CK_ATTRIBUTE {
            type_: CKA_CLASS,
            pValue: CKO_PRIVATE_KEY as CK_VOID_PTR,
            ulValueLen: std::mem::size_of_val(&CKO_PRIVATE_KEY) as CK_ULONG,
        }];
        assert_eq!(unsafe { C_FindObjectsInit(handle, template.as_mut_ptr(), 0) }, CKR_OK);
        let mut objects = vec![CK_OBJECT_HANDLE::default()];
        let mut count = 0;
        assert_eq!(unsafe { C_FindObjects(handle, objects.as_mut_ptr(), 1, &mut count) }, CKR_OK);
        assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
        assert_eq!(
            unsafe { C_FindObjects(handle, ptr::null_mut(), 0, ptr::null_mut()) },
            CKR_CRYPTOKI_NOT_INITIALIZED
        );
    }

    #[test]
    #[serial]
    fn find_objects_final() {
        test_init();
        assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
        let mut handle = CK_INVALID_HANDLE;
        assert_eq!(
            unsafe {
                C_OpenSession(SLOT_ID, CKF_SERIAL_SESSION, ptr::null_mut(), None, &mut handle)
            },
            CKR_OK
        );
        let mut template = vec![];
        assert_eq!(
            unsafe { C_FindObjectsInit(handle, template.as_mut_ptr(), template.len() as CK_ULONG) },
            CKR_OK
        );
        assert_eq!(C_FindObjectsFinal(handle), CKR_OK);
        assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
        assert_eq!(C_FindObjectsFinal(handle), CKR_CRYPTOKI_NOT_INITIALIZED);
    }

    #[test]
    #[serial]
    fn get_function_status() {
        test_init();
        assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
        let mut session_h = CK_INVALID_HANDLE;
        assert_eq!(
            unsafe {
                C_OpenSession(SLOT_ID, CKF_SERIAL_SESSION, ptr::null_mut(), None, &mut session_h)
            },
            CKR_OK
        );
        assert_eq!(C_GetFunctionStatus(session_h), CKR_FUNCTION_NOT_PARALLEL);
        assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
    }
    #[test]
    #[serial]
    fn cancel_function() {
        test_init();
        assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
        let mut session_h = CK_INVALID_HANDLE;
        assert_eq!(
            unsafe {
                C_OpenSession(SLOT_ID, CKF_SERIAL_SESSION, ptr::null_mut(), None, &mut session_h)
            },
            CKR_OK
        );
        assert_eq!(C_GetFunctionStatus(session_h), CKR_FUNCTION_NOT_PARALLEL);
        assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
    }

    #[test]
    #[serial]
    fn rejects_persistent_and_private_session_object_templates() {
        test_init();
        assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
        let mut session = CK_INVALID_HANDLE;
        assert_eq!(
            unsafe {
                C_OpenSession(
                    SLOT_ID,
                    CKF_SERIAL_SESSION | CKF_RW_SESSION,
                    ptr::null_mut(),
                    None,
                    &mut session,
                )
            },
            CKR_OK
        );

        let mut class = CKO_PUBLIC_KEY as CK_ULONG;
        let mut key_type = CKK_EC as CK_ULONG;
        let mut token = CK_TRUE;
        let mut template = [
            CK_ATTRIBUTE {
                type_: CKA_CLASS,
                pValue: (&mut class as *mut CK_ULONG).cast(),
                ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_KEY_TYPE,
                pValue: (&mut key_type as *mut CK_ULONG).cast(),
                ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_TOKEN,
                pValue: (&mut token as *mut CK_BBOOL).cast(),
                ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
            },
        ];
        let mut handle = CK_INVALID_HANDLE;
        assert_eq!(
            unsafe {
                C_CreateObject(
                    session,
                    template.as_mut_ptr(),
                    template.len() as CK_ULONG,
                    &mut handle,
                )
            },
            CKR_TEMPLATE_INCONSISTENT
        );

        let mut private_class = CKO_PRIVATE_KEY as CK_ULONG;
        let mut private_token = CK_FALSE;
        let private_template = [
            CK_ATTRIBUTE {
                type_: CKA_CLASS,
                pValue: (&mut private_class as *mut CK_ULONG).cast(),
                ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_KEY_TYPE,
                pValue: (&mut key_type as *mut CK_ULONG).cast(),
                ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_TOKEN,
                pValue: (&mut private_token as *mut CK_BBOOL).cast(),
                ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
            },
        ];
        assert_eq!(
            unsafe {
                C_CreateObject(
                    session,
                    private_template.as_ptr() as *mut CK_ATTRIBUTE,
                    private_template.len() as CK_ULONG,
                    &mut handle,
                )
            },
            CKR_TEMPLATE_INCOMPLETE
        );
        assert_eq!(C_CloseSession(session), CKR_OK);
        assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
    }

    #[test]
    fn session_template_defaults_and_validation() {
        use p256::ecdsa::SigningKey;

        let signing_key = SigningKey::from_bytes((&[23u8; 32]).into()).unwrap();
        let point = signing_key.verifying_key().to_encoded_point(false);
        let point_der = OctetString::new(point.as_bytes().to_vec()).unwrap().to_der().unwrap();
        let attrs = vec![
            (CKA_CLASS, (CKO_PUBLIC_KEY as CK_ULONG).to_ne_bytes().to_vec()),
            (CKA_KEY_TYPE, (CKK_EC as CK_ULONG).to_ne_bytes().to_vec()),
            (CKA_EC_PARAMS, P256_EC_PARAMS_DER.to_vec()),
            (CKA_EC_POINT, point_der),
        ];
        let template = parse_session_public_key_template(&attrs).unwrap();
        assert_eq!(template.point, point.as_bytes());
        assert!(template.id.is_empty());
        assert!(template.label.is_empty());

        let mut duplicate = attrs.clone();
        duplicate.push((CKA_TOKEN, vec![CK_FALSE]));
        duplicate.push((CKA_TOKEN, vec![CK_FALSE]));
        assert!(matches!(
            parse_session_public_key_template(&duplicate),
            Err(Error::TemplateInconsistent)
        ));

        let mut persistent = attrs.clone();
        persistent.push((CKA_TOKEN, vec![CK_TRUE]));
        assert!(matches!(
            parse_session_public_key_template(&persistent),
            Err(Error::TemplateInconsistent)
        ));

        let mut unsupported = attrs.clone();
        unsupported.push((CKA_MODIFIABLE, vec![CK_TRUE]));
        assert!(matches!(
            parse_session_public_key_template(&unsupported),
            Err(Error::AttributeTypeInvalid(CKA_MODIFIABLE))
        ));

        let mut derive_false = attrs.clone();
        derive_false.push((CKA_DERIVE, vec![CK_FALSE]));
        assert!(parse_session_public_key_template(&derive_false).is_ok());

        let mut derive_true = attrs.clone();
        derive_true.push((CKA_DERIVE, vec![CK_TRUE]));
        assert!(matches!(
            parse_session_public_key_template(&derive_true),
            Err(Error::TemplateInconsistent)
        ));

        let mut invalid_derive = attrs;
        invalid_derive.push((CKA_DERIVE, vec![2]));
        assert!(matches!(
            parse_session_public_key_template(&invalid_derive),
            Err(Error::AttributeValueInvalid(AttributeType::Derive))
        ));
    }

    #[test]
    fn session_template_rejects_missing_and_malformed_values() {
        use p256::ecdsa::SigningKey;

        let signing_key = SigningKey::from_bytes((&[29u8; 32]).into()).unwrap();
        let point = signing_key.verifying_key().to_encoded_point(false);
        let point_der = OctetString::new(point.as_bytes().to_vec()).unwrap().to_der().unwrap();
        let base = vec![
            (CKA_CLASS, (CKO_PUBLIC_KEY as CK_ULONG).to_ne_bytes().to_vec()),
            (CKA_KEY_TYPE, (CKK_EC as CK_ULONG).to_ne_bytes().to_vec()),
            (CKA_EC_PARAMS, P256_EC_PARAMS_DER.to_vec()),
            (CKA_EC_POINT, point_der),
        ];
        for missing in 0..base.len() {
            let mut attrs = base.clone();
            attrs.remove(missing);
            assert!(matches!(
                parse_session_public_key_template(&attrs),
                Err(Error::TemplateIncomplete)
            ));
        }

        let mut wrong_curve = base.clone();
        wrong_curve[2] =
            (CKA_EC_PARAMS, vec![0x06, 0x08, 0x2B, 0x81, 0x04, 0x00, 0x22, 0x03, 0x01, 0x01]);
        assert!(matches!(
            parse_session_public_key_template(&wrong_curve),
            Err(Error::AttributeValueInvalid(AttributeType::EcParams))
        ));

        let mut malformed_point = base;
        malformed_point[3] = (CKA_EC_POINT, vec![0x04, 0x02, 0x04]);
        assert!(matches!(
            parse_session_public_key_template(&malformed_point),
            Err(Error::AttributeValueInvalid(AttributeType::EcPoint))
        ));
    }

    #[test]
    fn session_object_attributes_and_cross_session_lifetime() {
        use native_pkcs11_core::object::Object;
        use p256::ecdsa::SigningKey;
        use std::sync::Arc;

        let signing_key = SigningKey::from_bytes((&[31u8; 32]).into()).unwrap();
        let point = signing_key.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        let key = SessionPublicKey::new(point.clone(), b"id".to_vec(), "label".to_owned()).unwrap();
        let object =
            Object::SessionPublicKey(Arc::new(key) as Arc<dyn native_pkcs11_traits::PublicKey>);
        assert_eq!(object.attribute(AttributeType::Class), Some(Attribute::Class(CKO_PUBLIC_KEY)));
        assert_eq!(object.attribute(AttributeType::KeyType), Some(Attribute::KeyType(CKK_EC)));
        assert_eq!(object.attribute(AttributeType::Token), Some(Attribute::Token(false)));
        assert_eq!(object.attribute(AttributeType::Private), Some(Attribute::Private(false)));
        assert_eq!(object.attribute(AttributeType::Verify), Some(Attribute::Verify(true)));
        let ec_point = match object.attribute(AttributeType::EcPoint).unwrap() {
            Attribute::EcPoint(value) => OctetString::from_der(&value).unwrap(),
            other => panic!("unexpected attribute: {other:?}"),
        };
        assert_eq!(ec_point.as_bytes(), point.as_slice());
        assert!(matches!(
            object.attribute(AttributeType::PublicKeyInfo),
            Some(Attribute::PublicKeyInfo(_))
        ));

        let mut store = sessions::OBJECT_STORE.lock().unwrap();
        let handle = store.insert_session_object(101, object).unwrap();
        assert!(store.get(&handle).is_some());
        assert!(store.destroy_session_object(102, handle).is_ok());
        assert!(store.get(&handle).is_none());
    }

    #[test]
    #[serial]
    fn creates_valid_session_key_with_default_token_and_reports_attributes() {
        use p256::ecdsa::SigningKey;

        test_init();
        assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
        let mut first = CK_INVALID_HANDLE;
        let mut second = CK_INVALID_HANDLE;
        assert_eq!(
            unsafe {
                C_OpenSession(SLOT_ID, CKF_SERIAL_SESSION, ptr::null_mut(), None, &mut first)
            },
            CKR_OK
        );
        assert_eq!(
            unsafe {
                C_OpenSession(SLOT_ID, CKF_SERIAL_SESSION, ptr::null_mut(), None, &mut second)
            },
            CKR_OK
        );

        let signing_key = SigningKey::from_bytes((&[41u8; 32]).into()).unwrap();
        let point = signing_key.verifying_key().to_encoded_point(false);
        let point_der = OctetString::new(point.as_bytes().to_vec()).unwrap().to_der().unwrap();
        let mut class = CKO_PUBLIC_KEY as CK_ULONG;
        let mut key_type = CKK_EC as CK_ULONG;
        let mut params = P256_EC_PARAMS_DER.to_vec();
        let mut derive_false = CK_FALSE;
        let mut template = [
            CK_ATTRIBUTE {
                type_: CKA_CLASS,
                pValue: (&mut class as *mut CK_ULONG).cast(),
                ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_KEY_TYPE,
                pValue: (&mut key_type as *mut CK_ULONG).cast(),
                ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_EC_PARAMS,
                pValue: params.as_mut_ptr().cast(),
                ulValueLen: params.len() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_EC_POINT,
                pValue: point_der.as_ptr() as *mut _,
                ulValueLen: point_der.len() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_DERIVE,
                pValue: (&mut derive_false as *mut CK_BBOOL).cast(),
                ulValueLen: std::mem::size_of::<CK_BBOOL>() as _,
            },
        ];
        let mut object = CK_INVALID_HANDLE;
        assert_eq!(
            unsafe {
                C_CreateObject(first, template.as_mut_ptr(), template.len() as _, &mut object)
            },
            CKR_OK
        );

        let mut token = CK_BBOOL::default();
        let mut private = CK_BBOOL::default();
        let mut verify = CK_BBOOL::default();
        let mut attributes = [
            CK_ATTRIBUTE {
                type_: CKA_TOKEN,
                pValue: (&mut token as *mut CK_BBOOL).cast(),
                ulValueLen: std::mem::size_of::<CK_BBOOL>() as _,
            },
            CK_ATTRIBUTE {
                type_: CKA_PRIVATE,
                pValue: (&mut private as *mut CK_BBOOL).cast(),
                ulValueLen: std::mem::size_of::<CK_BBOOL>() as _,
            },
            CK_ATTRIBUTE {
                type_: CKA_VERIFY,
                pValue: (&mut verify as *mut CK_BBOOL).cast(),
                ulValueLen: std::mem::size_of::<CK_BBOOL>() as _,
            },
            CK_ATTRIBUTE {
                type_: CKA_DERIVE,
                pValue: (&mut derive_false as *mut CK_BBOOL).cast(),
                ulValueLen: std::mem::size_of::<CK_BBOOL>() as _,
            },
        ];
        assert_eq!(
            unsafe {
                C_GetAttributeValue(second, object, attributes.as_mut_ptr(), attributes.len() as _)
            },
            CKR_OK
        );
        assert_eq!((token, private, verify, derive_false), (CK_FALSE, CK_FALSE, CK_TRUE, CK_FALSE));
        assert_eq!(C_DestroyObject(second, object), CKR_OK);
        assert_eq!(C_DestroyObject(first, object), CKR_OBJECT_HANDLE_INVALID);

        let mut derive_true = CK_TRUE;
        template[4].pValue = (&mut derive_true as *mut CK_BBOOL).cast();
        let mut rejected_object = CK_INVALID_HANDLE;
        assert_eq!(
            unsafe {
                C_CreateObject(
                    first,
                    template.as_mut_ptr(),
                    template.len() as _,
                    &mut rejected_object,
                )
            },
            CKR_TEMPLATE_INCONSISTENT
        );
        assert_eq!(rejected_object, CK_INVALID_HANDLE);
        let mut rejected_attribute =
            CK_ATTRIBUTE { type_: CKA_CLASS, pValue: ptr::null_mut(), ulValueLen: 0 };
        assert_eq!(
            unsafe { C_GetAttributeValue(first, rejected_object, &mut rejected_attribute, 1) },
            CKR_OBJECT_HANDLE_INVALID
        );
        assert_eq!(C_CloseSession(first), CKR_OK);
        assert_eq!(C_CloseSession(second), CKR_OK);
        assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
    }

    #[test]
    #[serial]
    fn creates_verifies_and_destroys_session_public_key() {
        use p256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner};

        test_init();
        assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);

        let mut session = CK_INVALID_HANDLE;
        assert_eq!(
            unsafe {
                C_OpenSession(
                    SLOT_ID,
                    CKF_SERIAL_SESSION | CKF_RW_SESSION,
                    ptr::null_mut(),
                    None,
                    &mut session,
                )
            },
            CKR_OK
        );

        let signing_key = SigningKey::from_bytes((&[9u8; 32]).into()).unwrap();
        let point = signing_key.verifying_key().to_encoded_point(false);
        let mut ec_point = vec![0x04, point.as_bytes().len() as u8];
        ec_point.extend_from_slice(point.as_bytes());
        let mut class = CKO_PUBLIC_KEY as CK_ULONG;
        let mut key_type = CKK_EC as CK_ULONG;
        let mut token = CK_FALSE;
        let mut params = P256_EC_PARAMS_DER.to_vec();
        let mut template = [
            CK_ATTRIBUTE {
                type_: CKA_CLASS,
                pValue: (&mut class as *mut CK_ULONG).cast(),
                ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_KEY_TYPE,
                pValue: (&mut key_type as *mut CK_ULONG).cast(),
                ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_TOKEN,
                pValue: (&mut token as *mut CK_BBOOL).cast(),
                ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_EC_PARAMS,
                pValue: params.as_mut_ptr().cast(),
                ulValueLen: params.len() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_EC_POINT,
                pValue: ec_point.as_mut_ptr().cast(),
                ulValueLen: ec_point.len() as CK_ULONG,
            },
        ];

        let mut public_handle = CK_INVALID_HANDLE;
        assert_eq!(
            unsafe {
                C_CreateObject(
                    session,
                    template.as_mut_ptr(),
                    template.len() as CK_ULONG,
                    &mut public_handle,
                )
            },
            CKR_OK
        );

        let mechanism =
            CK_MECHANISM { mechanism: CKM_ECDSA, pParameter: ptr::null_mut(), ulParameterLen: 0 };
        assert_eq!(
            unsafe { C_VerifyInit(session, &mechanism as *const _ as *mut _, public_handle) },
            CKR_OK
        );

        let digest = [0x5Au8; 32];
        let signature: p256::ecdsa::Signature = signing_key.sign_prehash(&digest).unwrap();
        let mut signature_bytes = signature.to_bytes().to_vec();
        let mut digest_bytes = digest;
        assert_eq!(
            unsafe {
                C_Verify(
                    session,
                    digest_bytes.as_mut_ptr(),
                    digest_bytes.len() as CK_ULONG,
                    signature_bytes.as_mut_ptr(),
                    signature_bytes.len() as CK_ULONG,
                )
            },
            CKR_OK
        );
        assert_eq!(
            unsafe {
                C_Verify(
                    session,
                    digest_bytes.as_mut_ptr(),
                    digest_bytes.len() as CK_ULONG,
                    signature_bytes.as_mut_ptr(),
                    signature_bytes.len() as CK_ULONG,
                )
            },
            CKR_OPERATION_NOT_INITIALIZED
        );

        assert_eq!(C_DestroyObject(session, public_handle), CKR_OK);
        assert_eq!(C_DestroyObject(session, public_handle), CKR_OBJECT_HANDLE_INVALID);
        assert_eq!(C_CloseSession(session), CKR_OK);
        assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
    }

    #[test]
    #[serial]
    fn verify_init_and_verify_return_defined_errors_and_consume_operation() {
        use p256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner};

        test_init();
        assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
        let session = open_test_session();
        let signing_key = SigningKey::from_bytes((&[11u8; 32]).into()).unwrap();
        let public_handle = create_test_public_key(session, &signing_key);
        let mut mechanism = raw_ecdsa_mechanism();

        assert_eq!(unsafe { C_VerifyInit(session, &mut mechanism, public_handle) }, CKR_OK);
        assert_eq!(
            unsafe { C_VerifyInit(session, &mut mechanism, public_handle) },
            CKR_OPERATION_ACTIVE
        );

        let digest = [0x5Au8; 32];
        let signature: p256::ecdsa::Signature = signing_key.sign_prehash(&digest).unwrap();
        let mut signature_bytes = signature.to_bytes().to_vec();
        signature_bytes[0] ^= 1;
        assert_eq!(
            unsafe {
                C_Verify(
                    session,
                    digest.as_ptr() as *mut _,
                    digest.len() as CK_ULONG,
                    signature_bytes.as_mut_ptr(),
                    signature_bytes.len() as CK_ULONG,
                )
            },
            CKR_SIGNATURE_INVALID
        );
        assert_eq!(
            unsafe {
                C_Verify(
                    session,
                    digest.as_ptr() as *mut _,
                    digest.len() as CK_ULONG,
                    signature_bytes.as_mut_ptr(),
                    signature_bytes.len() as CK_ULONG,
                )
            },
            CKR_OPERATION_NOT_INITIALIZED
        );

        assert_eq!(unsafe { C_VerifyInit(session, &mut mechanism, public_handle) }, CKR_OK);
        let mut malformed_signature = vec![0u8; 64];
        assert_eq!(
            unsafe {
                C_Verify(
                    session,
                    digest.as_ptr() as *mut _,
                    digest.len() as CK_ULONG,
                    malformed_signature.as_mut_ptr(),
                    malformed_signature.len() as CK_ULONG,
                )
            },
            CKR_SIGNATURE_INVALID
        );

        assert_eq!(unsafe { C_VerifyInit(session, &mut mechanism, public_handle) }, CKR_OK);
        let mut short_signature = vec![0u8; 63];
        assert_eq!(
            unsafe {
                C_Verify(
                    session,
                    digest.as_ptr() as *mut _,
                    digest.len() as CK_ULONG,
                    short_signature.as_mut_ptr(),
                    short_signature.len() as CK_ULONG,
                )
            },
            CKR_SIGNATURE_LEN_RANGE
        );

        assert_eq!(unsafe { C_VerifyInit(session, &mut mechanism, public_handle) }, CKR_OK);
        let mut oversized_signature = vec![0u8; 65];
        assert_eq!(
            unsafe {
                C_Verify(
                    session,
                    digest.as_ptr() as *mut _,
                    digest.len() as CK_ULONG,
                    oversized_signature.as_mut_ptr(),
                    oversized_signature.len() as CK_ULONG,
                )
            },
            CKR_SIGNATURE_LEN_RANGE
        );

        assert_eq!(unsafe { C_VerifyInit(session, &mut mechanism, public_handle) }, CKR_OK);
        let mut long_digest = vec![0u8; 33];
        let long_signature: p256::ecdsa::Signature =
            signing_key.sign_prehash(&long_digest).unwrap();
        let mut valid_signature = long_signature.to_bytes().to_vec();
        assert_eq!(
            unsafe {
                C_Verify(
                    session,
                    long_digest.as_mut_ptr(),
                    long_digest.len() as CK_ULONG,
                    valid_signature.as_mut_ptr(),
                    valid_signature.len() as CK_ULONG,
                )
            },
            CKR_OK
        );

        assert_eq!(unsafe { C_VerifyInit(session, &mut mechanism, public_handle) }, CKR_OK);
        let short_digest = vec![0x3Cu8; 16];
        let short_signature: p256::ecdsa::Signature =
            signing_key.sign_prehash(&short_digest).unwrap();
        let mut short_signature = short_signature.to_bytes().to_vec();
        assert_eq!(
            unsafe {
                C_Verify(
                    session,
                    short_digest.as_ptr() as *mut _,
                    short_digest.len() as _,
                    short_signature.as_mut_ptr(),
                    short_signature.len() as _,
                )
            },
            CKR_OK
        );

        assert_eq!(C_CloseSession(session), CKR_OK);
        assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
    }

    #[test]
    #[serial]
    fn verify_init_rejects_invalid_handles_mechanisms_and_parameters() {
        test_init();
        assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
        let session = open_test_session();
        let mut mechanism = raw_ecdsa_mechanism();
        let signing_key = p256::ecdsa::SigningKey::from_bytes((&[13u8; 32]).into()).unwrap();
        let public_handle = create_test_public_key(session, &signing_key);

        assert_eq!(
            unsafe { C_VerifyInit(session, &mut mechanism, CK_INVALID_HANDLE) },
            CKR_KEY_HANDLE_INVALID
        );
        mechanism.mechanism = CKM_DSA;
        assert_eq!(
            unsafe { C_VerifyInit(session, &mut mechanism, public_handle) },
            CKR_MECHANISM_INVALID
        );

        mechanism.mechanism = CKM_RSA_PKCS;
        assert_eq!(
            unsafe { C_VerifyInit(session, &mut mechanism, public_handle) },
            CKR_MECHANISM_INVALID
        );

        mechanism.mechanism = CKM_ECDSA_SHA256;
        assert_eq!(
            unsafe { C_VerifyInit(session, &mut mechanism, public_handle) },
            CKR_MECHANISM_INVALID
        );

        mechanism = raw_ecdsa_mechanism();
        let parameter = 0u8;
        mechanism.pParameter = &parameter as *const _ as *mut _;
        assert_eq!(
            unsafe { C_VerifyInit(session, &mut mechanism, public_handle) },
            CKR_MECHANISM_PARAM_INVALID
        );
        assert_eq!(
            unsafe { C_Verify(session, ptr::null_mut(), 0, ptr::null_mut(), 0) },
            CKR_OPERATION_NOT_INITIALIZED
        );

        assert_eq!(C_CloseSession(session), CKR_OK);
        assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
    }

    #[test]
    #[serial]
    fn session_public_keys_are_visible_and_invalidation_is_observed() {
        use p256::ecdsa::SigningKey;

        test_init();
        assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
        let first = open_test_session();
        let second = open_test_session();
        let signing_key = SigningKey::from_bytes((&[17u8; 32]).into()).unwrap();
        let public_handle = create_test_public_key(first, &signing_key);
        let mut mechanism = raw_ecdsa_mechanism();

        assert_eq!(unsafe { C_VerifyInit(second, &mut mechanism, public_handle) }, CKR_OK);
        assert_eq!(unsafe { C_VerifyInit(first, &mut mechanism, public_handle) }, CKR_OK);
        assert_eq!(C_CloseSession(first), CKR_OK);
        let digest = [0x5Au8; 32];
        let mut signature = vec![0u8; 64];
        assert_eq!(
            unsafe {
                C_Verify(
                    second,
                    digest.as_ptr() as *mut _,
                    digest.len() as _,
                    signature.as_mut_ptr(),
                    signature.len() as _,
                )
            },
            CKR_KEY_HANDLE_INVALID
        );
        assert_eq!(C_CloseSession(second), CKR_OK);
        assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
    }

    #[test]
    #[serial]
    fn provider_session_object_is_removed_when_connection_session_closes() {
        test_init();
        assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
        let first = open_test_session();
        let signing_key = p256::ecdsa::SigningKey::from_bytes((&[19u8; 32]).into()).unwrap();
        let public_handle = create_test_public_key(first, &signing_key);
        assert_eq!(C_CloseSession(first), CKR_OK);

        let second = open_test_session();
        let mut mechanism = raw_ecdsa_mechanism();
        assert_eq!(
            unsafe { C_VerifyInit(second, &mut mechanism, public_handle) },
            CKR_KEY_HANDLE_INVALID
        );
        assert_eq!(C_CloseSession(second), CKR_OK);
        assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
    }
}
