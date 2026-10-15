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

use std::{collections::HashMap, time::Duration};

use cached::{Cached, TtlCache};
use native_pkcs11_core::{
    Result,
    attribute::{Attribute, AttributeType, Attributes},
};
use native_pkcs11_traits::{KeySearchOptions, backend};
use pkcs11_sys::{
    CK_OBJECT_HANDLE, CK_SESSION_HANDLE, CKO_CERTIFICATE, CKO_PRIVATE_KEY, CKO_PUBLIC_KEY,
    CKO_SECRET_KEY, CKP_BASELINE_PROVIDER,
};
use tracing::{instrument, warn};

use crate::{Error, object::Object};

#[derive(Debug)]
pub struct ObjectStore {
    objects: HashMap<CK_OBJECT_HANDLE, Object>,
    handles_by_object: HashMap<Object, CK_OBJECT_HANDLE>,
    temporary_owners: HashMap<CK_OBJECT_HANDLE, CK_SESSION_HANDLE>,
    next_object_handle: CK_OBJECT_HANDLE,
    query_cache: TtlCache<Attributes, Vec<CK_OBJECT_HANDLE>>,
}

impl ObjectStore {
    fn allocate_handle(&mut self) -> Result<CK_OBJECT_HANDLE> {
        let handle = self.next_object_handle.checked_add(1).ok_or(Error::ObjectHandleExhausted)?;
        if handle == pkcs11_sys::CK_INVALID_HANDLE || self.objects.contains_key(&handle) {
            return Err(Error::ObjectHandleExhausted);
        }
        self.next_object_handle = handle;
        Ok(handle)
    }

    #[instrument(skip(self))]
    pub fn insert(&mut self, object: Object) -> Result<CK_OBJECT_HANDLE> {
        if let Some(existing_handle) = self.handles_by_object.get(&object) {
            return Ok(*existing_handle);
        }
        let handle = self.allocate_handle()?;
        self.objects.insert(handle, object.clone());
        self.handles_by_object.insert(object, handle);
        self.query_cache.cache_clear();
        Ok(handle)
    }

    pub fn insert_session_object(
        &mut self,
        session: CK_SESSION_HANDLE,
        object: Object,
    ) -> Result<CK_OBJECT_HANDLE> {
        let handle = self.allocate_handle()?;
        self.objects.insert(handle, object);
        self.temporary_owners.insert(handle, session);
        self.query_cache.cache_clear();
        Ok(handle)
    }

    pub fn destroy_session_object(
        &mut self,
        _session: CK_SESSION_HANDLE,
        handle: CK_OBJECT_HANDLE,
    ) -> Result<()> {
        match self.temporary_owners.get(&handle) {
            Some(_) => {
                self.temporary_owners.remove(&handle);
                self.objects.remove(&handle);
                self.query_cache.cache_clear();
                Ok(())
            }
            None => Err(Error::ObjectHandleInvalid(handle)),
        }
    }

    pub fn destroy_session_objects(&mut self, session: CK_SESSION_HANDLE) {
        let handles: Vec<_> = self
            .temporary_owners
            .iter()
            .filter_map(|(handle, owner)| (*owner == session).then_some(*handle))
            .collect();
        for handle in handles {
            self.temporary_owners.remove(&handle);
            self.objects.remove(&handle);
        }
        self.query_cache.cache_clear();
    }

    pub fn clear_session_objects(&mut self) {
        let handles: Vec<_> = self.temporary_owners.keys().copied().collect();
        for handle in handles {
            self.temporary_owners.remove(&handle);
            self.objects.remove(&handle);
        }
        self.query_cache.cache_clear();
    }

    #[instrument(skip(self))]
    pub fn get(&self, handle: &CK_OBJECT_HANDLE) -> Option<&Object> {
        self.objects.get(handle)
    }

    pub fn get_for_session(
        &self,
        session: CK_SESSION_HANDLE,
        handle: &CK_OBJECT_HANDLE,
    ) -> Option<&Object> {
        let _ = session;
        self.objects.get(handle)
    }

    #[instrument(skip(self))]
    pub fn find(&mut self, template: Attributes) -> Result<Vec<CK_OBJECT_HANDLE>> {
        // Cache certificates.
        //
        // Firefox + NSS query certificates for every TLS connection in order to
        // evaluate server trust. Cache the results for 3 seconds.
        if let Some(c) = self.query_cache.cache_get(&template) {
            Ok(c.to_vec())
        } else {
            let output = self.find_impl(&template)?;
            self.query_cache.cache_set(template, output.clone());
            Ok(output)
        }
    }

    #[instrument(skip(self))]
    fn find_impl(&mut self, template: &Attributes) -> Result<Vec<CK_OBJECT_HANDLE>> {
        self.find_with_backend(template)?;
        if template.is_empty() { Ok(self.find_all()) } else { Ok(self.find_store(template)) }
    }

    #[instrument(skip(self))]
    fn find_all(&self) -> Vec<CK_OBJECT_HANDLE> {
        self.objects.keys().copied().collect()
    }

    #[instrument(skip(self))]
    fn find_store(&self, template: &Attributes) -> Vec<CK_OBJECT_HANDLE> {
        self.objects
            .iter()
            .filter(|(_, object)| object.matches(template))
            .map(|(handle, _)| *handle)
            .collect()
    }

    #[instrument(skip(self))]
    fn find_with_backend(&mut self, template: &Attributes) -> Result<()> {
        if template.is_empty() {
            self.find_with_backend_all_certificates()?;
            self.find_with_backend_all_public_keys()?;
            self.find_with_backend_all_private_keys()?;
            return Ok(());
        }

        let class = match template.get(AttributeType::Class) {
            Some(Attribute::Class(class)) => class,
            None => {
                return Err(Error::Todo("no class attribute".to_string()));
            }
            class => {
                return Err(Error::Todo(format!("class {class:?} not implemented")));
            }
        };
        match *class {
            CKO_CERTIFICATE => {
                if template.len() > 1 {
                    warn!("ignoring attributes for certificate search");
                }
                self.find_with_backend_all_certificates()?;
            }
            // CKO_NSS_TRUST | CKO_NETSCAPE_BUILTIN_ROOT_LIST
            3461563219 | 3461563220 => (),
            CKO_SECRET_KEY => (),
            CKO_PUBLIC_KEY | CKO_PRIVATE_KEY => {
                let opts = if let Some(Attribute::Id(id)) = template.get(AttributeType::Id) {
                    KeySearchOptions::Id(id.clone())
                } else if let Some(Attribute::Label(label)) = template.get(AttributeType::Label) {
                    KeySearchOptions::Label(label.into())
                } else {
                    match *class {
                        CKO_PRIVATE_KEY => self.find_with_backend_all_private_keys()?,
                        CKO_PUBLIC_KEY => self.find_with_backend_all_public_keys()?,
                        _ => unreachable!(),
                    }
                    return Ok(());
                };
                match *class {
                    CKO_PRIVATE_KEY => {
                        if let Some(key) = backend().find_private_key(opts)? {
                            self.insert(Object::PrivateKey(key))?;
                        }
                    }
                    CKO_PUBLIC_KEY => {
                        if let Some(key) = backend().find_public_key(opts)? {
                            self.insert(Object::PublicKey(key.into()))?;
                        }
                    }
                    _ => unreachable!(),
                };
            }
            _ => {
                return Err(Error::AttributeTypeInvalid(*class));
            }
        }
        Ok(())
    }

    fn find_with_backend_all_certificates(&mut self) -> Result<()> {
        for cert in backend().find_all_certificates()? {
            self.insert(Object::Certificate(cert.into()))?;
        }
        Ok(())
    }

    fn find_with_backend_all_public_keys(&mut self) -> Result<()> {
        for public_key in backend().find_all_public_keys()? {
            self.insert(Object::PublicKey(public_key))?;
        }
        Ok(())
    }

    fn find_with_backend_all_private_keys(&mut self) -> Result<()> {
        for private_key in backend().find_all_private_keys()? {
            self.insert(Object::PrivateKey(private_key))?;
        }
        Ok(())
    }
}

impl Default for ObjectStore {
    fn default() -> Self {
        Self {
            objects: HashMap::from([(1, Object::Profile(CKP_BASELINE_PROVIDER))]),
            handles_by_object: HashMap::from([(Object::Profile(CKP_BASELINE_PROVIDER), 1)]),
            temporary_owners: HashMap::new(),
            next_object_handle: 2,
            query_cache: TtlCache::builder()
                .ttl(Duration::from_secs(10))
                .build()
                .expect("ttl is set"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, vec};

    use native_pkcs11_traits::{KeyAlgorithm, backend, random_label};
    use p256::ecdsa::SigningKey;
    use pkcs11_sys::CKO_PRIVATE_KEY;
    use serial_test::serial;

    use super::*;
    use crate::session_public_key::SessionPublicKey;
    use crate::tests::test_init;

    #[test]
    #[serial]
    fn test_object_store() {
        test_init();

        let label = &format!("objectstore test {}", random_label());

        let key =
            backend().generate_key(native_pkcs11_traits::KeyAlgorithm::Rsa, Some(label)).unwrap();

        let mut store = ObjectStore::default();

        let template = Attributes::from(vec![
            Attribute::Class(CKO_PRIVATE_KEY),
            Attribute::Label(label.into()),
        ]);
        let private_key_handle = store.find(template.clone()).unwrap()[0];
        //  find again
        assert_eq!(store.find(template).unwrap()[0], private_key_handle);

        key.find_public_key(backend()).unwrap().unwrap().delete();
        key.delete();
    }

    #[test]
    #[serial]
    fn key_alg() -> Result<()> {
        test_init();
        let ec = backend().generate_key(KeyAlgorithm::Ecc, Some(&random_label()))?;
        let rsa = backend().generate_key(KeyAlgorithm::Rsa, Some(&random_label()))?;

        assert_eq!(ec.algorithm(), KeyAlgorithm::Ecc);
        assert_eq!(rsa.algorithm(), KeyAlgorithm::Rsa);

        for key in [ec, rsa] {
            key.find_public_key(backend()).unwrap().unwrap().delete();
            key.delete();
        }

        Ok(())
    }

    #[test]
    fn session_objects_are_owned_and_destroyed() {
        let mut store = ObjectStore::default();
        let signing_key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let key = SessionPublicKey::from_sec1(
            signing_key.verifying_key().to_encoded_point(false).as_bytes().to_vec(),
        )
        .unwrap();
        let handle =
            store.insert_session_object(3, Object::SessionPublicKey(Arc::new(key))).unwrap();

        assert!(store.get(&handle).is_some());
        assert!(store.destroy_session_object(4, handle).is_ok());
        assert!(store.get(&handle).is_none());
        assert!(store.destroy_session_object(3, handle).is_err());
    }

    #[test]
    fn closing_a_session_removes_only_its_temporary_objects() {
        let mut store = ObjectStore::default();
        let point = SigningKey::from_bytes((&[7u8; 32]).into())
            .unwrap()
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let first = store
            .insert_session_object(
                3,
                Object::SessionPublicKey(Arc::new(
                    SessionPublicKey::from_sec1(point.clone()).unwrap(),
                )),
            )
            .unwrap();
        let second = store
            .insert_session_object(
                4,
                Object::SessionPublicKey(Arc::new(SessionPublicKey::from_sec1(point).unwrap())),
            )
            .unwrap();

        store.destroy_session_objects(3);
        assert!(store.get(&first).is_none());
        assert!(store.get(&second).is_some());
        store.clear_session_objects();
        assert!(store.get(&second).is_none());
    }

    #[test]
    fn session_mutations_invalidate_queries_and_handle_exhaustion_is_fallible() {
        let mut store = ObjectStore::default();
        let template = Attributes::from(Vec::<Attribute>::new());
        store.query_cache.cache_set(template.clone(), vec![99]);
        let signing_key = SigningKey::from_bytes((&[37u8; 32]).into()).unwrap();
        let point = signing_key.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        let key = SessionPublicKey::from_sec1(point).unwrap();
        let handle =
            store.insert_session_object(7, Object::SessionPublicKey(Arc::new(key))).unwrap();
        assert!(store.query_cache.cache_get(&template).is_none());
        store.query_cache.cache_set(template.clone(), vec![handle]);
        store.destroy_session_object(8, handle).unwrap();
        assert!(store.query_cache.cache_get(&template).is_none());

        store.next_object_handle = CK_OBJECT_HANDLE::MAX;
        assert!(matches!(
            store.insert_session_object(7, Object::Profile(CKP_BASELINE_PROVIDER)),
            Err(Error::ObjectHandleExhausted)
        ));
    }
}
