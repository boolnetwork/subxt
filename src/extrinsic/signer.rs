// Copyright 2019-2021 Parity Technologies (UK) Ltd.
// This file is part of substrate-subxt.
//
// subxt is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// subxt is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with substrate-subxt.  If not, see <http://www.gnu.org/licenses/>.

//! A library to **sub**mit e**xt**rinsics to a
//! [substrate](https://github.com/paritytech/substrate) node via RPC.

use super::{
    SignedExtra,
    SignedPayload,
    UncheckedExtrinsic,
};
use crate::runtimes::Runtime;
use codec::Encode;
use sp_core::keccak_256;
use sp_runtime::traits::{
    IdentifyAccount,
    SignedExtension,
    Verify,
};
use std::{
    future::Future,
    pin::Pin,
};
use crate::{PublicKey, SecretKey, sign, Message};

/// Extrinsic signer.
pub trait Signer<T: Runtime> {
    /// Returns the account id.
    fn account_id(&self) -> &T::AccountId;

    /// Optionally returns a nonce.
    fn nonce(&self) -> Option<T::Index>;

    /// Takes an unsigned extrinsic and returns a signed extrinsic.
    ///
    /// Some signers may fail, for instance because the hardware on which the keys are located has
    /// refused the operation.
    fn sign(
        &self,
        extrinsic: SignedPayload<T>,
    ) -> Pin<Box<dyn Future<Output = Result<UncheckedExtrinsic<T>, String>> + Send>>;
}

/// Extrinsic signer using a private key.
#[derive(Clone, Debug)]
pub struct PairSigner<T: Runtime> {
    account_id: T::AccountId,
    nonce: Option<T::Index>,
    signer: SecretKey,
}

impl<T> PairSigner<T>
where
    T: Runtime,
    T::Signature: From<sp_core::ecdsa::Signature>,
    <T::Signature as Verify>::Signer: From<sp_core::ecdsa::Public> + IdentifyAccount<AccountId = T::AccountId>,
{
    /// Creates a new `Signer` from a `Pair`.
    pub fn new(signer: SecretKey) -> Self {
        let pk_compressed = PublicKey::from_secret_key(&signer).serialize_compressed();
        let account_id =
            <T::Signature as Verify>::Signer::from(sp_core::ecdsa::Public::from_raw(pk_compressed)).into_account();
        Self {
            account_id,
            nonce: None,
            signer,
        }
    }

    /// Sets the nonce to a new value.
    pub fn set_nonce(&mut self, nonce: T::Index) {
        self.nonce = Some(nonce);
    }

    /// Increment the nonce.
    pub fn increment_nonce(&mut self) {
        self.nonce = self.nonce.map(|nonce| nonce + 1u32.into());
    }

    /// Returns the signer.
    pub fn signer(&self) -> &SecretKey {
        &self.signer
    }
}

impl<T> Signer<T> for PairSigner<T>
where
    T: Runtime,
    T::AccountId: Into<T::Address> + 'static,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send,
    T::Signature: From<sp_core::ecdsa::Signature>,
    T::AccountId: Into<[u8; 20]>,
{
    fn account_id(&self) -> &T::AccountId {
        &self.account_id
    }

    fn nonce(&self) -> Option<T::Index> {
        self.nonce
    }

    fn sign(
        &self,
        extrinsic: SignedPayload<T>,
    ) -> Pin<Box<dyn Future<Output = Result<UncheckedExtrinsic<T>, String>> + Send>> {
        let signature = extrinsic.using_encoded(|payload| {
            let msg = Message::parse(&keccak_256(payload));
            // self.signer.sign(payload)
            sign(&msg, &self.signer)
        });
        let mut raw_sig = signature.0.serialize().to_vec();
        raw_sig.push(signature.1.serialize());

        let ecdsa_signature = sp_core::ecdsa::Signature::from_slice(raw_sig.as_slice());
        let (call, extra, _) = extrinsic.deconstruct();
        let extrinsic = UncheckedExtrinsic::<T>::new_signed(
            call,
            // sp_runtime::MultiAddress::Address20(signed),
            self.account_id.clone().into(),
            ecdsa_signature.into(),
            extra,
        );
        Box::pin(async move { Ok(extrinsic) })
    }
}
