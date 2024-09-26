// Copyright 2019-2024 Parity Technologies (UK) Ltd.
// This file is dual-licensed as Apache-2.0 or GPL-3.0.
// see LICENSE for license details.

//! A library to **sub**mit e**xt**rinsics to a
//! [substrate](https://github.com/paritytech/substrate) node via RPC.

use crate::macros::cfg_substrate_compat;
use crate::Config;

/// Signing transactions requires a [`Signer`]. This is responsible for
/// providing the "from" account that the transaction is being signed by,
/// as well as actually signing a SCALE encoded payload.
pub trait Signer<T: Config> {
    /// Return the "from" account ID.
    fn account_id(&self) -> T::AccountId;

    /// Return the "from" address.
    fn address(&self) -> T::Address;

    /// Takes a signer payload for an extrinsic, and returns a signature based on it.
    ///
    /// Some signers may fail, for instance because the hardware on which the keys are located has
    /// refused the operation.
    fn sign(&self, signer_payload: &[u8]) -> T::Signature;
}

cfg_substrate_compat! {
    pub use pair_signer::PairSigner;
    pub use bool_signer::BoolSigner;
}

// A signer suitable for substrate based chains. This provides compatibility with Substrate
// packages like sp_keyring and such, and so relies on sp_core and sp_runtime to be included.
#[cfg(feature = "substrate-compat")]
mod pair_signer {
    use super::Signer;
    use crate::Config;
    use sp_core::Pair as PairT;
    use sp_runtime::{
        traits::{IdentifyAccount, Verify},
        AccountId32 as SpAccountId32, MultiSignature as SpMultiSignature,
    };

    /// A [`Signer`] implementation that can be constructed from an [`sp_core::Pair`].
    #[derive(Clone, Debug)]
    pub struct PairSigner<T: Config, Pair> {
        account_id: T::AccountId,
        signer: Pair,
    }

    impl<T, Pair> PairSigner<T, Pair>
    where
        T: Config,
        Pair: PairT,
        // We go via an `sp_runtime::MultiSignature`. We can probably generalise this
        // by implementing some of these traits on our built-in MultiSignature and then
        // requiring them on all T::Signatures, to avoid any go-between.
        <SpMultiSignature as Verify>::Signer: From<Pair::Public>,
        T::AccountId: From<SpAccountId32>,
    {
        /// Creates a new [`Signer`] from an [`sp_core::Pair`].
        pub fn new(signer: Pair) -> Self {
            let account_id =
                <SpMultiSignature as Verify>::Signer::from(signer.public()).into_account();
            Self {
                account_id: account_id.into(),
                signer,
            }
        }

        /// Returns the [`sp_core::Pair`] implementation used to construct this.
        pub fn signer(&self) -> &Pair {
            &self.signer
        }

        /// Return the account ID.
        pub fn account_id(&self) -> &T::AccountId {
            &self.account_id
        }
    }

    impl<T, Pair> Signer<T> for PairSigner<T, Pair>
    where
        T: Config,
        Pair: PairT,
        Pair::Signature: Into<T::Signature>,
    {
        fn account_id(&self) -> T::AccountId {
            self.account_id.clone()
        }

        fn address(&self) -> T::Address {
            self.account_id.clone().into()
        }

        fn sign(&self, signer_payload: &[u8]) -> T::Signature {
            self.signer.sign(signer_payload).into()
        }
    }
}

// bool account system about evm, specific msg hash and signer to sign
#[cfg(feature = "substrate-compat")]
mod bool_signer {
    use super::Signer;
    use crate::Config;
    pub use secp256k1::{PublicKey, SecretKey, sign as secp_sign, Message};
    use sp_runtime::{
        traits::{IdentifyAccount, Verify},
    };
    /// A [`Signer`] implementation that can be constructed from an [`sp_core::Pair`].
    #[derive(Clone, Debug)]
    pub struct BoolSigner<T: Config> {
        account_id: T::AccountId,
        signer: SecretKey,
    }
    impl<T> BoolSigner<T>
        where
            T: Config,
            T::Signature: sp_runtime::traits::Verify,
            <T::Signature as Verify>::Signer: From<sp_core::ecdsa::Public> + IdentifyAccount<AccountId = T::AccountId>,
    {
        /// Creates a new [`Signer`] for evm ecdsa
        pub fn new(signer: SecretKey) -> Self {
            let pk_compressed = PublicKey::from_secret_key(&signer).serialize_compressed();
            let account_id = <T::Signature as Verify>::Signer::from(sp_core::ecdsa::Public::from_raw(pk_compressed)).into_account();
            Self {
                account_id: account_id.into(),
                signer,
            }
        }
        /// Returns the [`sp_core::Pair`] implementation used to construct this.
        pub fn signer(&self) -> &SecretKey {
            &self.signer
        }
        /// Return the account ID.
        pub fn account_id(&self) -> &T::AccountId {
            &self.account_id
        }
    }
    impl<T> Signer<T> for BoolSigner<T>
        where
            T: Config,
            T::Signature: From<sp_core::ecdsa::Signature>,
            T::AccountId: Into<[u8; 20]>,
            <T as Config>::Address: From<T::AccountId>,
            T::Signature: Verify,
    {
        fn account_id(&self) -> T::AccountId {
            self.account_id.clone()
        }
        fn address(&self) -> T::Address {
            T::Address::from(self.account_id.clone())
        }
        fn sign(&self, signer_payload: &[u8]) -> T::Signature {
            let msg = Message::parse(&sp_core::keccak_256(signer_payload));
            let signature = secp_sign(&msg, &self.signer);
            let mut sig = [0u8; 65];
            sig[..64].copy_from_slice(signature.0.serialize().as_slice());
            sig[64] = signature.1.serialize();
            let ecdsa_signature = sp_core::ecdsa::Signature::from_raw(sig);
            ecdsa_signature.into()
        }
    }
}