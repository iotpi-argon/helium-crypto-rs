use crate::{
    ecc_compact::{self, Signature},
    keypair, public_key, Error, KeyTag, KeyType as CrateKeyType, Network, Result,
};
use p256::{ecdsa, elliptic_curve};
use sha2::{Digest, Sha256};
use std::convert::{TryFrom, TryInto};

pub use iotpi_helium_optee;

pub struct Keypair {
    pub network: Network,
    pub public_key: public_key::PublicKey,
    slot: u8,
}

impl PartialEq for Keypair {
    fn eq(&self, other: &Self) -> bool {
        self.public_key == other.public_key
    }
}

impl std::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        f.debug_struct("Keypair")
            .field("public", &self.public_key)
            .finish()
    }
}

impl keypair::Sign for Keypair {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        use signature::Signer;
        let signature = self.try_sign(msg)?;
        Ok(signature.to_vec())
    }
}

impl signature::Signer<Signature> for Keypair {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Signature, signature::Error> {
        let digest = Sha256::digest(msg);
        let sign_result = iotpi_helium_optee::ecdsa_sign_digest(self.slot, &digest);
        match sign_result {
            Ok(bytes) => {
                let signature = ecdsa::Signature::try_from(&bytes[..])?;
                println!("tee signature: {:?}", signature);
                Ok(Signature(signature))
            }
            Err(err) => Err(signature::Error::from_source(err)),
        }
    }
}

impl Keypair {
    pub fn keypair(slot: u8) -> Self {
        let pubkey = iotpi_helium_optee::publickey(slot).expect("failed to get tee public key");
        let mut key_bytes = vec![4u8];
        key_bytes.extend_from_slice(&pubkey.0);
        key_bytes.extend_from_slice(&pubkey.1);
        let keypair_pubkey = ecc_compact::PublicKey::try_from(key_bytes.as_ref())
            .expect("failed to covert to ecc_compact::PublicKey");
        let public_key = public_key::PublicKey::for_network(Network::MainNet, keypair_pubkey);
        let keypair = Keypair {
            network: Network::MainNet,
            public_key,
            slot,
        };

        return keypair;
    }

    pub fn key_tag(&self) -> KeyTag {
        KeyTag {
            network: self.network,
            key_type: CrateKeyType::EccCompact,
        }
    }

    pub fn ecdh<'a, C>(&self, public_key: C) -> Result<ecc_compact::SharedSecret>
    where
        C: TryInto<&'a ecc_compact::PublicKey, Error = Error>,
    {
        use elliptic_curve::sec1::ToEncodedPoint;
        let key = public_key.try_into()?;
        let point = key.0.to_encoded_point(false);
        println!("point: {:?}", &point);
        let shared_secret_bytes =
            iotpi_helium_optee::ecdh(self.slot, point.x().unwrap(), point.y().unwrap())?;
        Ok(ecc_compact::SharedSecret(p256::ecdh::SharedSecret::from(
            *p256::FieldBytes::from_slice(&shared_secret_bytes),
        )))
    }
}
