use std::fs;

use anyhow::Result;
use argon2::{
    password_hash::rand_core::{OsRng, RngCore},
    PasswordHasher, PasswordVerifier,
};
use base64::Engine;
use ssss::SsssConfig;

use crate::{
    archive::{Archive, Hash, SecretInfo, Share},
    error::Error,
};

pub(crate) struct SSS<'x> {
    pub argon: argon2::Argon2<'x>,
}

impl<'x> SSS<'x> {
    pub fn new() -> Self {
        Self {
            argon: argon2::Argon2::new(
                argon2::Algorithm::Argon2id,
                argon2::Version::V0x13,
                argon2::Params::new(2048, 32, 64, None).unwrap(),
            ),
        }
    }

    pub async fn generate(&self, secret_data: &Vec<u8>, blueprint: &ShareGenBlueprint) -> Result<()> {
        let shares = ssss::gen_shares(
            &SsssConfig::default()
                .set_max_secret_size(secret_data.len())
                .set_num_shares(blueprint.generate.len() as u8)
                .set_threshold(blueprint.threshold as u8),
            &secret_data,
        )?;

        for z in blueprint.generate.iter().zip(shares) {
            let share_data = Archive {
                version: "9f1e0683-7655-4f73-940a-38fa580b5725".to_owned(),
                name: z.0.name.clone(),
                comment: z.0.comment.clone(),
                info: if z.0.info {
                    Some(SecretInfo {
                        num_shares: blueprint.generate.len(),
                        threshold: blueprint.threshold,
                    })
                } else {
                    None
                },
                share: match &z.0.password {
                    | Some(pw) => {
                        let mut salt = [0u8; 32];
                        OsRng::default().fill_bytes(&mut salt);
                        let hash = self
                            .argon
                            .hash_password(
                                pw.as_bytes(),
                                argon2::password_hash::SaltString::encode_b64(&salt).unwrap().as_salt(),
                            )
                            .unwrap()
                            .serialize()
                            .to_string();

                        Share::EncryptedBase64 {
                            data: base64::engine::general_purpose::STANDARD
                                .encode(simplecrypt::encrypt(z.1.as_bytes(), pw.as_bytes())),
                            hash: Hash::Argon2id(hash),
                        }
                    },
                    | None => {
                        let encoded_share = base64::engine::general_purpose::STANDARD.encode(z.1);
                        Share::PlainBase64(encoded_share)
                    },
                },
            };
            let share_data_str = base64::engine::general_purpose::STANDARD.encode(serde_yaml::to_string(&share_data)?);

            fs::write(&z.0.path, share_data_str)?;
        }

        Ok(())
    }

    pub async fn restore(&self, shares: Vec<Vec<u8>>) -> Result<Vec<u8>> {
        let mut share_data = Vec::<String>::new();
        for s in shares {
            let archive = serde_yaml::from_str::<Archive>(&String::from_utf8(
                base64::engine::general_purpose::STANDARD.decode(s)?,
            )?)?;

            let data = match archive.share {
                | Share::PlainBase64(v) => base64::engine::general_purpose::STANDARD.decode(v)?,
                | Share::EncryptedBase64 { hash, data } => {
                    let pw: String = dialoguer::Password::new()
                        .with_prompt(format!(
                            "Enter password for share (name: {})",
                            archive.name.unwrap_or("{unknown}".to_owned())
                        ))
                        .interact()?;
                    match hash {
                        | Hash::Argon2id(v) => {
                            let pw_hash = argon2::PasswordHash::new(&v).or(Err(Error::PasswordVerification))?;
                            self.argon
                                .verify_password(pw.as_bytes(), &pw_hash)
                                .or(Err(Error::PasswordVerification))?;
                        },
                    }
                    let data_dec = base64::engine::general_purpose::STANDARD.decode(data)?;
                    simplecrypt::decrypt(data_dec.as_slice(), pw.as_bytes())?
                },
            };
            share_data.push(String::from_utf8(data)?);
        }

        Ok(ssss::unlock(share_data.as_slice())?)
    }
}

#[derive(Debug, serde::Deserialize)]
pub(crate) struct ShareGenBlueprint {
    pub threshold: usize,
    pub generate: Vec<ShareGenInfo>,
}
#[derive(Debug, serde::Deserialize)]
pub(crate) struct ShareGenInfo {
    pub path: String,
    pub name: Option<String>,
    pub password: Option<String>,
    pub comment: Option<String>,
    pub info: bool,
}
