use {
    crate::{
        archive::{
            self, Archive, ArchiveInfo, DataRepresentation, Hash, SecretInfo, Share
        },
        blueprint::Blueprint,
        error::Error,
    }, anyhow::Result, argon2::{
        password_hash::rand_core::{
            OsRng,
            RngCore,
        },
        PasswordHasher,
        PasswordVerifier,
    }, base64::{
        engine::general_purpose::STANDARD,
        Engine,
    }, ssss::SsssConfig, std::fs, uuid::Uuid
};

pub(crate) struct SSS<'x> {
    pub version: String,
    pub argon: argon2::Argon2<'x>,
}

impl<'x> SSS<'x> {
    pub fn new(version: String) -> Self {
        Self {
            version,
            argon: argon2::Argon2::new(
                argon2::Algorithm::Argon2id,
                argon2::Version::V0x13,
                argon2::Params::new(2048, 32, 64, None).unwrap(),
            ),
        }
    }

    pub async fn generate(&self, secret_data: &Vec<u8>, blueprint: &Blueprint, trust: bool) -> Result<()> {
        let shares = ssss::gen_shares(
            &SsssConfig::default()
                .set_max_secret_size(secret_data.len())
                .set_num_shares(blueprint.generate.len() as u8)
                .set_threshold(blueprint.threshold as u8),
            &secret_data,
        )?;

        for z in blueprint.generate.iter().zip(shares) {
            let share_data = Archive {
                uid: Uuid::new_v4().hyphenated().to_string(),
                share: match &z.0.encrypt {
                    | Some(enc) => {
                        let mut salt = [0u8; 32];
                        OsRng::default().fill_bytes(&mut salt);
                        let pass = enc.exec(trust)?;
                        let hash = self
                            .argon
                            .hash_password(
                                pass.as_bytes(),
                                argon2::password_hash::SaltString::encode_b64(&salt).unwrap().as_salt(),
                            )
                            .unwrap()
                            .serialize()
                            .to_string();

                        Share::Encrypted {
                            data: DataRepresentation::base64(simplecrypt::encrypt(z.1.as_bytes(), pass.as_bytes())),
                            hash: Hash::Argon2id(hash),
                        }
                    },
                    | None => {
                        Share::Plain(DataRepresentation::base64(z.1.into_bytes()))
                    },
                },
                info: ArchiveInfo {
                    name: z.0.name.clone(),
                    comment: z.0.comment.clone(),
                    secret: if z.0.info.unwrap_or(false) {
                        Some(SecretInfo {
                            num_shares: blueprint.generate.len(),
                            threshold: blueprint.threshold,
                        })
                    } else {
                        None
                    },
                }
            };
            let share_data_str = STANDARD.encode(serde_json::to_string(&share_data)?);

            fs::write(&z.0.path, format!("#v{}#{}", self.version, share_data_str))?;
        }
        Ok(())
    }

    pub async fn restore(&self, shares: &Vec<(String, Vec<u8>)>, interactive: bool) -> Result<Vec<u8>> {
        let mut share_data = Vec::<String>::new();
        for s in shares {
            let revision_and_data = archive::split_version_and_data(&s.1)?;
            if &revision_and_data.0 != &self.version {
                return Err(Error::VersionMismatch(self.version.to_owned(), revision_and_data.0).into());
            }
            let archive = serde_json::from_str::<Archive>(&String::from_utf8(STANDARD.decode(&revision_and_data.1)?)?)?;
            let data = match archive.share {
                | Share::Plain(v) => v.decode()?,
                | Share::Encrypted { hash, data } => {
                    if !interactive {
                        return Err(Error::NonInteractive.into());
                    }
                    let pw: String = dialoguer::Password::new()
                        .with_prompt(format!(
                            "Enter password for share (path: {}, name: {})",
                            &s.0,
                            archive.info.name.unwrap_or("{unknown}".to_owned())
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

                    String::from_utf8(simplecrypt::decrypt(data.decode()?.as_bytes(), pw.as_bytes())?).unwrap()
                },
            };
            share_data.push(data);
        }

        Ok(ssss::unlock(share_data.as_slice())?)
    }

    pub async fn info(&self, share: &Vec<u8>) -> Result<Archive> {
        let revision_and_data = archive::split_version_and_data(&share)?;
        if &revision_and_data.0 != &self.version {
            return Err(Error::VersionMismatch(self.version.to_owned(), revision_and_data.0).into());
        }
        Ok(serde_json::from_str::<Archive>(&String::from_utf8(
            STANDARD.decode(&revision_and_data.1)?,
        )?)?)
    }
}
