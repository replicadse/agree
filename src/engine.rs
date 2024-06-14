use {
    crate::{
        archive::{
            Archive, ArchiveData, Checksum, DataRepresentation, Hash, SecretInfo, Share, ShareInfo
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
    }, sha2::Digest, ssss::SsssConfig, std::{collections::HashSet, fs}, uuid::Uuid
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

        let pid = uuid::Uuid::new_v4().hyphenated().to_string();
        let mut hasher = sha2::Sha512::new();
        hasher.update(&secret_data);
        let checksum = format!("{:x}", hasher.finalize());
        for z in blueprint.generate.iter().zip(shares) {
            let archive = Archive {
                version: self.version.clone(),
                uid: Uuid::new_v4().hyphenated().to_string(),
                pid: pid.clone(),
                data: STANDARD.encode(serde_json::to_string(&ArchiveData {
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
                                pass_hash: Hash::Argon2id(hash),
                                checksum: Checksum::Sha512(checksum.clone()),
                            }
                        },
                        | None => {
                            Share::Plain(DataRepresentation::base64(z.1.into_bytes()), Checksum::Sha512(checksum.clone()),)
                        },
                    },
                    info: ShareInfo {
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
                }).unwrap()),
            };
            fs::write(&z.0.path, serde_json::to_string(&archive)?)?;
        }
        Ok(())
    }

    pub async fn restore(&self, shares: &Vec<(String, Vec<u8>)>, interactive: bool) -> Result<Vec<u8>> {
        let mut share_data = Vec::<String>::new();

        let mut ids = HashSet::<(String, Checksum)>::new();
        for s in shares {
            let archive = serde_json::from_str::<Archive>(&String::from_utf8(s.1.clone())?)?;
            let archive_data = serde_json::from_str::<ArchiveData>(&String::from_utf8(
                STANDARD.decode(&archive.data.as_bytes())?,
            )?)?;

            let data = match archive_data.share {
                | Share::Plain(v, checksum) => {
                    ids.insert((archive.pid.clone(), checksum.clone()));
                    v.decode()?
                },
                | Share::Encrypted { pass_hash: hash, data , checksum} => {
                    ids.insert((archive.pid.clone(), checksum.clone()));
                    if !interactive {
                        return Err(Error::NonInteractive.into());
                    }
                    let pw: String = dialoguer::Password::new()
                        .with_prompt(format!(
                            "Enter password for share at path: {}",
                            &s.0,
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
        if ids.len() != 1 {
            return Err(Error::MismatchedShares.into());
        }

        let res = ssss::unlock(share_data.as_slice())?;
        let confirm = ids.into_iter().next().unwrap();
        match confirm.1 {
            | Checksum::Sha512(v) => {
                let mut hasher = sha2::Sha512::new();
                hasher.update(&res);
                let hash = format!("{:x}", hasher.finalize());
                if hash != v {
                    return Err(Error::ChecksumFailed.into());
                }
            },
        }
        Ok(res)
    }

    pub async fn info(&self, share: &Vec<u8>) -> Result<Archive> {
        let archive = serde_json::from_str::<Archive>(&String::from_utf8(share.clone())?)?;

        Ok(archive)
    }
}
