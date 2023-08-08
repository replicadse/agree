use {
    crate::{
        archive::{
            v1,
            VERSION_0_1,
            VERSION_ID_LEN,
        },
        blueprint::Blueprint,
        error::Error,
    },
    anyhow::Result,
    argon2::{
        password_hash::rand_core::{
            OsRng,
            RngCore,
        },
        PasswordHasher,
        PasswordVerifier,
    },
    base64::{
        engine::general_purpose::STANDARD,
        Engine,
    },
    ssss::SsssConfig,
    std::fs,
    uuid::Uuid,
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

    pub async fn generate(&self, secret_data: &Vec<u8>, blueprint: &Blueprint, trust: bool) -> Result<()> {
        let shares = ssss::gen_shares(
            &SsssConfig::default()
                .set_max_secret_size(secret_data.len())
                .set_num_shares(blueprint.generate.len() as u8)
                .set_threshold(blueprint.threshold as u8),
            &secret_data,
        )?;

        for z in blueprint.generate.iter().zip(shares) {
            let share_data = v1::Archive {
                uid: Uuid::new_v4().hyphenated().to_string(),
                name: z.0.name.clone(),
                comment: z.0.comment.clone(),
                info: if z.0.info.unwrap_or(false) {
                    Some(v1::SecretInfo {
                        num_shares: blueprint.generate.len(),
                        threshold: blueprint.threshold,
                    })
                } else {
                    None
                },
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

                        v1::Share::EncryptedBase64 {
                            data: STANDARD.encode(simplecrypt::encrypt(z.1.as_bytes(), pass.as_bytes())),
                            hash: v1::Hash::Argon2id(hash),
                        }
                    },
                    | None => {
                        let encoded_share = STANDARD.encode(z.1);
                        v1::Share::PlainBase64(encoded_share)
                    },
                },
            };
            let share_data_str = STANDARD.encode(serde_yaml::to_string(&share_data)?);

            fs::write(&z.0.path, format!("{}{}", VERSION_0_1, share_data_str))?;
        }
        Ok(())
    }

    pub async fn restore(&self, shares: &Vec<(String, Vec<u8>)>) -> Result<Vec<u8>> {
        let mut share_data = Vec::<String>::new();
        for s in shares {
            let version = String::from_utf8(s.1[0..VERSION_ID_LEN].to_vec())?;
            let data = &s.1[VERSION_ID_LEN..];
            match version.as_str() {
                | VERSION_0_1 => {
                    let archive = serde_yaml::from_str::<v1::Archive>(&String::from_utf8(STANDARD.decode(&data)?)?)?;
                    let data = match archive.share {
                        | v1::Share::PlainBase64(v) => STANDARD.decode(v)?,
                        | v1::Share::EncryptedBase64 { hash, data } => {
                            let pw: String = dialoguer::Password::new()
                                .with_prompt(format!(
                                    "Enter password for share (path: {}, name: {})",
                                    &s.0,
                                    archive.name.unwrap_or("{unknown}".to_owned())
                                ))
                                .interact()?;
                            match hash {
                                | v1::Hash::Argon2id(v) => {
                                    let pw_hash = argon2::PasswordHash::new(&v).or(Err(Error::PasswordVerification))?;
                                    self.argon
                                        .verify_password(pw.as_bytes(), &pw_hash)
                                        .or(Err(Error::PasswordVerification))?;
                                },
                            }
                            let data_dec = STANDARD.decode(data)?;
                            simplecrypt::decrypt(data_dec.as_slice(), pw.as_bytes())?
                        },
                    };
                    share_data.push(String::from_utf8(data)?);
                },
                | v => Err(Error::UnknownVersion(v.to_owned()))?,
            }
        }

        Ok(ssss::unlock(share_data.as_slice())?)
    }
}
