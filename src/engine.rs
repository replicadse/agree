use {
    crate::{
        archive::{
            Archive,
            Hash,
            SecretInfo,
            Share,
        },
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
    base64::Engine,
    ssss::SsssConfig,
    std::{
        fs,
        process::Stdio,
    },
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
            let share_data = Archive {
                version: "9f1e0683-7655-4f73-940a-38fa580b5725".to_owned(),
                uid: Uuid::new_v4().hyphenated().to_string(),
                name: z.0.name.clone(),
                comment: z.0.comment.clone(),
                info: if z.0.info.unwrap_or(false) {
                    Some(SecretInfo {
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

                        Share::EncryptedBase64 {
                            data: base64::engine::general_purpose::STANDARD
                                .encode(simplecrypt::encrypt(z.1.as_bytes(), pass.as_bytes())),
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

    pub async fn restore(&self, shares: &Vec<(String, Vec<u8>)>) -> Result<Vec<u8>> {
        let mut share_data = Vec::<String>::new();
        for s in shares {
            let archive = serde_yaml::from_str::<Archive>(&String::from_utf8(
                base64::engine::general_purpose::STANDARD.decode(&s.1)?,
            )?)?;

            let data = match archive.share {
                | Share::PlainBase64(v) => base64::engine::general_purpose::STANDARD.decode(v)?,
                | Share::EncryptedBase64 { hash, data } => {
                    let pw: String = dialoguer::Password::new()
                        .with_prompt(format!(
                            "Enter password for share (path: {}, name: {})",
                            &s.0,
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
#[serde(rename_all = "snake_case")]
pub(crate) struct Blueprint {
    pub threshold: usize,
    pub generate: Vec<BlueprintShare>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct BlueprintShare {
    pub path: String,
    pub name: Option<String>,
    pub encrypt: Option<BlueprintShareEncryption>,
    pub comment: Option<String>,
    pub info: Option<bool>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BlueprintShareEncryption {
    Plain(String),
    Shell(String),
}

impl BlueprintShareEncryption {
    pub fn exec(&self, trust: bool) -> Result<String> {
        match self {
            | BlueprintShareEncryption::Plain(pw) => Ok::<String, anyhow::Error>(pw.clone()),
            | BlueprintShareEncryption::Shell(pw) => {
                if !trust {
                    return Err(Error::NoTrust.into());
                }

                let mut cmd_proc = std::process::Command::new("sh");
                cmd_proc.arg("-c");
                cmd_proc.arg(pw);

                cmd_proc.stdin(Stdio::null());
                cmd_proc.stderr(Stdio::null());
                cmd_proc.stdout(Stdio::piped());
                let output = cmd_proc.spawn()?.wait_with_output()?;

                match output.status.code().unwrap() {
                    | 0 => Ok(String::from_utf8(output.stdout)?),
                    | _ => Err(Error::PasswordProvider.into()),
                }
            },
        }
    }
}
