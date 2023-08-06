use {
    crate::archive::Payload,
    anyhow::Result,
    archive::{
        Archive,
        Hash,
        SecretInfo,
    },
    argon2::{
        password_hash::rand_core::{
            OsRng,
            RngCore,
        },
        PasswordHasher,
        PasswordVerifier,
    },
    args::{
        ClapArgumentLoader,
        Command,
        ManualFormat,
    },
    base64::Engine,
    error::Error,
    ssss::SsssConfig,
    std::{
        fs,
        io::Write,
        path::PathBuf,
    },
};

pub(crate) mod archive;
pub(crate) mod args;
pub(crate) mod error;
pub(crate) mod reference;

#[tokio::main]
async fn main() -> Result<()> {
    let cmd = ClapArgumentLoader::load()?;

    let argon = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(2048, 32, 64, None).unwrap(),
    );

    match cmd.command {
        | Command::Manual { path, format } => {
            let out_path = PathBuf::from(path);
            std::fs::create_dir_all(&out_path)?;
            match format {
                | ManualFormat::Manpages => {
                    reference::build_manpages(&out_path)?;
                },
                | ManualFormat::Markdown => {
                    reference::build_markdown(&out_path)?;
                },
            }
            Ok(())
        },
        | Command::Autocomplete { path, shell } => {
            let out_path = PathBuf::from(path);
            std::fs::create_dir_all(&out_path)?;
            reference::build_shell_completion(&out_path, &shell)?;
            Ok(())
        },
        | Command::RestoreSecret { shares } => {
            let mut share_data = Vec::<String>::new();
            for s in shares {
                let archive = serde_yaml::from_str::<Archive>(&String::from_utf8(
                    base64::engine::general_purpose::STANDARD.decode(s)?,
                )?)?;

                let data = match archive.payload {
                    | Payload::PlainBase64(v) => base64::engine::general_purpose::STANDARD.decode(v)?,
                    | Payload::EncryptedBase64 { hash, data } => {
                        let pw: String = dialoguer::Password::new()
                            .with_prompt(format!(
                                "Enter password for share (name: {})",
                                archive.name.unwrap_or("{unknown}".to_owned())
                            ))
                            .interact()?;
                        match hash {
                            | Hash::Argon2id(v) => {
                                let pw_hash = argon2::PasswordHash::new(&v).or(Err(Error::PasswordVerification))?;
                                argon
                                    .verify_password(pw.as_bytes(), &pw_hash)
                                    .or(Err(Error::PasswordVerification))?;
                            },
                        }
                        let data_dec = base64::engine::general_purpose::STANDARD.decode(data)?;
                        simplecrypt::decrypt(data_dec.as_slice(), pw.as_bytes())?
                    },
                };
                let data_str = String::from_utf8(data)?;
                share_data.push(data_str);
            }

            let secret = ssss::unlock(share_data.as_slice())?;
            std::io::stdout().write_all(&secret)?;
            Ok(())
        },
        | Command::InteractiveSplit { secret_data } => {
            let threshold: usize = dialoguer::Input::new().with_prompt("Enter threshold").interact()?;
            println!("");
            let mut share_infos = Vec::<ShareDataPrompt>::new();
            loop {
                println!("--- Entering share information ---");
                share_infos.push(ask_for_share_data().await?);
                println!("--- --- ---");
                println!("");
                if !dialoguer::Confirm::new().with_prompt("Add another share?").interact()? {
                    break;
                }
                println!("");
            }

            let shares = ssss::gen_shares(
                &SsssConfig::default()
                    .set_max_secret_size(secret_data.len())
                    .set_num_shares(share_infos.len() as u8)
                    .set_threshold(threshold as u8),
                &secret_data,
            )?;

            for z in share_infos.iter().zip(shares) {
                let share_data = Archive {
                    version: "9f1e0683-7655-4f73-940a-38fa580b5725".to_owned(),
                    name: if z.0.with_name { Some(z.0.name.clone()) } else { None },
                    comment: z.0.with_comment.clone(),
                    secret: if z.0.with_info {
                        Some(SecretInfo {
                            num_shares: share_infos.len(),
                            threshold,
                        })
                    } else {
                        None
                    },
                    payload: match &z.0.password {
                        | Some(pw) => {
                            let mut salt = [0u8; 32];
                            OsRng::default().fill_bytes(&mut salt);
                            let hash = argon
                                .hash_password(
                                    pw.as_bytes(),
                                    argon2::password_hash::SaltString::encode_b64(&salt).unwrap().as_salt(),
                                )
                                .unwrap()
                                .serialize()
                                .to_string();

                            Payload::EncryptedBase64 {
                                data: base64::engine::general_purpose::STANDARD
                                    .encode(simplecrypt::encrypt(z.1.as_bytes(), pw.as_bytes())),
                                hash: archive::Hash::Argon2id(hash),
                            }
                        },
                        | None => {
                            let encoded_payload = base64::engine::general_purpose::STANDARD.encode(z.1);
                            Payload::PlainBase64(encoded_payload)
                        },
                    },
                };
                let share_data_str =
                    base64::engine::general_purpose::STANDARD.encode(serde_yaml::to_string(&share_data)?);

                fs::write(&z.0.path, share_data_str)?;
            }

            Ok(())
        },
    }
}

#[derive(Debug)]
struct ShareDataPrompt {
    name: String,
    path: String,
    password: Option<String>,
    with_name: bool,
    with_info: bool,
    with_comment: Option<String>,
}
async fn ask_for_share_data() -> Result<ShareDataPrompt> {
    let name: String = dialoguer::Input::new().with_prompt("Name").interact()?;
    let path: String = dialoguer::Input::new()
        .with_prompt("Save to file")
        .with_initial_text(&name)
        .interact()?;
    let with_name = dialoguer::Confirm::new()
        .with_prompt("Include name in share?")
        .interact()?;
    let with_info = dialoguer::Confirm::new()
        .with_prompt("Include secret info (num shares / threshold) in share?")
        .interact()?;

    let add_comment = dialoguer::Confirm::new()
        .with_prompt("Add comment to share?")
        .interact()?;
    let with_comment: Option<String> = if add_comment {
        Some(dialoguer::Input::new().with_prompt("Comment").interact()?)
    } else {
        None
    };

    let with_encryption = dialoguer::Confirm::new()
        .with_prompt("Encrypt payload with password?")
        .interact()?;
    let password: Option<String> = if with_encryption {
        Some(dialoguer::Password::new().with_prompt("Enter password").interact()?)
    } else {
        None
    };

    Ok(ShareDataPrompt {
        name,
        path,
        password,
        with_name,
        with_info,
        with_comment,
    })
}
