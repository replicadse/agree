use {
    crate::{
        blueprint::Blueprint,
        engine::SSS,
    }, anyhow::Result, args::{
        ClapArgumentLoader,
        Command,
        ManualFormat,
    }, blueprint::{
        BlueprintShare,
        BlueprintShareEncryption,
    }, fancy_regex::Regex, itertools::Itertools, std::{
        io::Write,
        path::PathBuf,
    }
};

pub(crate) mod archive;
pub(crate) mod args;
pub(crate) mod blueprint;
pub(crate) mod engine;
pub(crate) mod error;
pub(crate) mod reference;

fn get_version() -> String {
    env!("CARGO_PKG_VERSION").split(".").take(2).join(".").to_owned()
}

#[forbid(unsafe_code)]
#[tokio::main]
async fn main() -> Result<()> {
    let cmd = ClapArgumentLoader::load()?;

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
        | Command::Split {
            secret_data,
            blueprint,
            trust,
        } => {
            #[derive(serde::Deserialize)]
            struct WithVersion {
                version: String,
            }
            let version_check: WithVersion = serde_yaml::from_slice(&blueprint)?;
            let version_regex = Regex::new("^([0-9]+)\\.([0-9]+)$")?;
            if !version_regex.is_match(&version_check.version)? {
                return Err(error::Error::Parser(format!("invalid version: {}", version_check.version)).into());
            }
            let expected_version = env!("CARGO_PKG_VERSION").split(".").collect::<Vec<_>>()[..2].join(".");
            if env!("CARGO_PKG_VERSION") != "0.0.0" {
                // local debug
                if &version_check.version != &expected_version {
                    return Err(error::Error::VersionMismatch(version_check.version, expected_version).into());
                }
            }

            let blueprint: Blueprint = serde_yaml::from_slice(&blueprint)?;
            let engine = SSS::new(get_version());
            engine.generate(&secret_data, &blueprint, trust).await?;
            Ok(())
        },
        | Command::InteractiveSplit { secret_data } => {
            let threshold: usize = dialoguer::Input::new().with_prompt("Enter threshold").interact()?;
            println!("");
            let mut blueprint = Blueprint {
                threshold,
                generate: Vec::<_>::new(),
            };
            loop {
                println!("--- Entering share information ---");

                let path: String = dialoguer::Input::new().with_prompt("Save to file").interact()?;
                let with_secret_info = dialoguer::Confirm::new()
                    .with_prompt("Include secret info (num shares / threshold) in share?")
                    .interact()?;

                let with_comment = dialoguer::Confirm::new()
                    .with_prompt("Add comment to share?")
                    .interact()?;
                let comment: Option<String> = if with_comment {
                    Some(dialoguer::Input::new().with_prompt("Comment").interact()?)
                } else {
                    None
                };
                let with_encryption = dialoguer::Confirm::new()
                    .with_prompt("Encrypt share data with password?")
                    .interact()?;
                let password: Option<String> = if with_encryption {
                    Some(dialoguer::Password::new().with_prompt("Enter password").interact()?)
                } else {
                    None
                };
                let bp = BlueprintShare {
                    path,
                    encrypt: if let Some(p) = password {
                        Some(BlueprintShareEncryption::Plain(p))
                    } else {
                        None
                    },
                    info: Some(with_secret_info),
                    comment,
                };
                
                blueprint.generate.push(bp);
                println!("--- --- ---");
                println!("");
                if !dialoguer::Confirm::new().with_prompt("Add another share?").interact()? {
                    break;
                }
                println!("");
            }

            let engine = SSS::new(get_version());
            engine.generate(&secret_data, &blueprint, false).await?;

            Ok(())
        },
        | Command::InteractiveRestoreSecret { shares } => {
            let engine = SSS::new(get_version());
            let secret = engine.restore(&shares, true).await?;
            std::io::stdout().write_all(&secret)?;
            Ok(())
        },
        | Command::RestoreSecret { shares } => {
            let engine = SSS::new(get_version());
            let secret = engine.restore(&shares, false).await?;
            std::io::stdout().write_all(&secret)?;
            Ok(())
        },
        | Command::Info { share } => {
            let engine = SSS::new(get_version());
            let info = engine.info(&share.1).await?;
            println!("{}", serde_json::to_string(&info).unwrap());
            Ok(())
        },
    }
}

#[cfg(test)]
mod tests {
    use {
        crate::error::Error,
        anyhow::Result,
        std::{
            fs,
            process::Command,
        },
    };

    fn exec(command: &str) -> Result<String> {
        let output = Command::new("sh").arg("-c").arg(command).output()?;
        if output.status.code().unwrap() != 0 {
            return Err(Error::Shell(String::from_utf8(output.stderr)?).into());
        }
        Ok(String::from_utf8(output.stdout)?)
    }

    #[test]
    fn headless_split() {
        exec("cargo run -- split -b ./test/blueprint.yaml -s LICENSE --trust").unwrap();

        let alice = fs::read("./test/alice.share").unwrap();
        let bob = fs::read("./test/bob.share").unwrap();
        let charlie = fs::read("./test/charlie.share").unwrap();

        assert_ne!(alice, bob);
        assert_ne!(alice, charlie);
        assert_ne!(bob, charlie);
    }

    #[test]
    fn restore() {
        exec("cargo run -- split -b ./test/blueprint.yaml -s ./LICENSE --trust").unwrap();
        let out = exec("cargo run -- restore -s ./test/alice.share -s ./test/bob.share").unwrap();

        dbg!(&out);
        assert_eq!(out, fs::read_to_string("LICENSE").unwrap());
    }
}
