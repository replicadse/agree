use crate::engine::{ShareGenBlueprint, SSS};

use {
    anyhow::Result,
    args::{ClapArgumentLoader, Command, ManualFormat},
    engine::ShareGenInfo,
    std::{io::Write, path::PathBuf},
};

pub(crate) mod archive;
pub(crate) mod args;
pub(crate) mod engine;
pub(crate) mod error;
pub(crate) mod reference;

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
        | Command::Split { secret_data, blueprint } => {
            let blueprint: ShareGenBlueprint = serde_yaml::from_slice(&blueprint)?;
            let engine = SSS::new();
            engine.generate(&secret_data, &blueprint).await?;
            Ok(())
        },
        | Command::InteractiveSplit { secret_data } => {
            let threshold: usize = dialoguer::Input::new().with_prompt("Enter threshold").interact()?;
            println!("");
            let mut blueprint = ShareGenBlueprint {
                threshold,
                generate: Vec::<_>::new(),
            };
            loop {
                println!("--- Entering share information ---");
                blueprint.generate.push(ask_for_share_data().await?);
                println!("--- --- ---");
                println!("");
                if !dialoguer::Confirm::new().with_prompt("Add another share?").interact()? {
                    break;
                }
                println!("");
            }

            let engine = SSS::new();
            engine.generate(&secret_data, &blueprint).await?;

            Ok(())
        },
        | Command::InteractiveRestoreSecret { shares } => {
            let engine = SSS::new();
            let secret = engine.restore(shares).await?;
            std::io::stdout().write_all(&secret)?;
            Ok(())
        },
    }
}

async fn ask_for_share_data() -> Result<ShareGenInfo> {
    let path: String = dialoguer::Input::new().with_prompt("Save to file").interact()?;

    let with_name = dialoguer::Confirm::new()
        .with_prompt("Include name in share?")
        .interact()?;
    let name: Option<String> = if with_name {
        Some(dialoguer::Input::new().with_prompt("Name").interact()?)
    } else {
        None
    };

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
        .with_prompt("Encrypt payload with password?")
        .interact()?;
    let password: Option<String> = if with_encryption {
        Some(dialoguer::Password::new().with_prompt("Enter password").interact()?)
    } else {
        None
    };

    Ok(ShareGenInfo {
        name,
        path,
        password,
        with_secret_info,
        comment,
    })
}
