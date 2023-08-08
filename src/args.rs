use {
    crate::error::Error,
    anyhow::Result,
    clap::{
        Arg,
        ArgAction,
    },
    itertools::Itertools,
    std::{
        fs,
        str::FromStr,
    },
};

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Privilege {
    Normal,
    Experimental,
}

#[derive(Debug)]
pub(crate) struct CallArgs {
    pub privileges: Privilege,
    pub command: Command,
}

impl CallArgs {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.privileges == Privilege::Experimental {
            return Ok(());
        }

        match &self.command {
            // | Command::Plan { .. } => Err(Box::new(Error::ExperimentalCommand)),
            | _ => Ok(()),
        }
    }
}

#[derive(Debug)]
pub(crate) enum ManualFormat {
    Manpages,
    Markdown,
}

#[derive(Debug)]
pub(crate) enum Command {
    Manual {
        path: String,
        format: ManualFormat,
    },
    Autocomplete {
        path: String,
        shell: clap_complete::Shell,
    },
    InteractiveSplit {
        secret_data: Vec<u8>,
    },
    Split {
        secret_data: Vec<u8>,
        blueprint: Vec<u8>,
        trust: bool,
    },
    InteractiveRestoreSecret {
        shares: Vec<(String, Vec<u8>)>,
    },
}

pub(crate) struct ClapArgumentLoader {}

impl ClapArgumentLoader {
    pub(crate) fn root_command() -> clap::Command {
        clap::Command::new("agree")
            .version(env!("CARGO_PKG_VERSION"))
            .about("A makefile alternative / task runner.")
            .author("Alexander Weber <alexanderh.weber@outlook.com>")
            .propagate_version(true)
            .subcommand_required(true)
            .args([Arg::new("experimental")
                .short('e')
                .long("experimental")
                .help("Enables experimental features.")
                .num_args(0)])
            .subcommand(
                clap::Command::new("man")
                    .about("Renders the manual.")
                    .arg(clap::Arg::new("out").short('o').long("out").required(true))
                    .arg(
                        clap::Arg::new("format")
                            .short('f')
                            .long("format")
                            .value_parser(["manpages", "markdown"])
                            .required(true),
                    ),
            )
            .subcommand(
                clap::Command::new("autocomplete")
                    .about("Renders shell completion scripts.")
                    .arg(clap::Arg::new("out").short('o').long("out").required(true))
                    .arg(
                        clap::Arg::new("shell")
                            .short('s')
                            .long("shell")
                            .value_parser(["bash", "zsh", "fish", "elvish", "powershell"])
                            .required(true),
                    ),
            )
            .subcommand(
                clap::Command::new("interactive")
                    .subcommand_required(true)
                    .alias("int")
                    .subcommand(
                        clap::Command::new("split").about("Split a secret.").arg(
                            clap::Arg::new("secret")
                                .long("secret")
                                .short('s')
                                .help("Path to the file containing the secret.")
                                .required(true),
                        ),
                    )
                    .subcommand(
                        clap::Command::new("restore")
                            .about("Restores a secret from shares.")
                            .arg(
                                clap::Arg::new("share")
                                    .long("share")
                                    .short('s')
                                    .help("Path to a share file.")
                                    .required(true)
                                    .action(ArgAction::Append),
                            ),
                    ),
            )
            .subcommand(
                clap::Command::new("headless")
                    .subcommand_required(true)
                    .alias("hl")
                    .subcommand(
                        clap::Command::new("split")
                            .about("Split a secret.")
                            .arg(
                                clap::Arg::new("secret")
                                    .long("secret")
                                    .short('s')
                                    .help("Path to the file containing the secret.")
                                    .required(true),
                            )
                            .arg(
                                clap::Arg::new("blueprint")
                                    .long("blueprint")
                                    .short('b')
                                    .help("Path to the blueprint file.")
                                    .required(true),
                            )
                            .arg(
                                clap::Arg::new("trust")
                                    .long("trust")
                                    .short('t')
                                    .help("Allow shell invocations from blueprint scripts.")
                                    .num_args(0),
                            ),
                    ),
            )
    }

    pub(crate) fn load() -> Result<CallArgs> {
        let command = Self::root_command().get_matches();

        let privileges = if command.get_flag("experimental") {
            Privilege::Experimental
        } else {
            Privilege::Normal
        };

        let cmd = if let Some(subc) = command.subcommand_matches("man") {
            Command::Manual {
                path: subc.get_one::<String>("out").unwrap().into(),
                format: match subc.get_one::<String>("format").unwrap().as_str() {
                    | "manpages" => ManualFormat::Manpages,
                    | "markdown" => ManualFormat::Markdown,
                    | _ => return Err(Error::Argument("unknown format".into()).into()),
                },
            }
        } else if let Some(subc) = command.subcommand_matches("autocomplete") {
            Command::Autocomplete {
                path: subc.get_one::<String>("out").unwrap().into(),
                shell: clap_complete::Shell::from_str(subc.get_one::<String>("shell").unwrap().as_str()).unwrap(),
            }
        } else if let Some(subc) = command.subcommand_matches("interactive") {
            if let Some(subc) = subc.subcommand_matches("split") {
                Command::InteractiveSplit {
                    secret_data: fs::read(subc.get_one::<String>("secret").unwrap())?,
                }
            } else if let Some(subc) = subc.subcommand_matches("restore") {
                Command::InteractiveRestoreSecret {
                    shares: subc
                        .get_many::<String>("share")
                        .unwrap()
                        .map(|v| (v.clone(), fs::read(v).unwrap()))
                        .collect_vec(),
                }
            } else {
                return Err(Error::UnknownCommand.into());
            }
        } else if let Some(subc) = command.subcommand_matches("headless") {
            if let Some(subc) = subc.subcommand_matches("split") {
                Command::Split {
                    secret_data: fs::read(subc.get_one::<String>("secret").unwrap())?,
                    blueprint: fs::read(subc.get_one::<String>("blueprint").unwrap())?,
                    trust: subc.get_flag("trust"),
                }
            } else {
                return Err(Error::UnknownCommand.into());
            }
        } else {
            return Err(Error::UnknownCommand.into());
        };

        let callargs = CallArgs {
            privileges,
            command: cmd,
        };

        callargs.validate()?;
        Ok(callargs)
    }
}
