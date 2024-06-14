use {
    crate::error::Error,
    anyhow::Result,
    std::process::Stdio,
};

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct Blueprint {
    pub threshold: usize,
    pub generate: Vec<BlueprintShare>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct BlueprintShare {
    pub path: String,
    pub encrypt: Option<BlueprintShareEncryption>,
    pub comment: Option<String>,
    pub info: Option<bool>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
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
