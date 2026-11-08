//! Explicit signer authorization. GPG verifies signatures; SQLite grants trust.
use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use rusqlite::{params, Connection, OpenFlags};
use tempfile::TempDir;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub const MAX_KEY_BYTES: usize = 1024 * 1024;
pub fn error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    io::Error::other(message.into()).into()
}

pub fn data_dir() -> Result<PathBuf> {
    let base = if let Some(path) = env::var_os("XDG_DATA_HOME") {
        PathBuf::from(path)
    } else {
        PathBuf::from(env::var_os("HOME").ok_or_else(|| error("HOME is not set"))?)
            .join(".local/share")
    };
    if !base.is_absolute() {
        return Err(error("the data directory must be absolute"));
    }
    Ok(base.join("git-safe"))
}

pub fn private_dir(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if !meta.is_dir() || meta.permissions().mode() & 0o077 != 0 {
                return Err(error(format!(
                    "{} must be a private directory (mode 700)",
                    path.display()
                )));
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(path)?;
        }
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

pub fn fingerprint(value: &str) -> Result<String> {
    if !matches!(value.len(), 40 | 64) || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(error(
            "use a full primary-key fingerprint (40 or 64 hexadecimal characters)",
        ));
    }
    Ok(value.to_ascii_uppercase())
}

fn identifier(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err(error(
            "signer ID must contain 1–64 letters, digits, dots, underscores, or hyphens",
        ));
    }
    Ok(())
}

pub struct Keyring {
    pub home: TempDir,
}
impl Keyring {
    pub fn new() -> Result<Self> {
        let home = tempfile::tempdir()?;
        fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700))?;
        Ok(Self { home })
    }
    pub fn command(&self) -> Command {
        let mut cmd = Command::new("/usr/bin/gpg");
        cmd.args([
            "--no-options",
            "--batch",
            "--no-tty",
            "--no-autostart",
            "--no-auto-key-retrieve",
            "--auto-key-locate",
            "clear",
            "--homedir",
        ])
        .arg(self.home.path());
        cmd
    }
    pub fn import(&self, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() || bytes.len() > MAX_KEY_BYTES {
            return Err(error("public-key file is empty or exceeds 1 MiB"));
        }
        let out = with_input(self.command().args(["--status-fd", "1", "--import"]), bytes)?;
        let status = String::from_utf8_lossy(&out.stdout);
        let secret = status.lines().any(|line| {
            line.strip_prefix("[GNUPG:] IMPORT_OK ")
                .and_then(|v| v.split_whitespace().next())
                .and_then(|v| v.parse::<u32>().ok())
                .is_some_and(|flags| flags & 16 != 0)
        });
        if secret || !out.status.success() {
            return Err(error(
                "cannot import public key (secret-key material is not accepted)",
            ));
        }
        let secret_list = self
            .command()
            .args(["--with-colons", "--list-secret-keys"])
            .output()?;
        if String::from_utf8_lossy(&secret_list.stdout)
            .lines()
            .any(|l| l.starts_with("sec:"))
        {
            return Err(error("secret-key material is not accepted"));
        }
        Ok(())
    }
    pub fn primary_keys(&self) -> Result<Vec<String>> {
        let out = self
            .command()
            .args(["--with-colons", "--list-keys"])
            .output()?;
        if !out.status.success() {
            return Err(error("cannot inspect public keys"));
        }
        let mut keys = Vec::new();
        let mut primary = false;
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let parts: Vec<_> = line.split(':').collect();
            match parts[0] {
                "pub" => primary = true,
                "sub" => primary = false,
                "fpr" if primary => {
                    keys.push(fingerprint(parts.get(9).copied().unwrap_or(""))?);
                    primary = false;
                }
                _ => {}
            }
        }
        Ok(keys)
    }
    pub fn export(&self, fpr: &str) -> Result<Vec<u8>> {
        let out = self.command().args(["--armor", "--export", fpr]).output()?;
        if !out.status.success() || out.stdout.is_empty() {
            return Err(error("cannot export public key"));
        }
        if out.stdout.len() > MAX_KEY_BYTES {
            return Err(error("public-key export exceeds 1 MiB"));
        }
        Ok(out.stdout)
    }
}

fn with_input(cmd: &mut Command, input: &[u8]) -> Result<Output> {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| error("missing GPG input pipe"))?;
    let bytes = input.to_vec();
    let writer = std::thread::spawn(move || stdin.write_all(&bytes));
    let output = child.wait_with_output()?;
    writer
        .join()
        .map_err(|_| error("GPG input thread failed"))??;
    Ok(output)
}

pub fn inspect(bytes: &[u8]) -> Result<(String, Vec<u8>)> {
    let ring = Keyring::new()?;
    ring.import(bytes)?;
    let keys = ring.primary_keys()?;
    if keys.len() != 1 {
        return Err(error(
            "provide exactly one primary public key, including its subkeys",
        ));
    }
    Ok((keys[0].clone(), ring.export(&keys[0])?))
}

pub fn read_key(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take((MAX_KEY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_KEY_BYTES {
        return Err(error("public-key file exceeds 1 MiB"));
    }
    Ok(bytes)
}

pub fn export_personal(fpr: &str) -> Result<Vec<u8>> {
    let fpr = fingerprint(fpr)?;
    // This intentionally uses the user's normal GPG home; only --export, never
    // --export-secret-keys. Normalize through an isolated public-only keyring.
    let out = Command::new("/usr/bin/gpg")
        .args(["--no-options", "--batch", "--armor", "--export", &fpr])
        .output()?;
    if !out.status.success() {
        return Err(error("GPG public-key export failed"));
    }
    let (actual, bytes) = inspect(&out.stdout)?;
    if actual != fpr {
        return Err(error(
            "select the primary fingerprint, not a signing subkey",
        ));
    }
    Ok(bytes)
}

// Called by the installer as the regular user, outside sudo.
fn trust_own() -> Result<()> {
    let output = Command::new("/usr/bin/gpg")
        .args(["--no-options", "--batch", "--with-colons", "--list-secret-keys"])
        .output()?;
    if !output.status.success() {
        return Err(error("cannot discover your GPG signing keys"));
    }
    let mut primary = false;
    let mut count = 0;
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let fields: Vec<_> = line.split(':').collect();
        match fields[0] {
            "sec" => {
                primary = !matches!(fields.get(1).copied(), Some("r" | "e" | "d" | "i"))
                    && fields.get(11).is_some_and(|caps| caps.contains('S'));
            }
            "ssb" => primary = false,
            "fpr" if primary => {
                primary = false;
                let fpr = fingerprint(fields.get(9).copied().unwrap_or(""))?;
                let bytes = export_personal(&fpr)?;
                let db = open_store()?;
                let id = match db.query_row(
                    "SELECT id FROM signers WHERE fingerprint=?1", [&fpr],
                    |row| row.get::<_, String>(0),
                ) {
                    Ok(id) => id,
                    Err(rusqlite::Error::QueryReturnedNoRows) => fpr.clone(),
                    Err(err) => return Err(err.into()),
                };
                drop(db);
                import_signer(&id, &bytes, Some(&fpr), true)?;
                count += 1;
            }
            _ => {}
        }
    }
    println!("Registered {count} own signing key(s).");
    if count == 0 {
        println!("No usable GPG signing keys found. After creating one, run: git-safe keys trust-own");
    }
    Ok(())
}

fn open_store() -> Result<Connection> {
    let dir = data_dir()?;
    private_dir(&dir)?;
    let path = dir.join("trust.sqlite3");
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
    {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            if !fs::symlink_metadata(&path)?.is_file() {
                return Err(error("trust database must be a regular file"));
            }
        }
        Err(e) => return Err(e.into()),
    }
    let db = Connection::open(path)?;
    db.busy_timeout(std::time::Duration::from_secs(5))?;
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS signers (
        id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL UNIQUE, public_key BLOB NOT NULL,
        updated_at INTEGER NOT NULL DEFAULT (unixepoch()));",
    )?;
    Ok(db)
}

/// Bound terminal input and keep peer cancellation responsive even while the
/// terminal is waiting for a line. A cancelled command exits the process, so an
/// input worker that is still blocked cannot survive the command.
pub fn input_line(limit: u64) -> Result<String> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = io::stdin()
            .lock()
            .take(limit + 1)
            .read_until(b'\n', &mut bytes)
            .and_then(|_| {
                if bytes.len() as u64 > limit {
                    return Err(io::Error::other("input exceeds the size limit"));
                }
                String::from_utf8(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
            });
        let _ = tx.send(result);
    });
    let started = std::time::Instant::now();
    loop {
        if crate::peer::cancelled() {
            return Err(error("key exchange cancelled"));
        }
        if started.elapsed() > std::time::Duration::from_secs(300) {
            return Err(error("input timed out"));
        }
        match rx.recv_timeout(std::time::Duration::from_millis(100)) {
            Ok(line) => return Ok(line?),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(e) => return Err(e.into()),
        }
    }
}

pub fn confirm(message: &str) -> Result<()> {
    use std::io::IsTerminal;
    if !io::stdin().is_terminal() {
        return Err(error("approval requires a terminal; for file imports use --yes --fingerprint FULL_FINGERPRINT"));
    }
    eprint!("{message} [y/N] ");
    io::stderr().flush()?;
    let answer = input_line(16)?;
    if !matches!(answer.trim(), "y" | "Y" | "yes") {
        return Err(error("signer was not approved"));
    }
    Ok(())
}

pub fn import_signer(id: &str, bytes: &[u8], expected: Option<&str>, yes: bool) -> Result<()> {
    identifier(id)?;
    let (fpr, normalized) = inspect(bytes)?;
    if let Some(expected) = expected {
        if fingerprint(expected)? != fpr {
            return Err(error(
                "public-key fingerprint does not match the expected fingerprint",
            ));
        }
    }
    if yes && expected.is_none() {
        return Err(error("--yes requires --fingerprint FULL_FINGERPRINT"));
    }
    eprintln!("Signer: {id}\nPrimary fingerprint: {fpr}");
    if !yes {
        confirm("Trust this signer to approve commits and their ancestor history?")?;
    }
    let mut db = open_store()?;
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let previous = tx.query_row(
        "SELECT fingerprint, public_key FROM signers WHERE id = ?1",
        [id],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
    );
    let merged = match previous {
        Ok((old_fpr, old_bytes)) => {
            if old_fpr != fpr {
                return Err(error("this ID belongs to a different primary key; remove it explicitly before replacing it"));
            }
            // Merge rather than replace, preserving known revocations/subkeys.
            let ring = Keyring::new()?;
            ring.import(&old_bytes)?;
            ring.import(&normalized)?;
            ring.export(&fpr)?
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => normalized,
        Err(e) => return Err(e.into()),
    };
    tx.execute(
        "INSERT INTO signers(id, fingerprint, public_key) VALUES (?1, ?2, ?3)
        ON CONFLICT(id) DO UPDATE SET public_key=excluded.public_key, updated_at=unixepoch()",
        params![id, fpr, merged],
    )
    .map_err(|e| {
        error(format!(
            "cannot store signer (IDs and fingerprints must be unique): {e}"
        ))
    })?;
    tx.commit()?;
    println!("Trusted signer {id} ({fpr})");
    Ok(())
}

pub struct Snapshot {
    pub ring: Keyring,
    pub fingerprints: std::collections::HashSet<String>,
}
impl Snapshot {
    pub fn load() -> Result<Self> {
        let ring = Keyring::new()?;
        let mut fingerprints = std::collections::HashSet::new();
        let path = data_dir()?.join("trust.sqlite3");
        if path.exists() {
            private_dir(&data_dir()?)?;
            if !fs::symlink_metadata(&path)?.is_file() {
                return Err(error("trust database must be a regular file"));
            }
            let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            let mut stmt = db.prepare("SELECT fingerprint, public_key FROM signers")?;
            let rows = stmt.query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
            })?;
            for row in rows {
                let (fpr, bytes) = row?;
                let (actual, normalized) = inspect(&bytes)?;
                if actual != fpr {
                    return Err(error("trust database contains an inconsistent fingerprint"));
                }
                ring.import(&normalized)?;
                fingerprints.insert(fpr);
            }
        }
        Ok(Self { ring, fingerprints })
    }
}

pub fn run(args: &[OsString]) -> Result<()> {
    let args: Vec<_> = args
        .iter()
        .map(|s| {
            s.to_str()
                .ok_or_else(|| error("key arguments must be UTF-8"))
        })
        .collect::<Result<_>>()?;
    match args.as_slice() {
        [] | ["help"] | ["--help"] => println!("git-safe keys export --key PRIMARY_FINGERPRINT --output FILE\ngit-safe keys import ID FILE [--fingerprint FINGERPRINT] [--yes]\ngit-safe keys trust-own\ngit-safe keys list\ngit-safe keys remove ID"),
        ["trust-own"] => trust_own()?,
        ["export", "--key", fpr, "--output", path] => {
            let bytes = export_personal(fpr)?;
            let mut out = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
            out.write_all(&bytes)?;
            out.sync_all()?;
            println!("Exported public key to {path}");
        }
        ["import", id, path, rest @ ..] => {
            let mut expected = None;
            let mut yes = false;
            let mut i = 0;
            while i < rest.len() {
                match rest[i] {
                    "--fingerprint" if i + 1 < rest.len() => { expected = Some(rest[i+1]); i += 2; }
                    "--yes" => { yes = true; i += 1; }
                    _ => return Err(error("unknown import option; see git-safe keys help")),
                }
            }
            import_signer(id, &read_key(Path::new(path))?, expected, yes)?;
        }
        ["list"] => {
            let db = open_store()?;
            let mut stmt = db.prepare("SELECT id, fingerprint FROM signers ORDER BY id")?;
            for row in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
                let (id, fpr) = row?; println!("{id}\t{fpr}");
            }
        }
        ["remove", id] => {
            identifier(id)?;
            let db = open_store()?;
            if db.execute("DELETE FROM signers WHERE id=?1", [id])? == 0 { return Err(error("unknown signer ID")); }
            println!("Removed signer {id}");
        }
        _ => return Err(error("invalid key command; see git-safe keys help")),
    }
    Ok(())
}
