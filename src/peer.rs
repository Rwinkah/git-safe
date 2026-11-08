//! Short-lived, authenticated key exchange over a managed Tor onion service.
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::keys::{self, error, Result, MAX_KEY_BYTES};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tempfile::TempDir;

static CANCELLED: AtomicBool = AtomicBool::new(false);
pub fn cancelled() -> bool {
    CANCELLED.load(Ordering::Relaxed)
}
const MAX_MESSAGE: usize = MAX_KEY_BYTES * 2 + 4096;
const SESSION_SECONDS: u64 = 300;

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(error("invalid invitation secret"));
    }
    let mut bytes = [0; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16)?;
    }
    Ok(bytes)
}

struct Invitation {
    host: String,
    secret: [u8; 32],
}
impl Invitation {
    fn parse(value: &str) -> Result<Self> {
        let (host, secret) = value
            .trim()
            .strip_prefix("git-safe://")
            .and_then(|v| v.split_once('/'))
            .ok_or_else(|| error("expected a git-safe://ONION_ADDRESS/SECRET invitation"))?;
        let name = host
            .strip_suffix(".onion")
            .ok_or_else(|| error("only Tor onion destinations are accepted"))?;
        if name.len() != 56
            || !name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
        {
            return Err(error("expected a v3 onion address"));
        }
        Ok(Self {
            host: host.into(),
            secret: unhex(secret)?,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u32,
    public_key: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    version: u32,
    public_key: String,
}

#[derive(Clone, Copy)]
struct Deadline(Instant);
impl Deadline {
    fn after(seconds: u64) -> Self {
        Self(Instant::now() + Duration::from_secs(seconds))
    }
    fn check(self) -> Result<()> {
        if CANCELLED.load(Ordering::Relaxed) {
            return Err(error("key exchange cancelled"));
        }
        if Instant::now() >= self.0 {
            return Err(error(
                "key exchange timed out; create a new invitation and retry",
            ));
        }
        Ok(())
    }
    fn pause(self) -> Result<()> {
        self.check()?;
        std::thread::sleep(Duration::from_millis(100));
        Ok(())
    }
}

fn read_exact(stream: &mut impl Read, bytes: &mut [u8], deadline: Deadline) -> Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        deadline.check()?;
        match stream.read(&mut bytes[offset..]) {
            Ok(0) => return Err(error("peer disconnected")),
            Ok(n) => offset += n,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::TimedOut
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::Interrupted
                ) =>
            {
                continue
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
fn write_all(stream: &mut impl Write, bytes: &[u8], deadline: Deadline) -> Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        deadline.check()?;
        match stream.write(&bytes[offset..]) {
            Ok(0) => return Err(error("peer disconnected")),
            Ok(n) => offset += n,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::TimedOut
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::Interrupted
                ) =>
            {
                continue
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
fn send<T: Serialize>(stream: &mut impl Write, value: &T, deadline: Deadline) -> Result<()> {
    let data = serde_json::to_vec(value)?;
    if data.len() > MAX_MESSAGE {
        return Err(error("key exchange message exceeds the size limit"));
    }
    write_all(stream, &(data.len() as u32).to_be_bytes(), deadline)?;
    write_all(stream, &data, deadline)
}
fn receive<T: serde::de::DeserializeOwned>(
    stream: &mut impl Read,
    deadline: Deadline,
) -> Result<T> {
    let mut size = [0; 4];
    read_exact(stream, &mut size, deadline)?;
    let size = u32::from_be_bytes(size) as usize;
    if size == 0 || size > MAX_MESSAGE {
        return Err(error("invalid key exchange message size"));
    }
    let mut data = vec![0; size];
    read_exact(stream, &mut data, deadline)?;
    Ok(serde_json::from_slice(&data)?)
}
// Drain the SOCKS connection before stopping Tor. Sending the last frame and
// immediately killing the client can otherwise discard data still in transit.
fn finish(stream: &mut TcpStream, deadline: Deadline) -> Result<()> {
    stream.shutdown(std::net::Shutdown::Write)?;
    loop {
        deadline.check()?;
        let mut byte = [0];
        match stream.read(&mut byte) {
            Ok(0) => return Ok(()),
            Ok(_) => return Err(error("unexpected data after exchange completion")),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::TimedOut
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e.into()),
        }
    }
}

fn authenticate(stream: &mut impl Read, secret: &[u8; 32], deadline: Deadline) -> Result<()> {
    let mut offered = [0; 32];
    read_exact(stream, &mut offered, deadline)?;
    if !bool::from(secret.ct_eq(&offered)) {
        return Err(error("pairing secret did not match; invitation cancelled"));
    }
    Ok(())
}

fn configure(stream: &TcpStream) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    stream.set_write_timeout(Some(Duration::from_secs(1)))?;
    Ok(())
}

struct Tor {
    child: Child,
    _session: TempDir,
    control: UnixStream,
    socks: std::net::SocketAddr,
}
impl Drop for Tor {
    fn drop(&mut self) {
        // Give Tor a chance to flush its normal client state before exiting.
        let _ = self.control.write_all(b"SIGNAL SHUTDOWN\r\n");
        for _ in 0..10 {
            if self.child.try_wait().ok().flatten().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Tor {
    fn start() -> Result<Self> {
        let root = keys::data_dir()?;
        keys::private_dir(&root)?;
        let state = root.join("tor");
        keys::private_dir(&state)?;
        let session = tempfile::Builder::new().prefix("git-safe-tor-").tempdir()?;
        fs::set_permissions(session.path(), fs::Permissions::from_mode(0o700))?;
        let socket = session.path().join("control");
        let cookie = session.path().join("cookie");
        let config = session.path().join("torrc");
        fs::write(&config, b"# Isolated configuration managed by git-safe.\n")?;
        let control_path = socket
            .to_str()
            .ok_or_else(|| error("invalid Tor control socket path"))?;
        let startup = fs::File::create(session.path().join("startup.log"))?;
        let startup_err = startup.try_clone()?;
        let mut child = Command::new("tor")
            .arg("-f")
            .arg(&config)
            .args([
                "--RunAsDaemon",
                "0",
                "--ClientOnly",
                "1",
                "--SocksPort",
                "auto",
                "--ControlPort",
                "0",
                "--CookieAuthentication",
                "1",
                "--AvoidDiskWrites",
                "1",
                "--SafeLogging",
                "1",
                "--ControlSocket",
                control_path,
                "--CookieAuthFile",
            ])
            .arg(&cookie)
            .arg("--DataDirectory")
            .arg(&state)
            .arg("--Log")
            .arg(format!(
                "notice file {}",
                session.path().join("tor.log").display()
            ))
            .stdin(Stdio::null())
            .stdout(Stdio::from(startup))
            .stderr(Stdio::from(startup_err))
            .spawn()
            .map_err(|e| error(format!("cannot start Tor; install the tor package: {e}")))?;
        // Ensure every early return reaps the child too.
        let deadline = Deadline::after(180);
        let init = (|| -> Result<UnixStream> {
            loop {
                deadline.check()?;
                if child.try_wait()?.is_some() {
                    let mut diagnostics = String::new();
                    for name in ["startup.log", "tor.log"] {
                        if let Ok(log) = fs::read_to_string(session.path().join(name)) {
                            for line in log
                                .lines()
                                .filter(|l| l.contains("[warn]") || l.contains("[err]"))
                            {
                                diagnostics.push_str(line);
                                diagnostics.push('\n');
                            }
                        }
                    }
                    return Err(error(format!(
                        "Tor exited during startup: {}",
                        diagnostics.trim()
                    )));
                }
                if cookie.exists() {
                    if let Ok(control) = UnixStream::connect(&socket) {
                        return Ok(control);
                    }
                }
                deadline.pause()?;
            }
        })();
        let control = match init {
            Ok(control) => control,
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
        };
        let mut tor = Self {
            child,
            _session: session,
            control,
            socks: "127.0.0.1:0".parse()?,
        };
        tor.control.set_read_timeout(Some(Duration::from_secs(1)))?;
        tor.control
            .set_write_timeout(Some(Duration::from_secs(1)))?;
        let cookie = fs::read(cookie)?;
        if cookie.len() != 32 {
            return Err(error("invalid Tor authentication cookie"));
        }
        tor.command(&format!("AUTHENTICATE {}", hex(&cookie)), deadline)?;
        tor.command("TAKEOWNERSHIP", deadline)?;
        eprintln!("Connecting to Tor (first startup may take a minute or more)…");
        loop {
            let response = tor.command("GETINFO status/bootstrap-phase", deadline)?;
            if response
                .iter()
                .any(|s| s.split_whitespace().any(|field| field == "PROGRESS=100"))
            {
                break;
            }
            deadline.pause()?;
        }
        let lines = tor.command("GETINFO net/listeners/socks", deadline)?;
        let address = lines
            .iter()
            .find_map(|s| s.strip_prefix("250-net/listeners/socks="))
            .and_then(|s| s.split_whitespace().next())
            .ok_or_else(|| error("Tor did not provide a SOCKS listener"))?;
        tor.socks = address.trim_matches('"').parse()?;
        if !tor.socks.ip().is_loopback() {
            return Err(error("Tor SOCKS listener must be local"));
        }
        Ok(tor)
    }
    fn command(&mut self, cmd: &str, deadline: Deadline) -> Result<Vec<String>> {
        write_all(&mut self.control, format!("{cmd}\r\n").as_bytes(), deadline)?;
        let mut lines = Vec::new();
        loop {
            let mut line = Vec::new();
            loop {
                let mut byte = [0];
                read_exact(&mut self.control, &mut byte, deadline)?;
                line.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
                if line.len() > 8192 {
                    return Err(error("oversized Tor control response"));
                }
            }
            let line = String::from_utf8(line)?;
            if !line.starts_with("250") {
                return Err(error("Tor rejected a control command"));
            }
            let done = line.as_bytes().get(3) == Some(&b' ');
            lines.push(line.trim_end().to_string());
            if done {
                return Ok(lines);
            }
            if lines.len() > 64 {
                return Err(error("oversized Tor control response"));
            }
        }
    }
    fn publish(&mut self, port: u16) -> Result<String> {
        let lines = self.command(
            &format!("ADD_ONION NEW:ED25519-V3 Flags=DiscardPK Port=80,127.0.0.1:{port}"),
            Deadline::after(30),
        )?;
        let id = lines
            .iter()
            .find_map(|s| s.strip_prefix("250-ServiceID="))
            .ok_or_else(|| error("Tor did not return an onion address"))?;
        let host = format!("{id}.onion");
        Invitation::parse(&format!("git-safe://{host}/{}", "00".repeat(32)))?;
        Ok(host)
    }
    fn connect(&self, host: &str, deadline: Deadline) -> Result<TcpStream> {
        // A freshly created service may not have published its descriptor yet.
        loop {
            deadline.check()?;
            match self.connect_once(host, deadline) {
                Ok(stream) => return Ok(stream),
                Err(err) => {
                    deadline.check()?;
                    eprintln!("Waiting for the onion service: {err}");
                    for _ in 0..20 {
                        deadline.pause()?;
                    }
                }
            }
        }
    }
    fn connect_once(&self, host: &str, deadline: Deadline) -> Result<TcpStream> {
        let mut stream = TcpStream::connect_timeout(&self.socks, Duration::from_secs(5))?;
        configure(&stream)?;
        write_all(&mut stream, &[5, 1, 0], deadline)?;
        let mut response = [0; 2];
        read_exact(&mut stream, &mut response, deadline)?;
        if response != [5, 0] {
            return Err(error("Tor SOCKS authentication failed"));
        }
        let mut request = vec![5, 1, 0, 3, host.len() as u8];
        request.extend_from_slice(host.as_bytes());
        request.extend_from_slice(&80u16.to_be_bytes());
        write_all(&mut stream, &request, deadline)?;
        let mut header = [0; 4];
        read_exact(&mut stream, &mut header, deadline)?;
        if header[..3] != [5, 0, 0] {
            return Err(error(
                "Tor could not reach the onion service; check that the invitation is active",
            ));
        }
        let length = match header[3] {
            1 => 4,
            4 => 16,
            3 => {
                let mut n = [0];
                read_exact(&mut stream, &mut n, deadline)?;
                n[0] as usize
            }
            _ => return Err(error("invalid SOCKS response")),
        };
        read_exact(&mut stream, &mut vec![0; length + 2], deadline)?;
        Ok(stream)
    }
}

fn invite(key: &str, peer_id: Option<&str>) -> Result<()> {
    let public_key = String::from_utf8(keys::export_personal(key)?)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let mut tor = Tor::start()?;
    let host = tor.publish(listener.local_addr()?.port())?;
    let mut secret = [0; 32];
    getrandom::fill(&mut secret)
        .map_err(|e| error(format!("cannot generate pairing secret: {e}")))?;
    println!(
        "Invitation (private, single-use, expires in 5 minutes):\ngit-safe://{host}/{}",
        hex(&secret)
    );
    io::stdout().flush()?;
    eprintln!("Waiting for the recipient. Share the entire invitation privately; Ctrl-C cancels.");
    let deadline = Deadline::after(SESSION_SECONDS);
    let (mut stream, _) = loop {
        deadline.check()?;
        match listener.accept() {
            Ok(peer) => break peer,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => deadline.pause()?,
            Err(e) => return Err(e.into()),
        }
    };
    configure(&stream)?;
    authenticate(&mut stream, &secret, deadline)?;
    let request: Request = receive(&mut stream, deadline)?;
    if request.version != 1 {
        return Err(error("unsupported key-exchange protocol version"));
    }
    if peer_id.is_some() != request.public_key.is_some() {
        return Err(error(
            "reciprocal exchange requires --peer-id on invite and --key on connect",
        ));
    }
    if let (Some(id), Some(bytes)) = (peer_id, request.public_key.as_ref()) {
        keys::import_signer(id, bytes.as_bytes(), None, false)?;
    }
    send(
        &mut stream,
        &Response {
            version: 1,
            public_key,
        },
        deadline,
    )?;
    let approved: bool = receive(&mut stream, deadline)?;
    if !approved {
        return Err(error("recipient did not approve the signer"));
    }
    send(&mut stream, &true, deadline)?;
    finish(&mut stream, deadline)?;
    println!("Recipient approved the public key. Tor session closed.");
    Ok(())
}

fn connect(id: &str, key: Option<&str>) -> Result<()> {
    eprint!("Paste the private invitation: ");
    io::stderr().flush()?;
    let invitation = keys::input_line(512)?;
    let invitation = Invitation::parse(&invitation)?;
    let public_key = key
        .map(keys::export_personal)
        .transpose()?
        .map(String::from_utf8)
        .transpose()?;
    let tor = Tor::start()?;
    let deadline = Deadline::after(SESSION_SECONDS);
    let mut stream = tor.connect(&invitation.host, deadline)?;
    write_all(&mut stream, &invitation.secret, deadline)?;
    send(
        &mut stream,
        &Request {
            version: 1,
            public_key,
        },
        deadline,
    )?;
    let response: Response = receive(&mut stream, deadline)?;
    if response.version != 1 {
        return Err(error("unsupported key-exchange protocol version"));
    }
    let result = keys::import_signer(id, response.public_key.as_bytes(), None, false);
    let _ = send(&mut stream, &result.is_ok(), deadline);
    result?;
    let complete: bool = receive(&mut stream, deadline)?;
    if !complete {
        return Err(error("peer did not confirm exchange completion"));
    }
    finish(&mut stream, deadline)?;
    println!("Public key received. Tor session closed.");
    Ok(())
}

pub fn run(args: &[OsString]) -> Result<()> {
    let args: Vec<_> = args
        .iter()
        .map(|s| {
            s.to_str()
                .ok_or_else(|| error("peer arguments must be UTF-8"))
        })
        .collect::<Result<_>>()?;
    if matches!(args.as_slice(), [] | ["help"] | ["--help"]) {
        println!("git-safe peer invite --key PRIMARY_FINGERPRINT [--peer-id LOCAL_ID]\ngit-safe peer connect --id LOCAL_ID [--key PRIMARY_FINGERPRINT]\nInvitations are entered interactively. Both computers must be online. Requires tor.");
        return Ok(());
    }
    CANCELLED.store(false, Ordering::Relaxed);
    ctrlc::set_handler(|| CANCELLED.store(true, Ordering::Relaxed))?;
    match args.as_slice() {
        ["invite", "--key", key] => invite(key, None),
        ["invite", "--key", key, "--peer-id", id] => invite(key, Some(id)),
        ["connect", "--id", id] => connect(id, None),
        ["connect", "--id", id, "--key", key] => connect(id, Some(key)),
        _ => Err(error("invalid peer command; see git-safe peer help")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wrong_and_truncated_secrets_are_rejected_before_payloads() {
        let secret = [7; 32];
        assert!(authenticate(&mut &[7u8; 32][..], &secret, Deadline::after(1)).is_ok());
        assert!(authenticate(&mut &[6u8; 32][..], &secret, Deadline::after(1)).is_err());
        assert!(authenticate(&mut &[7u8; 31][..], &secret, Deadline::after(1)).is_err());
    }

    #[test]
    fn invitation_restricts_destination_and_secret() {
        let good = format!("git-safe://{}.onion/{}", "a".repeat(56), "12".repeat(32));
        assert!(Invitation::parse(&good).is_ok());
        for bad in [
            good.replace(".onion", ".com"),
            good.replace(".onion", ".onion:80"),
            good.replace("git-safe://", "https://"),
            format!("git-safe://{}.onion/1234", "a".repeat(56)),
        ] {
            assert!(Invitation::parse(&bad).is_err());
        }
    }
    #[test]
    fn framing_rejects_oversized_truncated_and_unknown_messages() {
        let deadline = Deadline::after(2);
        assert!(receive::<Request>(&mut &(u32::MAX.to_be_bytes())[..], deadline).is_err());
        assert!(receive::<Request>(&mut &[0, 0, 0, 8, b'{'][..], deadline).is_err());
        let mut data = Vec::new();
        send(
            &mut data,
            &Request {
                version: 1,
                public_key: None,
            },
            deadline,
        )
        .unwrap();
        assert_eq!(
            receive::<Request>(&mut &data[..], deadline)
                .unwrap()
                .version,
            1
        );
        let data = br#"{"version":1,"public_key":null,"extra":1}"#;
        let mut frame = (data.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(data);
        assert!(receive::<Request>(&mut &frame[..], deadline).is_err());
    }
}
