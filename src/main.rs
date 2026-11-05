//! iphone-fido CLI: `run` (daemon), `pair` (PSK pairing), `selftest`.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

use iphone_fido::authenticator::Authenticator;
use iphone_fido::bridge;
use iphone_fido::phone::{MockPhone, Phone, TcpPhone};
use iphone_fido::transport::{StdioTransport, Transport, UhidTransport};

#[derive(Parser)]
#[command(name = "iphone-fido", version, about = "Use an iPhone as a FIDO2/WebAuthn security key over USB")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum TransportKind {
    /// Real virtual HID device via /dev/uhid
    Uhid,
    /// Development: raw 64-byte packets over stdin/stdout
    Stdio,
}

#[derive(Subcommand)]
enum Command {
    /// Run the authenticator daemon.
    Run {
        /// Use the software mock phone (DEVELOPMENT ONLY; in-memory keys,
        /// no Secure Enclave, no Face ID).
        #[arg(long)]
        mock_phone: bool,
        /// Address of the (iproxy-forwarded) phone bridge.
        #[arg(long, default_value = bridge::DEFAULT_PHONE_ADDR)]
        phone_addr: String,
        /// Path to the pairing PSK file.
        #[arg(long)]
        pairing_file: Option<PathBuf>,
        /// HID transport to expose.
        #[arg(long, value_enum, default_value = "uhid")]
        transport: TransportKind,
        /// Log each CTAPHID message and CTAP2 command/status to stderr
        /// (metadata only; useful when diagnosing browser behaviour).
        #[arg(long)]
        verbose: bool,
    },
    /// Pair with the iPhone: store the Base32 pairing secret it displays.
    Pair {
        /// The 52-character Base32 pairing secret shown by the iPhone app.
        code: String,
        /// Path to the pairing PSK file.
        #[arg(long)]
        pairing_file: Option<PathBuf>,
    },
    /// Run the in-process end-to-end self test (mock phone + mock transport).
    Selftest,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Selftest => match iphone_fido::selftest::run_selftest() {
            Ok(lines) => {
                for line in &lines {
                    println!("{line}");
                }
                println!("selftest: PASS");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("selftest: FAIL: {e}");
                println!("selftest: FAIL");
                ExitCode::FAILURE
            }
        },
        Command::Pair { code, pairing_file } => {
            let path = pairing_file.unwrap_or_else(bridge::default_pairing_path);
            match bridge::base32_decode_nopad(&code) {
                Ok(bytes) if bytes.len() == 32 => {
                    let mut psk = [0u8; 32];
                    psk.copy_from_slice(&bytes);
                    match bridge::save_pairing(&path, &psk) {
                        Ok(()) => {
                            println!("Pairing secret saved to {} (mode 0600)", path.display());
                            println!("SAS (compare with the iPhone app): {}", bridge::sas_for_psk(&psk));
                            ExitCode::SUCCESS
                        }
                        Err(e) => {
                            eprintln!("error: cannot save pairing file {}: {e}", path.display());
                            ExitCode::FAILURE
                        }
                    }
                }
                Ok(bytes) => {
                    eprintln!(
                        "error: pairing secret must decode to 32 bytes, got {} (expected a 52-character Base32 string)",
                        bytes.len()
                    );
                    ExitCode::FAILURE
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Command::Run {
            mock_phone,
            phone_addr,
            pairing_file,
            transport,
            verbose,
        } => run_daemon(mock_phone, &phone_addr, pairing_file, transport, verbose),
    }
}

fn run_daemon(
    mock_phone: bool,
    phone_addr: &str,
    pairing_file: Option<PathBuf>,
    transport: TransportKind,
    verbose: bool,
) -> ExitCode {
    // Build the transport first so a missing /dev/uhid fails fast and
    // with an explicit message, before any phone connection attempt.
    macro_rules! serve {
        ($transport:expr, $phone:expr) => {{
            let mut transport = $transport;
            let mut auth = Authenticator::new($phone);
            auth.set_verbose(verbose);
            loop {
                match transport.recv_packet() {
                    Ok(packet) => {
                        for out in auth.handle_packet(&packet) {
                            if let Err(e) = transport.send_packet(&out) {
                                eprintln!("error: transport send failed: {e}");
                                return ExitCode::FAILURE;
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("error: transport receive failed: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            }
        }};
    }

    if mock_phone {
        eprintln!(
            "WARNING: --mock-phone is enabled. Credentials are software P-256 keys \
             held in memory on THIS PC — no Secure Enclave, no Face ID. \
             Development only; never treat mock credentials as real."
        );
        let phone = MockPhone::new();
        match transport {
            TransportKind::Uhid => match UhidTransport::new() {
                Ok(mut t) => {
                    t.set_verbose(verbose);
                    serve!(t, phone)
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            },
            TransportKind::Stdio => serve!(StdioTransport::new(), phone),
        }
    } else {
        let path = pairing_file.unwrap_or_else(bridge::default_pairing_path);
        let psk = match bridge::load_pairing(&path) {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "error: cannot load pairing secret from {}: {e}\n\
                     Run `iphone-fido pair <BASE32>` with the code shown by the iPhone app first.",
                    path.display()
                );
                return ExitCode::FAILURE;
            }
        };
        println!(
            "Pairing SAS: {} (must match the iPhone app)",
            bridge::sas_for_psk(&psk)
        );
        let mut phone = match TcpPhone::connect(phone_addr, &psk) {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "error: cannot reach the iPhone bridge at {phone_addr}: {e}\n\
                     Is the iPhone connected by USB, the app in the foreground, \
                     and iproxy running (iproxy 18766 18765)?"
                );
                return ExitCode::FAILURE;
            }
        };
        match phone.ping() {
            Ok(v) => println!("Phone bridge connected: {v}"),
            Err(e) => {
                eprintln!("error: phone ping failed: {e}");
                return ExitCode::FAILURE;
            }
        }
        match transport {
            TransportKind::Uhid => match UhidTransport::new() {
                Ok(mut t) => {
                    t.set_verbose(verbose);
                    serve!(t, phone)
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            },
            TransportKind::Stdio => serve!(StdioTransport::new(), phone),
        }
    }
}
