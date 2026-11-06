//! iphone-fido CLI: `run` (daemon), `pair` (PSK pairing), `selftest`.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

use iphone_fido::authenticator::Authenticator;
use iphone_fido::bridge;
use iphone_fido::phone::{MockPhone, Phone, TcpPhone};
use iphone_fido::transport::{StdioTransport, Transport};
#[cfg(unix)]
use iphone_fido::transport::UhidTransport;

#[derive(Parser)]
#[command(name = "iphone-fido", version, about = "Use a phone as a FIDO2/WebAuthn security key over USB")]
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
    /// Pair with the phone: store the Base32 pairing secret it displays.
    Pair {
        /// The 52-character Base32 pairing secret shown by the phone app. Spaces and hyphens are ignored.
        code: String,
        /// Path to the pairing PSK file.
        #[arg(long)]
        pairing_file: Option<PathBuf>,
    },
    /// Pair by QR code: generate a new pairing secret on this PC, save it,
    /// and print a QR code for the phone app to scan. Nothing is typed.
    PairQr {
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
            let code: String = code.chars().filter(|c| !c.is_whitespace() && *c != '-').collect();
            match bridge::base32_decode_nopad(&code) {
                Ok(bytes) if bytes.len() == 32 => {
                    let mut psk = [0u8; 32];
                    psk.copy_from_slice(&bytes);
                    match bridge::save_pairing(&path, &psk) {
                        Ok(()) => {
                            println!("Pairing secret saved to {} (mode 0600)", path.display());
                            println!("SAS (compare with the phone app): {}", bridge::sas_for_psk(&psk));
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
        Command::PairQr { pairing_file } => {
            let path = pairing_file.unwrap_or_else(bridge::default_pairing_path);
            let mut psk = [0u8; 32];
            iphone_fido::fill_random(&mut psk);
            match bridge::save_pairing(&path, &psk) {
                Ok(()) => {
                    let code = bridge::base32_encode_nopad(&psk);
                    let payload = format!("phonefido-pair:1:{code}");
                    println!("New pairing secret saved to {}", path.display());
                    println!();
                    match qrcode::QrCode::new(payload.as_bytes()) {
                        Ok(qr) => {
                            let rendered = qr
                                .render::<qrcode::render::unicode::Dense1x2>()
                                .quiet_zone(true)
                                .build();
                            println!("{rendered}");
                        }
                        Err(e) => eprintln!("(could not render the QR code: {e})"),
                    }
                    println!("Scan this QR code with the phone app:");
                    println!("  Phone FIDO Key -> Pairing -> Pair with QR code");
                    println!();
                    println!(
                        "SAS (must match the phone after scanning): {}",
                        bridge::sas_for_psk(&psk)
                    );
                    println!("Pairing key (only if the camera cannot be used):");
                    println!(
                        "  {}",
                        code.as_bytes()
                            .chunks(4)
                            .map(|c| std::str::from_utf8(c).unwrap_or(""))
                            .collect::<Vec<_>>()
                            .join(" ")
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: cannot save pairing file {}: {e}", path.display());
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
                // The 2-second tick drives phone-session upkeep so the
                // bridge connects by itself when the phone appears.
                match transport.recv_packet_timeout(std::time::Duration::from_secs(2)) {
                    Ok(Some(packet)) => {
                        for out in auth.handle_packet(&packet) {
                            if let Err(e) = transport.send_packet(&out) {
                                eprintln!("error: transport send failed: {e}");
                                return ExitCode::FAILURE;
                            }
                        }
                    }
                    Ok(None) => auth.maintain(),
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
            TransportKind::Uhid => {
                #[cfg(unix)]
                {
                    match UhidTransport::new() {
                        Ok(mut t) => {
                            t.set_verbose(verbose);
                            serve!(t, phone)
                        }
                        Err(e) => {
                            eprintln!("error: {e}");
                            ExitCode::FAILURE
                        }
                    }
                }
                #[cfg(not(unix))]
                {
                    eprintln!("error: the UHID transport is only available on Linux");
                    ExitCode::FAILURE
                }
            }
            TransportKind::Stdio => serve!(StdioTransport::new(), phone),
        }
    } else {
        let path = pairing_file.unwrap_or_else(bridge::default_pairing_path);
        let psk = match bridge::load_pairing(&path) {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "error: cannot load pairing secret from {}: {e}\n\
                     Run `iphone-fido pair <BASE32>` with the code shown by the phone app first.",
                    path.display()
                );
                return ExitCode::FAILURE;
            }
        };
        println!(
            "Pairing SAS: {} (must match the phone app)",
            bridge::sas_for_psk(&psk)
        );
        // The phone connection is lazy and self-healing: the app suspends
        // whenever it is backgrounded, so requiring it at startup (and
        // exiting when it is absent) would make the daemon unusable. Ping
        // once as an early check, warn if it fails, and serve anyway —
        // TcpPhone reconnects on the first real request.
        let mut phone = TcpPhone::new(phone_addr, &psk);
        match phone.ping() {
            Ok(v) => println!("Phone bridge connected: {v}"),
            Err(e) => {
                eprintln!(
                    "warning: phone not reachable yet ({e}).\n\
                     The daemon keeps running and will connect on first use.\n\
                     Keep the phone connected by USB, the app in the foreground,\n\
                     Keep the phone connected by USB, the app in the foreground,\\n\
                     and the forwarder running (iproxy 18766 18765 for iPhone,\\n\
                     adb forward tcp:18766 tcp:18765 for Android) when authenticating."
                );
            }
        }
        match transport {
            TransportKind::Uhid => {
                #[cfg(unix)]
                {
                    match UhidTransport::new() {
                        Ok(mut t) => {
                            t.set_verbose(verbose);
                            serve!(t, phone)
                        }
                        Err(e) => {
                            eprintln!("error: {e}");
                            ExitCode::FAILURE
                        }
                    }
                }
                #[cfg(not(unix))]
                {
                    eprintln!("error: the UHID transport is only available on Linux");
                    ExitCode::FAILURE
                }
            }
            TransportKind::Stdio => serve!(StdioTransport::new(), phone),
        }
    }
}
