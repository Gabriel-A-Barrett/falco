use anyhow::{Context, Result};
use clap::Parser;
use std::io::Write;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

/// Read a file of IP addresses and test TCP connection reachability.
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli {
    /// Path to file containing IP addresses
    #[arg(short, long)]
    path: std::path::PathBuf,

    /// Test standard Remote Desktop Protocol (RDP) port (3389)
    #[arg(long)]
    rdp: bool,

    /// Target port to test (defaults to 3389 if --rdp is set, otherwise 3389)
    #[arg(short, long)]
    port: Option<u16>,

    /// Connection timeout in milliseconds
    #[arg(short, long, default_value_t = 2000)]
    timeout_ms: u64,
}

#[derive(Debug, PartialEq)]
enum ConnectionStatus {
    Connected(Duration),
    Failed(String),
}

fn test_connection(ip: IpAddr, port: u16, timeout: Duration) -> ConnectionStatus {
    let socket_addr = SocketAddr::new(ip, port);
    let start = Instant::now();
    match TcpStream::connect_timeout(&socket_addr, timeout) {
        Ok(_) => ConnectionStatus::Connected(start.elapsed()),
        Err(err) => ConnectionStatus::Failed(err.to_string()),
    }
}

fn main() -> Result<()> {
    let args = Cli::parse();

    let port = args.port.unwrap_or(if args.rdp { 3389 } else { 3389 });
    let timeout = Duration::from_millis(args.timeout_ms);

    let content = std::fs::read_to_string(&args.path)
        .with_context(|| format!("could not read file `{}`", args.path.display()))?;

    process_and_test_ips(&content, port, timeout, &mut std::io::stdout())?;

    Ok(())
}

fn process_and_test_ips(
    content: &str,
    port: u16,
    timeout: Duration,
    mut writer: impl Write,
) -> Result<()> {
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        match trimmed.parse::<IpAddr>() {
            Ok(ip) => {
                let ip_type = match ip {
                    IpAddr::V4(_) => "IPv4",
                    IpAddr::V6(_) => "IPv6",
                };

                write!(writer, "Line {}: {} [{}] -> Port {}: ", idx + 1, ip, ip_type, port)?;

                match test_connection(ip, port, timeout) {
                    ConnectionStatus::Connected(duration) => {
                        writeln!(writer, "CONNECTED in {:.2?}", duration)?;
                    }
                    ConnectionStatus::Failed(err) => {
                        writeln!(writer, "FAILED ({})", err)?;
                    }
                }
            }
            Err(_) => {
                writeln!(
                    writer,
                    "Line {}: '{}' is NOT a valid IPv4/IPv6 address (skipped)",
                    idx + 1,
                    trimmed
                )?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_ip_handling() {
        let input = "not_an_ip\n999.999.999.999\n";
        let mut output = Vec::new();
        process_and_test_ips(input, 3389, Duration::from_millis(100), &mut output).unwrap();

        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("'not_an_ip' is NOT a valid IPv4/IPv6 address"));
        assert!(output_str.contains("'999.999.999.999' is NOT a valid IPv4/IPv6 address"));
    }
}
