use anyhow::{Context, Result};
use clap::Parser;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

/// Read a file of IP addresses and test reachability / RDP connectivity.
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli {
    /// Path to file containing plain IP addresses (one per line)
    #[arg(short, long)]
    path: std::path::PathBuf,

    /// List of ports to test for each IP (comma-separated, e.g. "3389" or "3389,80,443,22").
    /// Defaults to 3389 (RDP).
    #[arg(long, value_delimiter = ',', default_value = "3389")]
    ports: Vec<u16>,

    /// Enable deep RDP handshake verification on port 3389 (enabled by default)
    #[arg(long, default_value_t = true)]
    rdp_probe: bool,

    /// Connection timeout in milliseconds per endpoint
    #[arg(short, long, default_value_t = 2500)]
    timeout_ms: u64,
}

#[derive(Debug, PartialEq)]
enum ConnectionStatus {
    Connected {
        rtt: Duration,
        rdp_detail: Option<String>,
    },
    Failed(String),
}

fn main() -> Result<()> {
    let args = Cli::parse();
    let timeout = Duration::from_millis(args.timeout_ms);

    let content = std::fs::read_to_string(&args.path)
        .with_context(|| format!("could not read file `{}`", args.path.display()))?;

    process_and_test_ips(&content, &args.ports, args.rdp_probe, timeout, &mut std::io::stdout())?;

    Ok(())
}

/// Standard RDP X.224 Connection Request PDU with RDP Negotiation Request (SSL + HYBRID/CredSSP).
/// Structure per MS-RDPBCGR §2.2.1.1:
/// - TPKT Header (4 bytes): version 3, reserved 0, length 19 (0x0013)
/// - X.224 CR TPDU (7 bytes): LI 14 (0x0e), code 0xe0 (CR), dst 0x0000, src 0x0000, class 0x00
/// - RDP Negotiation Request (8 bytes): type 0x01 (RDP_NEG_REQ), flags 0x00, length 8 (0x0008),
///   protocols 0x00000003 (PROTOCOL_SSL | PROTOCOL_HYBRID)
const RDP_CONNECTION_REQUEST_PDU: [u8; 19] = [
    0x03, 0x00, 0x00, 0x13, // TPKT Header (length = 19)
    0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, // X.224 CR TPDU
    0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00, // RDP_NEG_REQ (SSL | HYBRID)
];

/// Tests RDP protocol handshake over an active TCP stream.
fn test_rdp_handshake(stream: &mut TcpStream, timeout: Duration) -> Result<String> {
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    stream
        .write_all(&RDP_CONNECTION_REQUEST_PDU)
        .context("Failed to send RDP Connection Request PDU")?;

    let mut buf = [0u8; 1024];
    let n = stream
        .read(&mut buf)
        .context("Failed to read RDP server response")?;

    if n == 0 {
        return Err(anyhow::anyhow!("Remote endpoint closed connection during RDP handshake"));
    }

    // Verify TPKT header (starts with 0x03 0x00)
    if n >= 4 && buf[0] == 0x03 && buf[1] == 0x00 {
        let tpkt_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        
        // Check X.224 Connection Confirm code (0xd0 at byte 5)
        if n >= 6 && buf[5] == 0xd0 {
            // Check for RDP Negotiation Response inside X.224
            if n >= 19 && buf[11] == 0x02 { // TYPE_RDP_NEG_RSP
                let protocol_flags = u32::from_le_bytes([buf[15], buf[16], buf[17], buf[18]]);
                let protocol_str = match protocol_flags {
                    0x00 => "Standard RDP Security",
                    0x01 => "SSL / TLS",
                    0x02 => "CredSSP (NLA)",
                    0x03 => "SSL + CredSSP",
                    0x04 => "RDSTLS",
                    _ => "Custom RDP Security",
                };
                return Ok(format!("RDP Verified (Security: {protocol_str})"));
            } else if n >= 19 && buf[11] == 0x03 { // TYPE_RDP_NEG_FAILURE
                let fail_code = u32::from_le_bytes([buf[15], buf[16], buf[17], buf[18]]);
                return Ok(format!("RDP Detected (Negotiation Failure Code: 0x{fail_code:08X})"));
            }

            return Ok(format!("RDP Confirmed (X.224 CC, {tpkt_len} bytes)"));
        }

        return Ok(format!("RDP Service Detected (TPKT frame, {n} bytes)"));
    }

    Err(anyhow::anyhow!("Non-RDP response received ({} bytes)", n))
}

fn test_connection(ip: IpAddr, port: u16, check_rdp: bool, timeout: Duration) -> ConnectionStatus {
    let socket_addr = SocketAddr::new(ip, port);
    let start = Instant::now();
    match TcpStream::connect_timeout(&socket_addr, timeout) {
        Ok(mut stream) => {
            let rtt = start.elapsed();
            if check_rdp {
                match test_rdp_handshake(&mut stream, timeout) {
                    Ok(detail) => ConnectionStatus::Connected {
                        rtt,
                        rdp_detail: Some(detail),
                    },
                    Err(err) => ConnectionStatus::Failed(format!("TCP Open, but RDP Handshake Failed: {err}")),
                }
            } else {
                ConnectionStatus::Connected {
                    rtt,
                    rdp_detail: None,
                }
            }
        }
        Err(err) => ConnectionStatus::Failed(err.to_string()),
    }
}

fn process_and_test_ips(
    content: &str,
    ports: &[u16],
    rdp_probe: bool,
    timeout: Duration,
    mut writer: impl Write,
) -> Result<()> {
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Support plain IP (e.g. 192.168.1.1) or optional IP:port (e.g. 192.168.1.1:3389)
        let (ip, explicit_port) = match trimmed.parse::<IpAddr>() {
            Ok(ip) => (Some(ip), None),
            Err(_) => match trimmed.parse::<SocketAddr>() {
                Ok(socket_addr) => (Some(socket_addr.ip()), Some(socket_addr.port())),
                Err(_) => (None, None),
            },
        };

        match ip {
            Some(ip) => {
                let ip_type = match ip {
                    IpAddr::V4(_) => "IPv4",
                    IpAddr::V6(_) => "IPv6",
                };

                let target_ports: Vec<u16> = match explicit_port {
                    Some(p) => vec![p],
                    None => ports.to_vec(),
                };

                for &port in &target_ports {
                    let should_probe_rdp = rdp_probe && port == 3389;
                    let probe_tag = if should_probe_rdp { " [RDP Probe]" } else { "" };

                    write!(
                        writer,
                        "Line {}: {} [{}] -> Port {}{}: ",
                        idx + 1,
                        ip,
                        ip_type,
                        port,
                        probe_tag
                    )?;

                    match test_connection(ip, port, should_probe_rdp, timeout) {
                        ConnectionStatus::Connected { rtt, rdp_detail } => {
                            if let Some(detail) = rdp_detail {
                                writeln!(writer, "CONNECTED in {:.2?} | {}", rtt, detail)?;
                            } else {
                                writeln!(writer, "CONNECTED in {:.2?}", rtt)?;
                            }
                        }
                        ConnectionStatus::Failed(err) => {
                            writeln!(writer, "FAILED ({})", err)?;
                        }
                    }
                }
            }
            None => {
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
        process_and_test_ips(input, &[3389], false, Duration::from_millis(100), &mut output).unwrap();

        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("'not_an_ip' is NOT a valid IPv4/IPv6 address"));
        assert!(output_str.contains("'999.999.999.999' is NOT a valid IPv4/IPv6 address"));
    }

    #[test]
    fn test_comments_and_empty_lines_ignored() {
        let input = "# This is a comment\n\n127.0.0.1\n";
        let mut output = Vec::new();
        process_and_test_ips(input, &[3389], false, Duration::from_millis(100), &mut output).unwrap();

        let output_str = String::from_utf8(output).unwrap();
        assert!(!output_str.contains("Line 1"));
        assert!(output_str.contains("Line 3: 127.0.0.1 [IPv4]"));
    }
}
