//! ShadowAPI probe: loads the eBPF program (or replays a capture in simulation mode),
//! reconstructs HTTP requests and ships them to the detector.

#[cfg(target_os = "linux")]
mod attach;
mod sender;

use anyhow::Result;
use clap::{Parser, Subcommand};
use shadowapi_reconstructor::parse_request;
use std::io::BufRead;

#[derive(Parser)]
#[command(name = "shadowapi-probe", about = "L7 traffic probe for ShadowAPI Guard")]
struct Cli {
    /// Detector base URL
    #[arg(long, env = "DETECTOR_URL", default_value = "http://localhost:8081")]
    detector: String,
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    /// Attach the compiled eBPF object to the kernel (needs root / CAP_BPF).
    Attach {
        /// Path to the compiled eBPF object (see probe/ebpf)
        #[arg(long, env = "PROBE_OBJECT", default_value = "probe/ebpf/target/bpfel-unknown-none/release/probe-ebpf")]
        object: String,
    },
    /// Local fallback: replay captures from a file (or `-` for stdin), one JSON line per
    /// write: {"raw": "GET /users/1 HTTP/1.1\r\nHost: x\r\n\r\n"}
    Simulate { input: String },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut tx = sender::Sender::new(&cli.detector);
    match cli.mode {
        Mode::Simulate { input } => {
            let reader: Box<dyn BufRead> = if input == "-" {
                Box::new(std::io::BufReader::new(std::io::stdin()))
            } else {
                Box::new(std::io::BufReader::new(std::fs::File::open(&input)?))
            };
            let mut n = 0;
            for line in reader.lines() {
                let v: serde_json::Value = serde_json::from_str(&line?)?;
                if let Some(ev) = v["raw"].as_str().and_then(|r| parse_request(r.as_bytes())) {
                    tx.push(ev);
                    n += 1;
                }
            }
            tx.flush()?;
            eprintln!("replayed {n} requests");
            Ok(())
        }
        Mode::Attach { object } => {
            #[cfg(target_os = "linux")]
            {
                attach::run(&object, &mut tx)
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = object;
                anyhow::bail!("eBPF requires Linux; use `simulate`")
            }
        }
    }
}
