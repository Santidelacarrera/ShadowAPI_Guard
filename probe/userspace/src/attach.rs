use crate::sender::Sender;
use anyhow::{Context, Result};
use aya::maps::RingBuf;
use aya::programs::TracePoint;
use aya::Ebpf;
use probe_common::DataEvent;
use shadowapi_reconstructor::parse_request;
use std::time::Duration;

pub fn run(object: &str, tx: &mut Sender) -> Result<()> {
    let mut ebpf = Ebpf::load_file(object).with_context(|| format!("loading eBPF object {object}"))?;
    for name in ["sys_enter_write", "sys_enter_sendto"] {
        let prog: &mut TracePoint = ebpf.program_mut(name).context("program missing")?.try_into()?;
        prog.load()?;
        prog.attach("syscalls", name)?;
    }
    let mut ring = RingBuf::try_from(ebpf.take_map("EVENTS").context("EVENTS map missing")?)?;
    eprintln!("probe attached; capturing plain-text HTTP/1.x requests (Ctrl-C to stop)");
    loop {
        while let Some(item) = ring.next() {
            if item.len() < std::mem::size_of::<DataEvent>() {
                continue;
            }
            // SAFETY: DataEvent is repr(C) plain data and the length was checked above.
            let ev: DataEvent = unsafe { std::ptr::read_unaligned(item.as_ptr() as *const DataEvent) };
            let n = (ev.len as usize).min(ev.data.len());
            if let Some(req) = parse_request(&ev.data[..n]) {
                tx.push(req);
            }
        }
        tx.tick(Duration::from_millis(500));
        std::thread::sleep(Duration::from_millis(20));
    }
}
