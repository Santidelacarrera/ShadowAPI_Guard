#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user_buf},
    macros::{map, tracepoint},
    maps::{PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use probe_common::{DataEvent, MAX_DATA};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

// DataEvent does not fit on the 512-byte BPF stack: stage it in a per-CPU scratch slot.
#[map]
static SCRATCH: PerCpuArray<DataEvent> = PerCpuArray::with_max_entries(1, 0);

/// Does the buffer start like an HTTP/1.x request line?
#[inline(always)]
fn looks_like_http(d: &[u8; MAX_DATA]) -> bool {
    matches!(
        (d[0], d[1], d[2], d[3]),
        (b'G', b'E', b'T', b' ')
            | (b'P', b'O', b'S', b'T')
            | (b'P', b'U', b'T', b' ')
            | (b'P', b'A', b'T', b'C')
            | (b'D', b'E', b'L', b'E')
            | (b'H', b'E', b'A', b'D')
            | (b'O', b'P', b'T', b'I')
    )
}

#[inline(always)]
fn capture(ctx: &TracePointContext, buf_off: usize, len_off: usize) -> Result<(), i64> {
    // Tracepoint args for sys_enter_write/sendto: fd @16, buf @24, count/len @32.
    let buf: *const u8 = unsafe { ctx.read_at::<u64>(buf_off)? } as *const u8;
    let count: u64 = unsafe { ctx.read_at::<u64>(len_off)? };
    if count < 16 {
        return Ok(());
    }
    let slot = SCRATCH.get_ptr_mut(0).ok_or(1i64)?;
    let ev = unsafe { &mut *slot };
    let n = if (count as usize) < MAX_DATA { count as usize } else { MAX_DATA };
    ev.data = [0u8; MAX_DATA];
    // Read a fixed-size window (verifier-friendly); `len` records the meaningful prefix.
    unsafe { bpf_probe_read_user_buf(buf, &mut ev.data)? };
    if !looks_like_http(&ev.data) {
        return Ok(());
    }
    ev.tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    ev.len = n as u32;
    ev.comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    if let Some(mut slot) = EVENTS.reserve::<DataEvent>(0) {
        slot.write(*ev);
        slot.submit(0);
    }
    Ok(())
}

#[tracepoint]
pub fn sys_enter_write(ctx: TracePointContext) -> u32 {
    let _ = capture(&ctx, 24, 32);
    0
}

#[tracepoint]
pub fn sys_enter_sendto(ctx: TracePointContext) -> u32 {
    let _ = capture(&ctx, 24, 32);
    0
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
