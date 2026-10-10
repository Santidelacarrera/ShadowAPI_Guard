//! Types shared between the eBPF program and the userspace loader.
#![no_std]

/// Bytes of each socket write we copy out of the kernel (enough for request line + headers).
pub const MAX_DATA: usize = 512;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DataEvent {
    pub tgid: u32,
    pub len: u32,
    pub comm: [u8; 16],
    pub data: [u8; MAX_DATA],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for DataEvent {}
