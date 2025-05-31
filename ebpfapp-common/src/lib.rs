#![no_std]

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SourceAddr {
    pub addr: u32,
    pub port: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SourceAddr {}
