#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::Queue,
    programs::XdpContext,
};
use aya_log_ebpf::{error, info};
use ebpfapp_common::SourceAddr;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[xdp]
pub fn ebpfapp(ctx: XdpContext) -> u32 {
    match try_ebpfapp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[map]
pub static mut SOURCE_ADDR_QUEUE: Queue<SourceAddr> = Queue::with_max_entries(1024, 0);

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn try_ebpfapp(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0).map_err(|e| {
        error!(&ctx, "prt_at err!");
        e
    })?;
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => {
            info!(&ctx, "not ipv4 packet");
            return Ok(xdp_action::XDP_PASS);
        }
    }

    info!(&ctx, "ipv4 packet");

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN).map_err(|e| {
        error!(&ctx, "prt_at err!");
        e
    })?;
    let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let mut protocol = IpProto::Tcp;

    let source_port = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be(unsafe { (*tcphdr).source })
        }
        IpProto::Udp => {
            protocol = IpProto::Udp;
            let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be(unsafe { (*udphdr).source })
        }
        IpProto::Icmp => {
            info!(&ctx, "icmp packet");
            return Ok(xdp_action::XDP_PASS);
        }
        _ => return Err(()),
    };

    info!(&ctx, "received a packet, proto: {}", protocol as u8);
    info!(&ctx, "SRC IP: {:i}, SRC PORT: {}", source_addr, source_port);

    let source_addr = SourceAddr {
        addr: source_addr,
        port: source_port,
    };
    unsafe {
        #[allow(static_mut_refs)]
        SOURCE_ADDR_QUEUE.push(&source_addr, 0).map_err(|e| {
            error!(&ctx, "push to queue err: {}", e);
        })?;
    }

    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
