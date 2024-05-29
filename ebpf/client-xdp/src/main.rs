#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{Array, CpuMap, DevMap, DevMapHash, XskMap},
    memcpy,
    programs::XdpContext,
};
use aya_log_ebpf::{info, WriteToBuf};
use core::{hash::Hasher, mem};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

#[map]
static SOCKS: XskMap = XskMap::with_max_entries(8, 0);

#[map]
static STATS: Array<u64> = Array::with_max_entries(1, 0);

#[map]
static TRACKER: Array<u64> = Array::with_max_entries(1, 0);

#[xdp]
pub fn client_xdp(ctx: XdpContext) -> u32 {
    match client_receiver(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn client_receiver(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr_ptr = ptr_at(&ctx, 0)?;
    let ethhdr: EthHdr = unsafe { *ethhdr_ptr };

    match ethhdr.ether_type {
        EtherType::Loop => {}
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr_ptr: *mut Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let ipv4hdr: Ipv4Hdr = unsafe { *ipv4hdr_ptr };

    if ipv4hdr.proto == IpProto::Tcp {
        info!(&ctx, "tcp packet received, ignored!");
        return Ok(xdp_action::XDP_PASS); // dont care about tcp packets, let them through
    }

    // let _source_addr = u32::from_be(ipv4hdr.src_addr);

    let udphdr_ptr: *mut UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    let udphdr: UdpHdr = unsafe { *udphdr_ptr };

    let source_port = u16::from_be(udphdr.source);

    if source_port != 32001 {
        // info!(
        //     &ctx,
        //     "IGNORING OTHER: {} from {}:{}",
        //     dest_port,
        //     source_addr,
        //     u16::from_be(udphdr.source),
        // );
        return Ok(xdp_action::XDP_PASS);
    }

    if let Some(v) = STATS.get_ptr_mut(0) {
        unsafe { *v += 1 };
    }

    if let Some(v) = TRACKER.get_ptr_mut(0) {
        unsafe {
            if *v != 0 {
                return Ok(xdp_action::XDP_DROP);
            }
        }
    }

    Ok(SOCKS.redirect(0, 0).unwrap_or(xdp_action::XDP_ABORTED))
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *mut T)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
