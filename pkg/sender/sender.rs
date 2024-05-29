#![feature(new_uninit)]
use anyhow::bail;
use aya::maps::{Array, XskMap};
use etherparse::{Ipv4Header, UdpHeader};
use log::info;
use std::mem::MaybeUninit;
use std::net::UdpSocket;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::{cell::UnsafeCell, num::NonZeroU32};

use xdpilone::xdp::XdpDesc;
use xdpilone::{BufIdx, IfInfo, RingRx, RingTx, Socket, SocketConfig, Umem, UmemConfig};

//We can use _any_ data mapping, so let's use a static one setup by the linker/loader.
#[repr(align(16384))]
struct PacketMap(MaybeUninit<[u8; 1 << 30]>);
// Safety: no instance used for unsynchronized data access.
unsafe impl Sync for PacketMap {}

// #[repr(align(4096))]
// struct PacketMap(MaybeUninit<[u8; 1 << 20]>);

pub fn start<T>(
    ifname: &str,
    server_addr: &str,
    cancelled: Arc<AtomicBool>,
    frequency: u64,
    mut socks: XskMap<T>,
    mut init: Array<T, u64>,
    threads: usize,
    clients: usize,
    start_port: usize,
) -> anyhow::Result<()>
where
    T: std::borrow::BorrowMut<aya::maps::MapData>,
{
    let umem_config = UmemConfig {
        fill_size: 1 << 16,
        complete_size: 1 << 16,
        ..Default::default()
    };

    let alloc = Box::new(PacketMap(MaybeUninit::uninit()));
    // Register the packet buffer with the kernel, getting an XDP socket file descriptor for it.
    let mem = NonNull::new(Box::leak(alloc).0.as_mut_ptr()).unwrap();

    // Safety: we guarantee this mapping is aligned, and will be alive. It is static, after-all.
    let umem = unsafe { Umem::new(umem_config, mem) }.unwrap();
    // Safety: don't access alloc down the line.
    // let mut alloc = Box::<PacketMap>::new_uninit();
    // let umem = {
    //     // Safety: this is a shared buffer between the kernel and us, uninitialized memory is valid.
    //     let mem = unsafe { alloc.assume_init_mut() }.0.into();
    //     // Safety: we cannot access `mem` further down the line because it falls out of scope.
    //     unsafe {
    //         Umem::new(
    //             umem_config,
    //             mem,
    //         )
    //         .expect("failed to generate umem")
    //     }
    // };

    // Safety: we guarantee this mapping is aligned, and will be alive. It is static, after-all.
    // let umem = unsafe {
    //     Umem::new(
    //         UmemConfig {
    //             fill_size: 1 << 14,
    //             complete_size: 1 << 14,
    //             ..Default::default()
    //         },
    //         mem,
    //     )
    // }
    // .expect("failed to generate umem");

    let mut bytes = String::from(ifname);
    bytes.push('\0');
    let bytes = bytes.as_bytes();
    let name = core::ffi::CStr::from_bytes_with_nul(bytes).unwrap();
    let mut info = IfInfo::invalid();
    info.from_name(name).unwrap();

    let sock = Socket::with_shared(&info, &umem).unwrap();
    // Get the fill/completion device (which handles the 'device queue').
    let device = umem.fq_cq(&sock).unwrap();

    let rxtx_config = SocketConfig {
        rx_size: NonZeroU32::new(1 << 4),
        tx_size: NonZeroU32::new(1 << 8),
        bind_flags: 0,
    };
    // let rxtx = umem.rx_tx(&sock, &rxtx_config).unwrap();

    // // assert!(rxtx.map_rx().is_ok(), "did not provide a rx_size");
    // // Map the TX queue into our memory space.
    // let mut rx = rxtx.map_rx().unwrap();
    // let tx = rxtx.map_tx().unwrap();

    // socks.set(0, rx.as_raw_fd(), 0).unwrap();

    let mut txs = vec![];
    let mut rx = None;

    let mut sock = Some(Socket::with_shared(&info, &umem).unwrap());
    (0..threads - 1).for_each(|_| {
        let sock = sock.take().unwrap_or_else(|| Socket::new(&info).unwrap());
        let rxtx = umem.rx_tx(&sock, &rxtx_config).unwrap();
        // Configure our receive/transmit queues.

        // Map the TX queue into our memory space.
        let tx = rxtx.map_tx().unwrap();

        if rx.is_none() {
            rx = Some(rxtx.map_rx().unwrap()); // get rx from only the first one
        }

        // Ready to bind, i.e. kernel to start doing things on the ring.
        umem.bind(&rxtx).unwrap();

        txs.push(tx);
    });

    let mut rx = rx.unwrap();
    socks.set(0, rx.as_raw_fd(), 0).unwrap();

    let frame = umem.frame(BufIdx(0)).unwrap();

    // Produce a frame to be filled by the kernel
    let mut device = device;

    {
        let mut writer = device.fill(1);
        writer.insert_once(frame.offset);
        writer.commit();
    }

    let sock = UdpSocket::bind("0.0.0.0:42001").unwrap();
    sock.send_to(&[0_u8; 100], server_addr).unwrap();

    info!("waiting for first response");

    while rx.available() == 0 {
        if !cancelled.load(Ordering::Relaxed) {
            return Ok(());
        }
    }

    let packet = rx.receive(1).read().unwrap();
    let buf = unsafe {
        &frame.addr.as_ref()[packet.addr as usize..(packet.addr as usize + packet.len as usize)]
    };

    let buf = etherparse::SlicedPacket::from_ethernet(buf).unwrap();
    let eth = buf.link.unwrap().to_header().unwrap().ethernet2().unwrap();

    let ipv4 = match buf.net.unwrap() {
        etherparse::NetSlice::Ipv4(ipv4) => ipv4.header().to_header(),
        etherparse::NetSlice::Ipv6(_) => bail!("got ipv6 packet?!"),
    };

    let udp = match buf.transport.unwrap() {
        etherparse::TransportSlice::Udp(u) => u.to_header(),
        _ => bail!("got something thats not udp packet!?"),
    };

    info!("received response");

    init.set(0, 1, 0).unwrap(); // throw away all future packets

    let packets = (0..clients)
        .map(|index| {
            let packet = etherparse::PacketBuilder::ethernet2(eth.destination, eth.source)
                .ipv4(ipv4.destination, ipv4.source, 120)
                .udp((start_port + index) as u16, udp.source_port);
            let payload = BUFFER1;

            let mut packet_data = Vec::<u8>::with_capacity(packet.size(payload.len()));

            packet.write(&mut packet_data, &payload).unwrap();

            let desc = {
                let Some(mut frame) = umem.frame(BufIdx(index as u32 + 1)) else {
                    panic!("failed buffer id with {}", index);
                };

                // Safety: we are the unique thread accessing this at the moment.
                prepare_buffer(frame.offset, unsafe { frame.addr.as_mut() }, &packet_data)
            };

            desc
        })
        .collect::<Vec<XdpDesc>>();

    let sent = AtomicU32::new(0);
    let completed = AtomicU32::new(0);
    let stall_count = AtomicU32::new(0);

    let completer = || loop {
        if cancelled.load(Ordering::Relaxed) {
            break;
        }

        // Number of completions reaped in this iteration.
        let comp_now: u32;
        let comp_batch = sent.load(Ordering::Relaxed);
        {
            // Try to dequeue some completions.
            let mut reader = device.complete(comp_batch);
            let mut comp_temp = 0;

            while reader.read().is_some() {
                comp_temp += 1;
            }

            comp_now = comp_temp;
            reader.release();
        }

        sent.fetch_sub(comp_now, Ordering::Relaxed);

        if comp_now == 0 {
            stall_count.fetch_add(1, Ordering::Relaxed);
        }
    };

    const WAKE_THRESHOLD: u32 = 1 << 2;

    let sender = |mut tx: RingTx, data: &[XdpDesc]| {
        let stall_threshold = WAKE_THRESHOLD;
        let data_len = data.len();
        info!("starting sender for {}", data_len);
        loop {
            if cancelled.load(Ordering::Relaxed) {
                break;
            }

            std::thread::sleep(Duration::from_millis(1000 / frequency));

            let sent_now: u32;

            {
                let descs = data.iter().copied();

                // Try to add descriptors to the transmit buffer.
                let mut writer = tx.transmit(data_len as u32);
                sent_now = writer.insert(descs);
                writer.commit();
            }

            if stall_count.load(Ordering::Relaxed) > stall_threshold {
                // It may be necessary to wake up. This is costly, in relative terms, so we avoid doing
                // it when the kernel proceeds without us. We detect this by checking if both queues
                // failed to make progress for some time.
                tx.wake();
                stall_count.fetch_sub(stall_threshold, Ordering::Relaxed);
            }

            sent.fetch_add(sent_now, Ordering::Relaxed);
        }
    };

    std::thread::scope(|scope| {
        scope.spawn(completer);

        let count_per_thread = clients / threads;
        for (index, tx) in txs.into_iter().enumerate() {
            let packets = &packets[index * count_per_thread..((index + 1) * count_per_thread)];
            scope.spawn(|| sender(tx, packets));
        }
    });

    Ok(())
}

fn prepare_buffer(offset: u64, buffer: &mut [u8], packet: &[u8]) -> XdpDesc {
    buffer[..packet.len()].copy_from_slice(packet);

    XdpDesc {
        addr: offset,
        len: packet.len() as u32,
        options: 0,
    }
}

static BUFFER1: [u8; 100] = [
    43, 20, 193, 151, 203, 27, 136, 87, 216, 82, 131, 147, 1, 55, 252, 8, 148, 181, 244, 139, 13,
    221, 95, 240, 225, 196, 121, 104, 250, 37, 96, 199, 202, 189, 37, 21, 38, 191, 143, 70, 5, 216,
    158, 166, 157, 90, 174, 206, 83, 233, 103, 2, 196, 72, 222, 56, 103, 189, 62, 182, 103, 108,
    249, 243, 6, 149, 13, 197, 50, 69, 99, 55, 38, 165, 163, 23, 13, 200, 12, 98, 26, 128, 194, 47,
    144, 149, 15, 212, 13, 64, 147, 2, 211, 20, 151, 117, 35, 99, 55, 190,
];
