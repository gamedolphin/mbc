use std::ptr::NonNull;
use std::time::Duration;
use std::{cell::UnsafeCell, num::NonZeroU32};

use xdpilone::xdp::XdpDesc;
use xdpilone::{BufIdx, IfInfo, Socket, SocketConfig, Umem, UmemConfig};

// We can use _any_ data mapping, so let's use a static one setup by the linker/loader.
#[repr(align(4096))]
struct PacketMap(UnsafeCell<[u8; 1 << 20]>);
// Safety: no instance used for unsynchronized data access.
unsafe impl Sync for PacketMap {}

static MEM: PacketMap = PacketMap(UnsafeCell::new([0; 1 << 20]));

pub async fn start(ifname: &str) -> anyhow::Result<()> {
    let mem = NonNull::new(MEM.0.get()).unwrap();

    // Safety: we guarantee this mapping is aligned, and will be alive. It is static, after-all.
    let umem = unsafe { Umem::new(UmemConfig::default(), mem) }.unwrap();

    let mut bytes = String::from(ifname);
    bytes.push('\0');
    let bytes = bytes.as_bytes();
    let name = core::ffi::CStr::from_bytes_with_nul(bytes).unwrap();
    let mut info = IfInfo::invalid();
    info.from_name(name).unwrap();

    let sock = Socket::with_shared(&info, &umem).unwrap();
    // Get the fill/completion device (which handles the 'device queue').
    let device = umem.fq_cq(&sock).unwrap();

    let rxtx = umem
        .rx_tx(
            &sock,
            &SocketConfig {
                rx_size: None,
                tx_size: NonZeroU32::new(1 << 14),
                bind_flags: SocketConfig::XDP_BIND_ZEROCOPY | SocketConfig::XDP_BIND_NEED_WAKEUP,
            },
        )
        .unwrap();

    assert!(rxtx.map_rx().is_err(), "did not provide a rx_size");
    // Map the TX queue into our memory space.
    let tx = rxtx.map_tx().unwrap();

    umem.bind(&rxtx).unwrap();

    let desc = {
        let mut frame = umem.frame(BufIdx(1)).unwrap();
        // Safety: we are the unique thread accessing this at the moment.
        prepare_buffer(frame.offset, unsafe { frame.addr.as_mut() })
    };

    let mut interval = monoio::time::interval(Duration::from_millis(100));

    let mut tx = tx;
    let mut device = device;

    loop {
        interval.tick().await;
        {
            // Try to add descriptors to the transmit buffer.
            let mut writer = tx.transmit(1);
            let bufs = core::iter::repeat(desc);
            writer.insert(bufs);
            writer.commit();
        }

        if tx.needs_wakeup() {
            tx.wake();
        }

        {
            // Try to dequeue some completions.
            let mut reader = device.complete(1);

            while reader.read().is_some() {}

            reader.release();
        }
    }

    Ok(())
}

fn prepare_buffer(offset: u64, buffer: &mut [u8]) -> XdpDesc {
    let builder = etherparse::PacketBuilder::ethernet2(
        [1, 2, 3, 4, 5, 6], //source mac
        [7, 8, 9, 10, 11, 12],
    ) //destination mac
    .ipv4(
        [192, 168, 1, 1], //source ip
        [192, 168, 1, 2], //destination ip
        20,
    ) //time to life
    .udp(
        21, //source port
        1234,
    ); //destination port

    buffer[..ETHERNET_PACKET.len()].copy_from_slice(&ETHERNET_PACKET[..]);

    XdpDesc {
        addr: offset,
        len: ETHERNET_PACKET.len() as u32,
        options: 0,
    }
}

#[rustfmt::skip]
const ETHERNET_PACKET: [u8; 126] = [
    0x01, 0x00, 0x5E, 0x00, 0x00, 0x09, 0xC2, 0x01, 0x17, 0x23, 0x00, 0x00, 0x08, 0x00, 0x45, 0xC0, 0x00, 0x70, 0x00, 0x00, 0x00, 0x00, 0x02, 0x11, 0xCD, 0xB2, 0x0A, 0x00, 0x00, 0x02, 0xE0, 0x00, 0x00, 0x09, 0x02, 0x08, 0x02, 0x08, 0x00, 0x5C, 0x75, 0xA9, 0x02, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x08, 0xFF, 0xFF, 0xFF, 0xFC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x0C, 0xFF, 0xFF, 0xFF, 0xFC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0xC0, 0xA8, 0x02, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0xC0, 0xA8, 0x04, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
];
