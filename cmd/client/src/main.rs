use std::borrow::{Borrow, BorrowMut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use aya::maps::{Array, MapData, XskMap};
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use env_logger::Env;
use log::{debug, info, warn};

pub fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    let iface = opt.iface.clone();

    let (s, r) = crossbeam::channel::bounded(1);

    // let opt = Opt::parse();
    let join: std::thread::JoinHandle<anyhow::Result<()>> = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        let join: anyhow::Result<()> = rt.block_on(async move {
            #[cfg(debug_assertions)]
            let mut bpf = Bpf::load(include_bytes_aligned!(
                "../../../ebpf/client-xdp/target/bpfel-unknown-none/debug/client-xdp"
            ))?;

            #[cfg(not(debug_assertions))]
            let mut bpf = Bpf::load(include_bytes_aligned!(
                "../../../ebpf/client-xdp/target/bpfel-unknown-none/release/client-xdp"
            ))?;

            let socks: XskMap<_> = bpf.take_map("SOCKS").unwrap().try_into().unwrap();

            if let Err(e) = BpfLogger::init(&mut bpf) {
                // This can happen if you remove all log statements from your eBPF program.
                warn!("failed to initialize eBPF logger: {}", e);
            }

            let stats: Array<_,u64> = bpf.take_map("STATS").unwrap().try_into().unwrap();
            let d: Array<_,u64> = bpf.take_map("TRACKER").unwrap().try_into().unwrap();

            tokio::spawn(async move {
                track_packets(stats).await;
            });

            let program: &mut Xdp = bpf.program_mut("client_xdp").unwrap().try_into()?;
            program.load()?;
            program.attach(&opt.iface, XdpFlags::default())
                .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

            info!("loaded client xdp");

            s.send((socks, d)).unwrap();

            info!("Waiting for Ctrl-C...");
            tokio::signal::ctrl_c().await?;
            info!("Exiting...");

            Ok(())
        });

        join
    });

    let cancelled = Arc::new(AtomicBool::new(false));
    let cloned = cancelled.clone();
    let (socks, init) = r.recv().unwrap();
    let other = std::thread::spawn(move || {
        sender::start(
            &iface,
            &opt.server_addr,
            cloned,
            opt.frequency,
            socks,
            init,
            opt.thread_count,
            opt.client_count,
            opt.start_port,
        )
    });
    join.join().expect("failed to join listening thread")?;

    cancelled.store(true, Ordering::Relaxed);

    other.join().expect("failed to join sending thread")?;

    Ok(())
}

async fn track_packets<T: Borrow<MapData> + BorrowMut<MapData>>(mut stats: Array<T, u64>) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));

    loop {
        interval.tick().await;
        let Ok(v) = stats.get(&0, 0) else {
            continue;
        };

        if v > 0 {
            info!("processed packets: {}", v);
            stats.set(0, 0, 0).unwrap();
        }
    }
}

#[derive(clap::Parser, Debug)]
#[command(version, about, long_about = None)]
struct Opt {
    #[arg(short, long)]
    iface: String,

    #[arg(short, long)]
    server_addr: String,

    #[arg(short, long, default_value = "1")]
    frequency: u64,

    #[arg(short, long, default_value = "1")]
    client_count: usize,

    #[arg(short, long, default_value = "1")]
    thread_count: usize,

    #[arg(short, long, default_value = "42002")]
    start_port: usize,
}
