use std::borrow::{Borrow, BorrowMut};
use std::time::Duration;

use anyhow::Context;
use aya::maps::{Array, IterableMap, MapData};
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use env_logger::Env;
use log::{debug, info, warn};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long)]
    iface: String,
}

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
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

    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../../ebpf/server-xdp/target/bpfel-unknown-none/debug/server-xdp"
    ))?;

    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../../ebpf/server-xdp/target/bpfel-unknown-none/release/server-xdp"
    ))?;

    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let stats: Array<_, u64> = bpf.take_map("STATS").unwrap().try_into().unwrap();

    tokio::spawn(async move { track_packets(stats).await });

    let program: &mut Xdp = bpf.program_mut("server_xdp").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    info!("Waiting for Ctrl-C...");
    tokio::signal::ctrl_c().await?;
    info!("Exiting...");

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

#[derive(clap::Parser)]
struct Args {
    /// The name of the interface to use.
    ifname: String,
}
