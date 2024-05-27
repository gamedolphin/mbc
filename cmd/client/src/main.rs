pub fn main() -> anyhow::Result<()> {
    let args = <Args as clap::Parser>::parse();

    let sender_thread: std::thread::JoinHandle<anyhow::Result<()>> =
        std::thread::spawn(move || {
            let mut rt = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
                .with_entries(32768)
                .enable_timer()
                .build()
                .expect("failed to start monoio runtime");
            rt.block_on(async move {
                sender::start(&args.ifname).await?;

                Ok(())
            })
        });

    sender_thread
        .join()
        .expect("failed to join sender thread")?;

    Ok(())
}

#[derive(clap::Parser)]
struct Args {
    /// The name of the interface to use.
    ifname: String,
}
