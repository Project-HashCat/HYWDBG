#[cfg(windows)]
mod winapi_impl;

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    winapi_impl::main_impl()
}

#[cfg(not(windows))]
fn main() {
    eprintln!("winapi-backend only builds for Windows");
}
