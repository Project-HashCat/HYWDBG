//! TitanEngine binding placeholder.
//!
//! Default backend compiles without linking TitanEngine.
//! Later add feature `real-titan` and dynamic-load TitanEngine.dll.

#[cfg(all(windows, feature = "real-titan"))]
mod real {
    // TODO: exact TitanEngine ABI wrapper.
}
