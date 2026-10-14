//! Signer-certificate sets shared by the per-client device-identity modules.
//!
//! These are the types [`crate::device`] uses for Happ and [`crate::incy_signers`] for Incy. They
//! live outside `device` so that a caller who only needs one client's certificate set does not
//! pull in the `device` feature's dependencies.

/// APK signature scheme whose certificates Android hands to the SSAID derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SigScheme {
    /// JAR signing.
    V1,
    /// APK Signature Scheme v2.
    V2,
    /// APK Signature Scheme v3.
    V3,
    /// APK Signature Scheme v3.1.
    V31,
}

/// Signer certificates of the highest verified scheme of one APK, in signing-block order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignerSet {
    /// Scheme the certificates come from; Android never mixes schemes.
    pub scheme: SigScheme,
    /// DER-encoded X.509 certificates.
    pub certs: &'static [&'static [u8]],
    /// APK version the certificates were extracted from.
    pub apk_version: &'static str,
}
