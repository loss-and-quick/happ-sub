//! Desktop platform facts and cross-client telemetry mapping.

/// Raw unformatted desktop telemetry gathered from the host system.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DesktopFacts<'a> {
    /// Operating system name: `"Linux"` or `"Windows"`.
    pub os: &'a str,
    /// OS release identifier, e.g. from `/etc/os-release` `ID=` (e.g. `"nixos"`, `"ubuntu"`).
    pub os_release_id: &'a str,
    /// OS release version, e.g. from `/etc/os-release` `VERSION_ID=` (e.g. `"26.05"`, `"24.04"`).
    pub os_release_version: &'a str,
    /// Kernel release from `uname -r`, e.g. `"6.12.18"` or `"6.17.8-cachyos"`.
    pub kernel_release: &'a str,
    /// Hostname, e.g. from `/proc/sys/kernel/hostname` or `$HOSTNAME`.
    pub hostname: &'a str,
    /// CPU target architecture, e.g. from `uname -m` or `std::env::consts::ARCH` (`"x86_64"`, `"aarch64"`, `"x86"`).
    pub cpu_arch: &'a str,
    /// System username, e.g. `$USER` or `System.getProperty("user.name")`.
    pub username: &'a str,
    /// System machine ID from `/etc/machine-id` or Windows Registry `MachineGuid`.
    pub machine_id: Option<&'a str>,
    /// POSIX locale string, e.g. `"ru_RU.UTF-8"` or `"de_DE.UTF-8"`.
    pub posix_locale: &'a str,
    /// BCP-47 language tag, e.g. `"ru-RU"`. When empty, derived from `posix_locale`.
    pub language_tag: &'a str,
}

/// `QSysInfo::productType()` + `_` + `productVersion()`: os-release `ID` and
/// `VERSION_ID`, each `"unknown"` when missing.
pub fn qt_product(id: &str, version_id: &str) -> String {
    let i = if id.trim().is_empty() {
        "unknown"
    } else {
        id.trim()
    };
    let v = if version_id.trim().is_empty() {
        "unknown"
    } else {
        version_id.trim()
    };
    format!("{i}_{v}")
}

/// Parse `ID=` and `VERSION_ID=` from `/etc/os-release` content into `(id, version_id)`.
pub fn parse_os_release(os_release: &str) -> (String, String) {
    let field = |key: &str| {
        os_release
            .lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
            .map(|v| v.trim().trim_matches(['"', '\'']).to_owned())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "unknown".into())
    };
    (field("ID"), field("VERSION_ID"))
}

/// `QSysInfo::currentCpuArchitecture()` for a target architecture.
pub fn qt_cpu_architecture(arch: &str) -> &str {
    match arch {
        "x86" => "i386",
        "aarch64" => "arm64",
        other => other,
    }
}

/// Subslice of `posix_locale` up to the first `.` or `@` character, trimmed.
///
/// Returns `"C"` if empty or `"POSIX"`.
pub fn qt_locale_subslice(posix: &str) -> &str {
    let trimmed = posix.trim();
    let name = trimmed.split(['.', '@']).next().unwrap_or_default();
    if name.is_empty() || name == "C" || name == "POSIX" {
        "C"
    } else {
        name
    }
}

/// `QLocale::name()` for a POSIX locale: `language_TERRITORY` without codeset/modifier,
/// or `"C"`.
pub fn qt_locale_name(posix: &str) -> String {
    qt_locale_subslice(posix).to_string()
}

/// Maps target CPU architecture to JVM `os.arch` format on desktop.
pub fn jvm_os_arch(arch: &str) -> &str {
    match arch {
        "x86_64" | "amd64" => "amd64",
        "aarch64" | "arm64" => "aarch64",
        "x86" | "i386" | "i686" => "x86",
        other => other,
    }
}

/// Checks whether a system hardware identifier is valid.
///
/// Observed in Happ desktop (`0x2f5920`), which trims whitespace and rejects strings that are
/// empty or contain only `'0'` and `'-'` characters (such as all-zero UUIDs).
pub fn is_valid_sys_hwid(s: &str) -> bool {
    let trimmed = s.trim();
    !trimmed.is_empty() && trimmed.bytes().any(|b| b != b'0' && b != b'-')
}

/// Returns true if an identifier string is a known dummy/bogus hardware serial or UUID.
///
/// Observed in Happ desktop (`0x3b48e0`), which filters out OEM placeholder strings, default
/// sequences, and dummy serial numbers before generating the fallback identifier.
pub fn is_bogus_machine_id(id: &str) -> bool {
    let s = id.trim().to_ascii_lowercase();
    matches!(
        s.as_str(),
        "" | "1234567890"
            | "0123456789"
            | "o.e.m"
            | "o.e.m."
            | "oem"
            | "default string"
            | "serial number"
            | "none"
            | "null"
            | "chassis serial number"
            | "system serial number"
            | "to be filled by o.e.m."
            | "to be filled by o.e.m"
            | "not applicable"
            | "na"
            | "n/a"
            | "system manufacturer"
            | "system product name"
    ) || !is_valid_sys_hwid(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qt_product_formatting() {
        assert_eq!(qt_product("nixos", "26.05"), "nixos_26.05");
        assert_eq!(qt_product("ubuntu", "24.04"), "ubuntu_24.04");
        assert_eq!(qt_product("arch", ""), "arch_unknown");
        assert_eq!(qt_product("", ""), "unknown_unknown");
    }

    #[test]
    fn parse_os_release_sample() {
        let text = "NAME=NixOS\nID=nixos\nVERSION_ID=\"26.05\"\nPRETTY_NAME=\"NixOS 26.05\"\n";
        let (id, ver) = parse_os_release(text);
        assert_eq!(id, "nixos");
        assert_eq!(ver, "26.05");
        assert_eq!(qt_product(&id, &ver), "nixos_26.05");

        let debian = "ID_LIKE=debian\nID=ubuntu\nVERSION_ID=24.04\n";
        let (id, ver) = parse_os_release(debian);
        assert_eq!(id, "ubuntu");
        assert_eq!(ver, "24.04");
        assert_eq!(qt_product(&id, &ver), "ubuntu_24.04");
    }

    #[test]
    fn qt_cpu_architecture_mapping() {
        assert_eq!(qt_cpu_architecture("x86_64"), "x86_64");
        assert_eq!(qt_cpu_architecture("aarch64"), "arm64");
        assert_eq!(qt_cpu_architecture("x86"), "i386");
    }

    #[test]
    fn jvm_os_arch_mapping() {
        assert_eq!(jvm_os_arch("x86_64"), "amd64");
        assert_eq!(jvm_os_arch("amd64"), "amd64");
        assert_eq!(jvm_os_arch("aarch64"), "aarch64");
        assert_eq!(jvm_os_arch("arm64"), "aarch64");
        assert_eq!(jvm_os_arch("x86"), "x86");
        assert_eq!(jvm_os_arch("i386"), "x86");
    }

    #[test]
    fn qt_locale_subslice_formatting() {
        assert_eq!(qt_locale_subslice("ru_RU.UTF-8"), "ru_RU");
        assert_eq!(qt_locale_subslice("de_DE.UTF-8"), "de_DE");
        assert_eq!(qt_locale_subslice("sr_RS@latin"), "sr_RS");
        assert_eq!(qt_locale_subslice("C.UTF-8"), "C");
        assert_eq!(qt_locale_subslice("POSIX"), "C");
        assert_eq!(qt_locale_subslice(""), "C");
    }
}
