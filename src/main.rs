use clap::Parser;
use std::fmt::Write as _;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser)]
#[command(version, about = "Query extended Linux file metadata")]
struct Args {
    #[arg(required = true, value_name = "PATH")]
    paths: Vec<PathBuf>,
    #[arg(long, help = "Inspect symbolic link targets")]
    dereference: bool,
    #[arg(long, help = "Emit a JSON array; unavailable fields are null")]
    json: bool,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Timestamp {
    seconds: i64,
    nanoseconds: u32,
    reserved: i32,
}

#[repr(C)]
#[derive(Default)]
struct Metadata {
    mask: u32,
    block_size: u32,
    attributes: u64,
    links: u32,
    uid: u32,
    gid: u32,
    mode: u16,
    reserved: u16,
    inode: u64,
    size: u64,
    blocks: u64,
    attributes_mask: u64,
    access: Timestamp,
    birth: Timestamp,
    change: Timestamp,
    modification: Timestamp,
    special_major: u32,
    special_minor: u32,
    device_major: u32,
    device_minor: u32,
    mount_id: u64,
    memory_alignment: u32,
    offset_alignment: u32,
    spare: [u64; 12],
}

#[cfg(target_os = "linux")]
mod ffi {
    use super::Metadata;
    use std::ffi::{CString, c_char, c_int, c_uint};
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    unsafe extern "C" {
        fn statx(
            dirfd: c_int,
            path: *const c_char,
            flags: c_int,
            mask: c_uint,
            buffer: *mut Metadata,
        ) -> c_int;
    }

    pub fn query(path: &Path, dereference: bool) -> io::Result<Metadata> {
        let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "path contains a null byte")
        })?;
        let mut metadata = Metadata::default();
        let flags = if dereference { 0 } else { 0x100 };
        let result = unsafe { statx(-100, path.as_ptr(), flags, 0x1fff, &mut metadata) };
        if result == 0 {
            return Ok(metadata);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(38) {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("statx is unavailable on this kernel: {error}"),
            ))
        } else {
            Err(error)
        }
    }
}

fn query(path: &Path, dereference: bool) -> io::Result<Metadata> {
    #[cfg(target_os = "linux")]
    {
        ffi::query(path, dereference)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, dereference);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "statx is unavailable on this platform; Linux is required",
        ))
    }
}

fn quoted(value: &str) -> String {
    let mut output = String::from("\"");
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character <= '\u{1f}' => {
                write!(output, "\\u{:04x}", character as u32).unwrap();
            }
            character => output.push(character),
        }
    }
    output.push('"');
    output
}

fn timestamp(value: Timestamp) -> String {
    let total = i128::from(value.seconds) * 1_000_000_000 + i128::from(value.nanoseconds);
    let magnitude = total.abs();
    format!(
        "{}{}.{:09}",
        if total < 0 { "-" } else { "" },
        magnitude / 1_000_000_000,
        magnitude % 1_000_000_000
    )
}

fn file_type(mode: u16) -> &'static str {
    match mode & 0xf000 {
        0x1000 => "FIFO",
        0x2000 => "character device",
        0x4000 => "directory",
        0x6000 => "block device",
        0x8000 => "regular file",
        0xa000 => "symbolic link",
        0xc000 => "socket",
        _ => "unknown",
    }
}

fn fields(metadata: &Metadata) -> Vec<(&'static str, Option<String>)> {
    let available = |mask, value| (metadata.mask & mask != 0).then_some(value);
    let mut fields = vec![
        ("type", available(0x1, quoted(file_type(metadata.mode)))),
        ("size", available(0x200, metadata.size.to_string())),
        ("inode", available(0x100, metadata.inode.to_string())),
        ("links", available(0x4, metadata.links.to_string())),
        ("uid", available(0x8, metadata.uid.to_string())),
        ("gid", available(0x10, metadata.gid.to_string())),
        (
            "permissions",
            available(0x2, quoted(&format!("{:04o}", metadata.mode & 0xfff))),
        ),
        ("device_major", Some(metadata.device_major.to_string())),
        ("device_minor", Some(metadata.device_minor.to_string())),
        (
            "special_device_major",
            Some(metadata.special_major.to_string()),
        ),
        (
            "special_device_minor",
            Some(metadata.special_minor.to_string()),
        ),
        ("access_time", available(0x20, timestamp(metadata.access))),
        (
            "modification_time",
            available(0x40, timestamp(metadata.modification)),
        ),
        (
            "status_change_time",
            available(0x80, timestamp(metadata.change)),
        ),
        ("birth_time", available(0x800, timestamp(metadata.birth))),
        ("mount_id", available(0x1000, metadata.mount_id.to_string())),
        ("availability_mask", Some(metadata.mask.to_string())),
        ("attributes", Some(metadata.attributes.to_string())),
        (
            "attributes_mask",
            Some(metadata.attributes_mask.to_string()),
        ),
    ];
    for (name, bit) in [
        ("compressed", 0x4),
        ("immutable", 0x10),
        ("append_only", 0x20),
        ("no_dump", 0x40),
        ("encrypted", 0x800),
        ("automount", 0x1000),
        ("mount_root", 0x2000),
        ("verity", 0x100000),
        ("dax", 0x200000),
        ("write_atomic", 0x400000),
    ] {
        fields.push((
            name,
            (metadata.attributes_mask & bit != 0)
                .then(|| (metadata.attributes & bit != 0).to_string()),
        ));
    }
    fields
}

fn run(args: Args) -> io::Result<bool> {
    let stdout = io::stdout();
    let mut output = io::BufWriter::new(stdout.lock());
    let mut failed = false;
    if args.json {
        write!(output, "[")?;
    }
    for (index, path) in args.paths.iter().enumerate() {
        let path_label = quoted(&path.to_string_lossy());
        if args.json {
            if index != 0 {
                write!(output, ",")?;
            }
            write!(output, "{{\"path\":{path_label}")?;
        } else {
            writeln!(output, "{path_label}:")?;
        }
        match query(path, args.dereference) {
            Ok(metadata) => {
                for (name, value) in fields(&metadata) {
                    if args.json {
                        write!(
                            output,
                            ",{}:{}",
                            quoted(name),
                            value.as_deref().unwrap_or("null")
                        )?;
                    } else {
                        writeln!(
                            output,
                            "  {name}: {}",
                            value.as_deref().unwrap_or("unavailable")
                        )?;
                    }
                }
            }
            Err(error) => {
                failed = true;
                eprintln!("statx: {path_label}: {error}");
                if args.json {
                    write!(output, ",\"error\":{}", quoted(&error.to_string()))?;
                } else {
                    writeln!(output, "  error: {error}")?;
                }
            }
        }
        if args.json {
            write!(output, "}}")?;
        }
    }
    if args.json {
        writeln!(output, "]")?;
    }
    output.flush()?;
    Ok(failed)
}

fn main() -> ExitCode {
    match run(Args::parse()) {
        Ok(false) => ExitCode::SUCCESS,
        Ok(true) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("statx: output: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_escapes_paths_and_controls() {
        assert_eq!(
            quoted("a\"\\\n\r\t\0\u{1f}é"),
            "\"a\\\"\\\\\\n\\r\\t\\u0000\\u001fé\""
        );
    }

    #[test]
    fn timestamps_preserve_nanoseconds_before_epoch() {
        let value = |seconds, nanoseconds| Timestamp {
            seconds,
            nanoseconds,
            reserved: 0,
        };
        assert_eq!(timestamp(value(12, 3)), "12.000000003");
        assert_eq!(timestamp(value(-1, 500_000_000)), "-0.500000000");
        assert_eq!(
            timestamp(value(i64::MIN, 0)),
            "-9223372036854775808.000000000"
        );
    }

    #[test]
    fn masks_distinguish_unavailable_from_zero_and_false() {
        let metadata = Metadata {
            mask: 0x200,
            attributes_mask: 0x10,
            ..Metadata::default()
        };
        let values = fields(&metadata);
        let get = |key| {
            values
                .iter()
                .find(|(name, _)| *name == key)
                .unwrap()
                .1
                .as_deref()
        };
        assert_eq!(get("size"), Some("0"));
        assert_eq!(get("inode"), None);
        assert_eq!(get("birth_time"), None);
        assert_eq!(get("immutable"), Some("false"));
        assert_eq!(get("compressed"), None);
    }

    #[test]
    fn statx_layout_matches_linux_abi() {
        assert_eq!(std::mem::size_of::<Metadata>(), 256);
        assert_eq!(std::mem::offset_of!(Metadata, access), 64);
        assert_eq!(std::mem::offset_of!(Metadata, mount_id), 144);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn real_statx_inspects_links_and_targets() {
        use std::os::unix::fs::symlink;
        let directory = PathBuf::from("target").join(format!("statx-test-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let file = directory.join("sample");
        let link = directory.join("link");
        std::fs::write(&file, b"Linux metadata sample\n").unwrap();
        symlink("sample", &link).unwrap();
        let direct = query(&file, false).unwrap();
        assert_eq!(direct.size, 22);
        assert_ne!(direct.mask & 0x200, 0);
        assert_eq!(
            file_type(query(&link, false).unwrap().mode),
            "symbolic link"
        );
        assert_eq!(query(&link, true).unwrap().inode, direct.inode);
        assert!(query(&directory.join("missing"), false).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
