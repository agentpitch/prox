use super::{DRIVER_NAME, DRIVER_SHA256};
use crate::platform;
use crate::updater::hash_reader;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use windows_sys::Win32::Storage::FileSystem::{
    MoveFileExW, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
    MOVEFILE_WRITE_THROUGH,
};

#[cfg(embedded_windivert_driver)]
const EMBEDDED: Option<&[u8]> = Some(include_bytes!(concat!(env!("OUT_DIR"), "/WinDivert64.sys")));
#[cfg(not(embedded_windivert_driver))]
const EMBEDDED: Option<&[u8]> = None;

pub(super) fn driver_path() -> io::Result<PathBuf> {
    Ok(std::env::current_exe()?.with_file_name(DRIVER_NAME))
}

pub(crate) fn extract_if_missing(path: &Path) -> io::Result<()> {
    let Some(bytes) = EMBEDDED else { return Ok(()) };
    match fs::symlink_metadata(path) {
        Ok(_) => return Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error),
    }

    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|error| io::Error::other(error.to_string()))?;
    let temporary = path.with_extension(format!("{:032x}.tmp", u128::from_ne_bytes(nonce)));
    let mut file = OpenOptions::new()
        .write(true)
        .share_mode(0)
        .create_new(true)
        .open(&temporary)?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    let result = written.and_then(|()| {
        let from = platform::wide(&temporary);
        let to = platform::wide(path);
        // Publish atomically and leave any pre-existing image alone.
        if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_WRITE_THROUGH) } != 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    });
    if let Err(error) = result {
        let _ = fs::remove_file(temporary);
        // Another instance may have created the file after the initial check.
        if error.kind() == io::ErrorKind::AlreadyExists || fs::symlink_metadata(path).is_ok() {
            return Ok(());
        }
        return Err(error);
    }
    Ok(())
}

pub(super) fn open_verified(path: &Path) -> io::Result<File> {
    extract_if_missing(path)?;
    let mut image = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| io::Error::new(error.kind(), format!("{}: {error}", path.display())))?;
    let info = image.metadata()?;
    if !info.is_file()
        || info.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || hash_reader(&mut image, 16 << 20)? != DRIVER_SHA256
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} is not the pinned WinDivert 2.2.2 driver",
                path.display()
            ),
        ));
    }
    Ok(image)
}

#[cfg(all(test, embedded_windivert_driver))]
mod tests {
    use super::*;

    #[test]
    fn extracts_the_original_driver_and_preserves_existing_files() {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).unwrap();
        let directory = std::env::temp_dir().join(format!(
            "pitchprox-embedded-driver-{:032x}",
            u128::from_ne_bytes(nonce)
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join(DRIVER_NAME);
        std::thread::scope(|threads| {
            for _ in 0..6 {
                threads.spawn(|| extract_if_missing(&path).unwrap());
            }
        });
        assert_eq!(fs::read(&path).unwrap(), EMBEDDED.unwrap());
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
        drop(open_verified(&path).unwrap());
        fs::write(&path, b"pre-existing file").unwrap();
        extract_if_missing(&path).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"pre-existing file");
        assert_eq!(
            open_verified(&path).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        fs::remove_file(&path).unwrap();
        fs::remove_dir(&directory).unwrap();
    }
}
