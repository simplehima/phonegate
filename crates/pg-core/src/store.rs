//! Atomic, lock-protected JSON persistence. Access control (SYSTEM + Administrators only) is
//! applied to the directory by the installer / agent, not here.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::{Error, Result};

/// Holds an exclusive OS lock on `<file>.lock` until dropped.
pub struct FileLock {
    file: File,
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

fn lock_path(path: &Path) -> PathBuf {
    let mut p = path.as_os_str().to_owned();
    p.push(".lock");
    PathBuf::from(p)
}

pub fn lock(path: &Path) -> Result<FileLock> {
    let file = OpenOptions::new().create(true).truncate(false).write(true).open(lock_path(path))?;
    file.lock()?;
    Ok(FileLock { file })
}

pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match fs::read(path) {
        Ok(b) => serde_json::from_slice(&b).map(Some).map_err(|e| Error::Io(format!("corrupt state file {}: {e}", path.display()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Writes via temp file + fsync + rename so readers never see a partial file.
pub fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let data = serde_json::to_vec_pretty(value).map_err(|e| Error::Io(e.to_string()))?;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    {
        let mut f = File::create(&tmp)?;
        f.write_all(&data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Read-modify-write under the file lock. `f` receives `None` when the file does not exist.
pub fn update_json<T, R>(path: &Path, f: impl FnOnce(&mut Option<T>) -> Result<R>) -> Result<R>
where
    T: Serialize + DeserializeOwned,
{
    let _guard = lock(path)?;
    let mut value = read_json::<T>(path)?;
    let out = f(&mut value)?;
    if let Some(v) = &value {
        write_json_atomic(path, v)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_update() {
        let dir = std::env::temp_dir().join(format!("pg-store-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("s.json");
        let _ = fs::remove_file(&p);
        assert_eq!(read_json::<Vec<u32>>(&p).unwrap(), None);
        write_json_atomic(&p, &vec![1u32, 2]).unwrap();
        assert_eq!(read_json::<Vec<u32>>(&p).unwrap(), Some(vec![1, 2]));
        update_json::<Vec<u32>, _>(&p, |v| {
            v.as_mut().unwrap().push(3);
            Ok(())
        })
        .unwrap();
        assert_eq!(read_json::<Vec<u32>>(&p).unwrap(), Some(vec![1, 2, 3]));
        fs::write(&p, b"{not json").unwrap();
        assert!(read_json::<Vec<u32>>(&p).is_err(), "corrupt state must be an error, never silently empty");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_updates_do_not_lose_writes() {
        let dir = std::env::temp_dir().join(format!("pg-store-c-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("c.json");
        write_json_atomic(&p, &0u32).unwrap();
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let p = p.clone();
                std::thread::spawn(move || {
                    for _ in 0..25 {
                        update_json::<u32, _>(&p, |v| {
                            *v.as_mut().unwrap() += 1;
                            Ok(())
                        })
                        .unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(read_json::<u32>(&p).unwrap(), Some(200));
        let _ = fs::remove_dir_all(&dir);
    }
}
