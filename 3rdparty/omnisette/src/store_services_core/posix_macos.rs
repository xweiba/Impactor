pub use libc::{
    chmod, close, free, ftruncate, gettimeofday, malloc, mkdir, read, strncpy, umask, write,
};

use libc::{
    fstat as fstat_macos, lstat as lstat_macos, open as open_macos, stat as stat_macos, O_CREAT,
    O_RDONLY, O_RDWR, O_WRONLY,
};

use android_loader::sysv64;

#[repr(C)]
pub struct StatLinux {
    pub st_dev: u64,
    pub st_ino: u64,
    #[cfg(target_arch = "x86_64")]
    pub st_nlink: u64,
    pub st_mode: u32,
    #[cfg(target_arch = "aarch64")]
    pub st_nlink: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    #[cfg(target_arch = "x86_64")]
    __pad0: libc::c_int,
    pub st_rdev: u64,
    #[cfg(target_arch = "aarch64")]
    __pad1: u64,
    pub st_size: i64,
    #[cfg(target_arch = "x86_64")]
    pub st_blksize: i64,
    #[cfg(target_arch = "aarch64")]
    pub st_blksize: i32,
    #[cfg(target_arch = "aarch64")]
    __pad2: i32,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_atime_nsec: i64,
    pub st_mtime: i64,
    pub st_mtime_nsec: i64,
    pub st_ctime: i64,
    pub st_ctime_nsec: i64,
    #[cfg(target_arch = "x86_64")]
    __unused: [i64; 3],
    #[cfg(target_arch = "aarch64")]
    __unused: [u32; 2],
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        ffi::CString,
        mem::{offset_of, size_of},
        os::unix::fs::PermissionsExt,
    };

    #[test]
    fn android_stat_layout_matches_target_abi() {
        #[cfg(target_arch = "aarch64")]
        {
            assert_eq!(size_of::<StatLinux>(), 128);
            assert_eq!(offset_of!(StatLinux, st_mode), 16);
            assert_eq!(offset_of!(StatLinux, st_size), 48);
        }
        #[cfg(target_arch = "x86_64")]
        {
            assert_eq!(size_of::<StatLinux>(), 144);
            assert_eq!(offset_of!(StatLinux, st_mode), 24);
            assert_eq!(offset_of!(StatLinux, st_size), 48);
        }
    }

    #[test]
    fn android_file_hooks_preserve_mode_size_and_failures() {
        let path = std::env::temp_dir().join(format!("omnisette-posix-{}", uuid::Uuid::new_v4()));
        let cpath = CString::new(path.to_str().unwrap()).unwrap();
        unsafe {
            let fd = open(cpath.as_ptr(), 0o100 | 0o200 | 0o2, 0o600);
            assert!(fd >= 0);
            assert_eq!(write(fd, b"abc".as_ptr().cast(), 3), 3);
            let mut st: StatLinux = std::mem::zeroed();
            assert_eq!(fstat(fd, &mut st), 0);
            assert_eq!(st.st_size, 3);
            assert_eq!(st.st_mode & 0o777, 0o600);
            close(fd);
            assert_eq!(fstat(-1, &mut st), -1);
            assert_eq!(lstat(cpath.as_ptr(), &mut st), 0);
            assert_eq!(st.st_size, 3);
        }
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_file(&path).unwrap();
        unsafe {
            let mut st: StatLinux = std::mem::zeroed();
            assert_eq!(lstat(cpath.as_ptr(), &mut st), -1);
        }
    }
}

#[sysv64]
pub unsafe fn lstat(path: *const libc::c_char, buf: *mut StatLinux) -> libc::c_int {
    let mut st: stat_macos = std::mem::zeroed();
    let result = lstat_macos(path, &mut st);
    if result != 0 {
        return result;
    }
    *buf = StatLinux {
        st_dev: st.st_dev as _,
        st_ino: st.st_ino as _,
        st_nlink: st.st_nlink as _,
        st_mode: st.st_mode as _,
        st_uid: st.st_uid as _,
        st_gid: st.st_gid as _,
        #[cfg(target_arch = "x86_64")]
        __pad0: 0,
        st_rdev: st.st_rdev as _,
        #[cfg(target_arch = "aarch64")]
        __pad1: 0,
        st_size: st.st_size as _,
        st_blksize: st.st_blksize as _,
        #[cfg(target_arch = "aarch64")]
        __pad2: 0,
        st_blocks: st.st_blocks as _,
        st_atime: st.st_atime as _,
        st_atime_nsec: st.st_atime_nsec as _,
        st_mtime: st.st_mtime as _,
        st_mtime_nsec: st.st_mtime_nsec as _,
        st_ctime: st.st_ctime as _,
        st_ctime_nsec: st.st_ctime_nsec as _,
        #[cfg(target_arch = "x86_64")]
        __unused: [0; 3],
        #[cfg(target_arch = "aarch64")]
        __unused: [0; 2],
    };
    0
}

#[sysv64]
pub unsafe fn fstat(fildes: libc::c_int, buf: *mut StatLinux) -> libc::c_int {
    let mut st: stat_macos = std::mem::zeroed();
    let result = fstat_macos(fildes, &mut st);
    if result != 0 {
        return result;
    }
    *buf = StatLinux {
        st_dev: st.st_dev as _,
        st_ino: st.st_ino as _,
        st_nlink: st.st_nlink as _,
        st_mode: st.st_mode as _,
        st_uid: st.st_uid as _,
        st_gid: st.st_gid as _,
        #[cfg(target_arch = "x86_64")]
        __pad0: 0,
        st_rdev: st.st_rdev as _,
        #[cfg(target_arch = "aarch64")]
        __pad1: 0,
        st_size: st.st_size as _,
        st_blksize: st.st_blksize as _,
        #[cfg(target_arch = "aarch64")]
        __pad2: 0,
        st_blocks: st.st_blocks as _,
        st_atime: st.st_atime as _,
        st_atime_nsec: st.st_atime_nsec as _,
        st_mtime: st.st_mtime as _,
        st_mtime_nsec: st.st_mtime_nsec as _,
        st_ctime: st.st_ctime as _,
        st_ctime_nsec: st.st_ctime_nsec as _,
        #[cfg(target_arch = "x86_64")]
        __unused: [0; 3],
        #[cfg(target_arch = "aarch64")]
        __unused: [0; 2],
    };
    0
}

#[sysv64]
pub unsafe fn open(
    path: *const libc::c_char,
    oflag: libc::c_int,
    mode: libc::c_uint,
) -> libc::c_int {
    let mut win_flag = 0; // binary mode

    if oflag & 0o100 != 0 {
        win_flag |= O_CREAT;
    }

    if oflag & 0o1 == 1 {
        win_flag |= O_WRONLY;
    } else if oflag & 0o2 != 0 {
        win_flag |= O_RDWR;
    } else {
        win_flag |= O_RDONLY;
    }

    // Android passes mode in a register; Darwin's variadic open expects it on
    // the stack on ARM64. Calling libc here performs that ABI conversion.
    for (android, darwin) in [
        (0o200, libc::O_EXCL),
        (0o1000, libc::O_TRUNC),
        (0o2000, libc::O_APPEND),
    ] {
        if oflag & android != 0 {
            win_flag |= darwin;
        }
    }
    let val = if oflag & 0o100 != 0 {
        open_macos(path, win_flag, mode)
    } else {
        open_macos(path, win_flag)
    };

    val
}
