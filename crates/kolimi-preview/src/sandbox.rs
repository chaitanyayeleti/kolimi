//! The sandbox applied inside the worker process.

use std::collections::BTreeMap;
use std::path::Path;

use landlock::{
    ABI, Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
    RulesetStatus,
};
use rustix::process::{Resource, Rlimit};

/// What actually got applied (for logging and tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hardening {
    /// rlimits were set.
    pub rlimits: bool,
    /// `no_new_privs` was set.
    pub no_new_privs: bool,
    /// Landlock ABI in effect (0 = not enforced).
    pub landlock_abi: i32,
    /// The seccomp filter was installed.
    pub seccomp: bool,
}

/// Syscalls the worker needs. Everything else returns `EPERM`; in
/// particular there is no `socket`, `connect`, `execve`, or `clone`.
#[cfg(target_arch = "x86_64")]
const ALLOWED_SYSCALLS: &[libc::c_long] = &[
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_readv,
    libc::SYS_writev,
    libc::SYS_close,
    libc::SYS_fstat,
    libc::SYS_lseek,
    libc::SYS_mmap,
    libc::SYS_mprotect,
    libc::SYS_munmap,
    libc::SYS_mremap,
    libc::SYS_brk,
    libc::SYS_madvise,
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_sigaltstack,
    libc::SYS_exit,
    libc::SYS_exit_group,
    libc::SYS_futex,
    libc::SYS_clock_gettime,
    libc::SYS_getrandom,
    libc::SYS_gettid,
    libc::SYS_getpid,
    libc::SYS_sched_yield,
    libc::SYS_rseq,
    libc::SYS_prlimit64,
    libc::SYS_arch_prctl,
    libc::SYS_set_tid_address,
    libc::SYS_set_robust_list,
    libc::SYS_prctl,
    libc::SYS_uname,
    libc::SYS_getcwd,
    libc::SYS_openat,
    libc::SYS_newfstatat,
    libc::SYS_statx,
    libc::SYS_fcntl,
    libc::SYS_pread64,
    libc::SYS_pwrite64,
    libc::SYS_poll,
    libc::SYS_ppoll,
    libc::SYS_membarrier,
];

#[cfg(not(target_arch = "x86_64"))]
const ALLOWED_SYSCALLS: &[libc::c_long] = &[];

/// Applies the full sandbox, allowing reads of `input` only.
pub fn harden(input: &Path) -> Hardening {
    let rlimits = set_rlimits();
    let no_new_privs = rustix::thread::set_no_new_privs(true).is_ok();
    let landlock_abi = apply_landlock(input);
    // Seccomp last: it locks down prctl etc. for the rest of the process.
    let seccomp = apply_seccomp();
    Hardening {
        rlimits,
        no_new_privs,
        landlock_abi,
        seccomp,
    }
}

fn set_rlimits() -> bool {
    let mut ok = true;
    let limits = [
        // 1 GiB of address space.
        (
            Resource::As,
            Rlimit {
                current: Some(1 << 30),
                maximum: Some(1 << 30),
            },
        ),
        // 10 CPU seconds.
        (
            Resource::Cpu,
            Rlimit {
                current: Some(10),
                maximum: Some(10),
            },
        ),
        // 64 MiB of output files (stdout is a pipe, unaffected).
        (
            Resource::Fsize,
            Rlimit {
                current: Some(64 << 20),
                maximum: Some(64 << 20),
            },
        ),
        // 32 open files.
        (
            Resource::Nofile,
            Rlimit {
                current: Some(32),
                maximum: Some(32),
            },
        ),
    ];
    for (resource, limit) in limits {
        if rustix::process::setrlimit(resource, limit).is_err() {
            ok = false;
        }
    }
    ok
}

fn apply_landlock(input: &Path) -> i32 {
    let abi = ABI::V1;
    let ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .and_then(|ruleset| ruleset.create());
    let Ok(ruleset) = ruleset else {
        return 0;
    };
    let Ok(path) = PathFd::new(input) else {
        return 0;
    };
    let rule = PathBeneath::new(path, AccessFs::ReadFile);
    let Ok(ruleset) = ruleset.add_rule(rule) else {
        return 0;
    };
    match ruleset.restrict_self() {
        Ok(status) => match status.ruleset {
            RulesetStatus::FullyEnforced | RulesetStatus::PartiallyEnforced => abi as i32,
            RulesetStatus::NotEnforced => 0,
        },
        Err(_) => 0,
    }
}

fn apply_seccomp() -> bool {
    let mut rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
    for syscall in ALLOWED_SYSCALLS {
        rules.insert(*syscall, Vec::new());
    }
    let Ok(arch) = seccompiler::TargetArch::try_from(std::env::consts::ARCH) else {
        return false;
    };
    let filter = seccompiler::SeccompFilter::new(
        rules,
        // Unlisted syscalls: fail with EPERM rather than killing the
        // worker, so a decoder encountering an unexpected call degrades
        // gracefully.
        seccompiler::SeccompAction::Errno(libc::EPERM as u32),
        seccompiler::SeccompAction::Allow,
        arch,
    );
    let Ok(filter) = filter else {
        return false;
    };
    let Ok(program) = seccompiler::BpfProgram::try_from(filter) else {
        return false;
    };
    seccompiler::apply_filter(&program).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardening_reports_layers() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input.bin");
        std::fs::write(&input, b"data").unwrap();
        let hardening = harden(&input);
        assert!(hardening.rlimits, "rlimits must apply");
        assert!(hardening.seccomp, "seccomp must apply");
        // Landlock needs kernel support; on CI and modern Linux it is there.
        if std::env::var("KOLIMI_REQUIRE_LANDLOCK").is_ok() {
            assert!(
                hardening.landlock_abi > 0,
                "landlock expected: {hardening:?}"
            );
        }
    }
}
