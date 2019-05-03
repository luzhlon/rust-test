
extern crate winapi;

use std::ffi::{OsStr, OsString};
use std::os::windows::prelude::*;

use std::mem::size_of;
use winapi::shared::minwindef::{MAX_PATH, BOOL};
use winapi::um::tlhelp32::*;
use winapi::um::handleapi::{INVALID_HANDLE_VALUE, CloseHandle};
use winapi::um::winnt::HANDLE;

use std::iter::Iterator;

struct TlHelpIter<T: Clone> {
    count: u32,
    handle: HANDLE,
    data: T,
    f_first: fn(HANDLE, &mut T)->BOOL,
    f_next: fn(HANDLE, &mut T)->BOOL,
}

impl<T: Clone> TlHelpIter<T> {
    fn new(handle: HANDLE, data: T,
           f_first: fn(HANDLE, &mut T)->BOOL,
           f_next: fn(HANDLE, &mut T)->BOOL) ->
    TlHelpIter<T> {
        assert!(handle != INVALID_HANDLE_VALUE);
        TlHelpIter {
            handle: handle, count: 0, data: data,
            f_first: f_first, f_next: f_next,
        }
    }

    fn next_item(&mut self) -> bool {
        let success = if self.count > 0 {
            (self.f_next)(self.handle, &mut self.data) > 0
        } else {
            (self.f_first)(self.handle, &mut self.data) > 0
        };
        self.count += 1;
        return success;
    }
}

impl<T: Clone> Iterator for TlHelpIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        if self.next_item() {Some(self.data.clone())} else {None}
    }
}

impl<T: Clone> Drop for TlHelpIter<T> {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

// --------------------------------------------

struct ProcessInfo {
    pid: u32,
    name: OsString,
}

struct ProcessEntry {
    base: TlHelpIter<PROCESSENTRY32W>,
}

impl Iterator for ProcessEntry {
    type Item = ProcessInfo;

    fn next(&mut self) -> Option<Self::Item> {
        if self.base.next_item() {
            let data = &self.base.data;
            Some(ProcessInfo {
                pid: data.th32ProcessID,
                name: OsString::from_wide(&data.szExeFile),
            })
        } else {
            None
        }
    }
}

fn enum_process() -> ProcessEntry {
    unsafe {
        let mut pe32: PROCESSENTRY32W = std::mem::zeroed();
        pe32.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        return ProcessEntry { base: TlHelpIter::new(
            CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0), pe32,
                |h, d| Process32FirstW(h, d), |h, d| Process32NextW(h, d)
        )};
    }
}

// --------------------------------------------

struct ThreadInfo {
    pid: u32,
    tid: u32,
}

struct ThreadEntry {
    base: TlHelpIter<THREADENTRY32>,
}

impl Iterator for ThreadEntry {
    type Item = ThreadInfo;

    fn next(&mut self) -> Option<Self::Item> {
        if self.base.next_item() {
            let data = &self.base.data;
            Some(ThreadInfo {
                pid: data.th32OwnerProcessID as u32,
                tid: data.th32ThreadID as u32,
            })
        } else {
            None
        }
    }
}

fn enum_thread(pid: u32) -> ThreadEntry {
    unsafe {
        let mut te32: THREADENTRY32 = std::mem::zeroed();
        te32.dwSize = size_of::<THREADENTRY32>() as u32;
        te32.th32OwnerProcessID = pid;
        return ThreadEntry { base: TlHelpIter::new(
            CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid), te32,
                |h, d| Thread32First(h, d), |h, d| Thread32Next(h, d)
        )};
    }
}

// --------------------------------------------

struct ModuleInfo {
    name: OsString,
    base: u64,
    size: u32,
}

struct ModuleEntry {
    base: TlHelpIter<MODULEENTRY32W>,
}

impl Iterator for ModuleEntry {
    type Item = ModuleInfo;

    fn next(&mut self) -> Option<Self::Item> {
        if self.base.next_item() {
            let data = &self.base.data;
            Some(ModuleInfo {
                name: OsString::from_wide(&data.szModule),
                base: data.modBaseAddr as u64,
                size: data.modBaseSize as u32,
            })
        } else {
            None
        }
    }
}

fn enum_module(pid: u32) -> ModuleEntry {
    unsafe {
        let mut te32: MODULEENTRY32W = std::mem::zeroed();
        te32.dwSize = size_of::<MODULEENTRY32W>() as u32;
        return ModuleEntry { base: TlHelpIter::new(
            CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid), te32,
                |h, d| Module32FirstW(h, d), |h, d| Module32NextW(h, d)
        )};
    }
}

fn main() {
    // for p in enum_process() { println!("{} {}", p.pid, p.name.to_str().unwrap()); }
    for p in enum_process().filter(|p| !p.name.to_str().unwrap().find("vim").is_none()) {
        println!("{} {}", p.pid, p.name.to_str().unwrap());
    }
    for t in enum_thread(16836) { println!("{}", t.tid); }
    for m in enum_module(16836) { println!("{:08X} {}", m.base, m.name.to_str().unwrap()); }
}
