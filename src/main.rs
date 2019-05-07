
extern crate winapi;

use std::ffi::{OsStr, OsString};
use std::os::windows::prelude::*;

use std::mem::{size_of, size_of_val, transmute};
use winapi::shared::minwindef::*;
use winapi::um::tlhelp32::*;
use winapi::um::processthreadsapi::*;
use winapi::um::handleapi::{INVALID_HANDLE_VALUE, CloseHandle};
use winapi::um::winnt::*;
use winapi::um::winbase::*;
use winapi::um::errhandlingapi::*;
use winapi::um::psapi::*;
use winapi::um::memoryapi::*;
use winapi::um::dbghelp::*;

use std::iter::Iterator;
use std::ptr::*;

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
        pe32.dwSize = size_of_val(&pe32) as u32;
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
    pid : u32,
}

impl Iterator for ThreadEntry {
    type Item = ThreadInfo;

    fn next(&mut self) -> Option<Self::Item> {
        while self.base.next_item() {
            let data = &self.base.data;
            if data.th32OwnerProcessID != self.pid {
                continue;
            }
            return Some(ThreadInfo {
                pid: data.th32OwnerProcessID as u32,
                tid: data.th32ThreadID as u32,
            });
        }
        return None;
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
        ), pid: pid};
    }
}

// --------------------------------------------

struct ModuleInfo {
    name: String,
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
                name: OsString::from_wide(&data.szModule).into_string().unwrap(),
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

fn get_current_pid() -> DWORD {
    unsafe { GetCurrentProcessId() }
}

fn last_error(code: DWORD) -> String {
    unsafe {
        let mut buf = [0 as u16; MAX_PATH as usize];
        if FormatMessageW(
            FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM,
            null_mut(), code, 0, buf.as_mut_ptr(),
            buf.len() as u32, null_mut()) != 0 {
            OsString::from_wide(&buf).into_string().unwrap()
        } else { "".to_string() }
    }
}

fn get_last_error() -> DWORD { unsafe { GetLastError() } }

fn last_error_str() -> String { last_error(get_last_error()) }

struct Process {
    pid: u32,
    handle: HANDLE,
}

impl Process {
    pub fn from_pid(pid: u32) -> Result<Process, String> {
        unsafe {
            let handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
            if handle == INVALID_HANDLE_VALUE { return Err(last_error_str()); }
            return Process::from_handle(handle);
        }
    }

    pub fn from_name(name: &str) -> Result<Process, String> {
        for p in enum_process()
            .filter(|p| p.name.to_str().unwrap().find(name).is_some()) {
            return Process::from_pid(p.pid);
        }
        return Err("This Process is not exists".to_string());
    }

    pub fn from_handle(handle: HANDLE) -> Result<Process, String> {
        unsafe {
            let pid = GetProcessId(handle);
            if pid == 0 { return Err(last_error_str()); }
            SymInitializeW(handle, null_mut(), 1);
            return Ok(Process {
                pid: pid, handle: handle,
            });
        }
    }

    pub fn get_module_name(&self, module: u64) -> Result<String, String> {
        unsafe {
            let mut name = [0 as u16; MAX_PATH];
            if GetModuleBaseNameW(self.handle, module as HMODULE, name.as_mut_ptr(), MAX_PATH as u32) > 0 {
                OsString::from_wide(&name).into_string().map_err(|x| "".to_string())
            } else { Err(last_error_str()) }
        }
    }

    pub fn get_module_path(&self, module: u64) -> Result<String, String> {
        unsafe {
            let mut path = [0 as u16; MAX_PATH];
            if GetModuleFileNameExW(self.handle, module as HMODULE, path.as_mut_ptr(), MAX_PATH as u32) > 0 {
                OsString::from_wide(&path).into_string().map_err(|x| "".to_string())
            } else { Err(last_error_str()) }
        }
    }

    pub fn get_modules(&self) -> Option<Vec<ModuleInfo>> {
        let mut module_handles = vec![0 as HMODULE; 64];
        let mut needed = 0 as DWORD;
        unsafe {
            let mut result = EnumProcessModulesEx(
                self.handle, module_handles.as_mut_ptr(),
                (size_of::<HMODULE>() * module_handles.len()) as u32,
                &mut needed, LIST_MODULES_ALL);
            module_handles.resize(needed as usize, 0 as HMODULE);
            if result == 0 {
                result = EnumProcessModulesEx(self.handle, module_handles.as_mut_ptr(),
                (size_of::<HMODULE>() * module_handles.len()) as u32,
                &mut needed, LIST_MODULES_ALL);
            }
            if result == 0 { return None; }

            let mut modules = Vec::<ModuleInfo>::new();
            println!("modules len {}", modules.len());
            for i in 0 .. needed as usize {
                let hModule = module_handles[i as usize];
                if hModule == null_mut() { break; }

                let mut modinfo: MODULEINFO = std::mem::zeroed();
                if GetModuleInformation(self.handle, hModule, &mut modinfo, size_of_val(&modinfo) as u32) > 0 {
                    modules.push(ModuleInfo {
                        base: hModule as u64,
                        size: modinfo.SizeOfImage,
                        name: self.get_module_name(hModule as u64).unwrap(),
                    });
                }
            }
            println!("modules len {}", modules.len());
            return Some(modules);
        }
    }

    pub fn image_file_name(&self) -> Result<String, String> {
        unsafe {
            let mut path = [0 as u16; MAX_PATH];
            // if GetProcessImageFileNameW(self.handle, path.as_mut_ptr(), MAX_PATH as u32) > 0 {
            //     OsString::from_wide(&path).into_string().map_err(|x| "".to_string())
            // } else { Err(last_error_str()) }
            let mut size = path.len() as u32;
            if QueryFullProcessImageNameW(self.handle, 0, path.as_mut_ptr(), &mut size) > 0 {
                OsString::from_wide(&path).into_string().map_err(|x| "".to_string())
            } else { Err(last_error_str()) }
        }
    }

    // fn read_memory(&self, address: u64, size: usize) -> Option<Vec<u8>> {
    // }

    pub fn write_memory(&self, address: u64, data: &[u8]) -> usize {
        unsafe {
            let mut written = 0 as usize;
            if WriteProcessMemory(
                self.handle,
                address as LPVOID,
                data.as_ptr() as LPVOID,
                data.len(),
                &mut written) > 0 { written as usize } else { 0 }
        }
    }

    pub fn get_address_by_symbol(&self, symbol: &str) -> u64 {
        unsafe {
            let mut si: SYMBOL_INFOW = std::mem::zeroed();
            si.SizeOfStruct = size_of_val(&si) as u32;

            let name: Vec<u16> = OsStr::new(symbol).encode_wide().collect();
            if SymFromNameW(self.handle, name.as_ptr(), &mut si) > 0 { si.Address as u64 } else { 0 }
        }
    }

    // pub fn get_symbol_by_address(&self, address: u64) -> (String, u32) {
    //     unsafe {
    //         let mut si: SYMBOL_INFOW = std::mem::zeroed();
    //         si.SizeOfStruct = size_of_val(&si) as u32;

    //         let name: Vec<u16> = OsStr::new(symbol).encode_wide().collect();
    //         if SymFromNameW(self.handle, name.as_ptr(), &mut si) > 0 { si.Address as u64 } else { 0 }
    //     }
    // }
}

// #[test]
fn test_process() {
    let p = Process::from_pid(get_current_pid()).unwrap();
    println!("Process {} {}", p.pid, p.image_file_name().unwrap());
    println!("Process CreateFileA {:x}", p.get_address_by_symbol("kernel32!CreateFileA"));
    for m in p.get_modules().unwrap() {
        let path = p.get_module_path(m.base).unwrap();
        println!("  {:p} {}", m.base as *const char, path);
    }
}

fn main() {
    test_process();
    // for p in enum_process() { println!("{} {}", p.pid, p.name.to_str().unwrap()); }
    // for p in enum_process().filter(|p| p.name.to_str().unwrap().find("vim").is_some()) {
    //     println!("{} {}", p.pid, p.name.to_str().unwrap());
    //     println!("Threads:");
    //     for t in enum_thread(p.pid) { println!("  {}", t.tid); }
    //     println!("Modules:");
    //     for m in enum_module(p.pid) { println!("  {:p} {}", m.base as *const char, m.name); }
    //     break;
    // }
    // for m in enum_module(get_current_pid()) { println!("  {:p} {}", m.base as *const char, m.name); }

    // let mut line = String::new();
    // std::io::stdin().read_line(&mut line);
}
