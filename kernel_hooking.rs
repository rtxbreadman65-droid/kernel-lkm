#![allow(missing_docs)]
#![allow(non_snake_case)]

use kernel::prelude::*;
use core::arch::asm;

static mut BYTE_BUFFER: [u8; 5] = [0; 5];
static mut ORIGN_BYTE_BUFF: [u8; 5] = [0; 5];

type MemFunc = unsafe extern "C" fn(u64, i32) -> i32;

extern "C" {
    /// .
    fn _printk(fmt: *const u8, ...) -> i32;
    fn strncpy_from_user(dest: *mut u8, src: *const u8, n: usize) -> i32;
}

pub unsafe extern "C" fn init_kernel() {
    unsafe {
        pr_info!("Main module.");
        let SYS_MKDIR_ADDR = runtime_address_of_sys_mkdir();
        let MEMORY_RO = memory_ro_addr();
        let MEMORY_RW = memory_rw_addr();
        pr_info!("Memory RO address: {:#x}\n", MEMORY_RO);
        pr_info!("Memory RW address: {:#x}\n", MEMORY_RW);
        pr_info!("Sys_mkdir address: {:#x}\n", SYS_MKDIR_ADDR);
        pr_info!("Disabling Write Protection");
        let memory_ro: MemFunc = core::mem::transmute(MEMORY_RO);
        let memory_rw: MemFunc = core::mem::transmute(MEMORY_RW);
        let page_addr = SYS_MKDIR_ADDR & !(4096 - 1);
        memory_rw(page_addr as u64, 1);
        disable_wp();
        let original_byte = SYS_MKDIR_ADDR as *mut u8;
        for i in 0..5 {
            ORIGN_BYTE_BUFF[i] = *original_byte.add(i);
        }
        let rel_addr = ((kernel_hooking_func as *const() as u64) - ((SYS_MKDIR_ADDR as u64) + 5)).to_le_bytes();
        BYTE_BUFFER[0] = 0xE9;
        let orig_byte = SYS_MKDIR_ADDR as *mut u8;
        for i in 0..4 {
            BYTE_BUFFER[i + 1] = rel_addr[i];
        }
        for i in 0..5 {
            let one_byte = BYTE_BUFFER[i];
            *orig_byte.add(i) = one_byte;
        }
        enable_wp();
        memory_ro(page_addr as u64, 1);
        pr_info!("Enabling Write Protection\n");
        pr_info!("Injected successfully.\n");
    }
}

pub unsafe extern "C" fn clean_up_module() {
    unsafe {
        pr_info!("Cleaning system.\n");
        let SYS_MKDIR_ADDR = runtime_address_of_sys_mkdir();
        let MEMORY_RO = memory_ro_addr();
        let MEMORY_RW = memory_rw_addr();
        let memory_ro: MemFunc = core::mem::transmute(MEMORY_RO);
        let memory_rw: MemFunc = core::mem::transmute(MEMORY_RW);
        let page_addr = SYS_MKDIR_ADDR & !(4096 - 1);
        memory_rw(page_addr as u64, 1);
        disable_wp();
        let original_address = SYS_MKDIR_ADDR as *mut u8;
        for i in 0..5 {
            *original_address.add(i) = ORIGN_BYTE_BUFF[i];
        }
        enable_wp();
        memory_ro(page_addr as u64, 1);
    }
}

pub unsafe extern "C" fn kernel_hooking_func(regs: *mut u8) -> i64 {
    unsafe {
        pr_info!("Kernel Hooked successfully");
        get_folder_string(regs);
        let SYS_MKDIR_ADDR = runtime_address_of_sys_mkdir();
        let MEMORY_RO = memory_ro_addr();
        let MEMORY_RW = memory_rw_addr();
        let memory_ro: MemFunc = core::mem::transmute(MEMORY_RO);
        let memory_rw: MemFunc = core::mem::transmute(MEMORY_RW);
        let page_addr = SYS_MKDIR_ADDR & !(4096 - 1);
        memory_rw(page_addr as u64, 1);
        disable_wp();
        let original_addr = SYS_MKDIR_ADDR as *mut u8;
        for i in 0..5 {
            *original_addr.add(i) = ORIGN_BYTE_BUFF[i];
        }
        memory_ro(page_addr as u64, 1);
        enable_wp();
        let orign_func: extern "C" fn(*mut u8) -> i64 = core::mem::transmute(SYS_MKDIR_ADDR);
        let ret = orign_func(regs);
        memory_rw(page_addr as u64, 1);
        disable_wp();
        for i in 0..5 {
            *original_addr.add(i) = BYTE_BUFFER[i];
        }
        memory_ro(page_addr as u64, 1);
        enable_wp();
        ret
    }
}

pub unsafe extern "C" fn get_folder_string(regs: *mut u8) {
    unsafe {
        let string_ptr = *(regs.add(104) as *const *const u8);
        let mut buffer: [u8; 256] = [0; 256];
        let result = strncpy_from_user(buffer.as_mut_ptr(), string_ptr, 256);
        if result < 0 {
            pr_info!("Failed to copy string from user space: {}\n", result);
        }
        core::str::from_utf8(&buffer)
            .map(|s| pr_info!("Folder name: {}\n", s))
            .unwrap_or_else(|_| pr_info!("Failed to convert folder name to string\n"));
    }
}

pub unsafe extern "C" fn runtime_address_of_stext() -> u64 {
    let runtime_address_of_printk = _printk as *const() as u64;
    let dyamic_address: u64 = (runtime_address_of_printk - 0x213970) as u64;
    dyamic_address
}

pub unsafe extern "C" fn runtime_address_of_sys_mkdir() -> u64 {
    unsafe {
        let runtime_addr_of_base_addr = runtime_address_of_stext();
        let runtime_addr_of_sys_mkdir = runtime_addr_of_base_addr + 0x7F4600;
        runtime_addr_of_sys_mkdir
    }
}

pub unsafe extern "C" fn memory_ro_addr() -> u64 {
    unsafe {
        let runtime_addr_of_base_addr = runtime_address_of_stext();
        let runtime_addr_of_ro_addr = runtime_addr_of_base_addr + 0x353790;
        runtime_addr_of_ro_addr
    }
}

pub unsafe extern "C" fn memory_rw_addr() -> u64 {
    unsafe {
        let runtime_addr_of_base_addr = runtime_address_of_stext();
        let runtime_addr_of_rw_addr = runtime_addr_of_base_addr + 0x353840;
        runtime_addr_of_rw_addr
    }
}

pub unsafe extern "C" fn disable_wp() {
    unsafe {
        let mut cr0: usize = 0 as usize;
        asm!("mov {}, cr0", out(reg) cr0);
        cr0 = cr0 & !(1 << 16);
        asm!("mov cr0, {}", in(reg) cr0);
    }
}

pub unsafe extern "C" fn enable_wp() {
    unsafe {
        let mut cr0: usize = 0 as usize;
        asm!("mov {}, cr0", out(reg) cr0);
        cr0 = cr0 | (1 << 16);
        asm!("mov cr0, {}", in(reg) cr0);
    }
}

module! {
    type: DummyModule,
    name: "direct_fn_module",
    authors: ["Arshman"],
    description: "Direct functions Rust LKM",
    license: "GPL",
}

struct DummyModule;

impl kernel::Module for DummyModule {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        unsafe { init_kernel(); }
        Ok(DummyModule)
    }
}

impl Drop for DummyModule {
    fn drop(&mut self) {
        unsafe {
            clean_up_module();
        }
    }
}
