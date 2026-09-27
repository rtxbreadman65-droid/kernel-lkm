# Rust Linux Kernel Inline Hooking (PoC)

A bare-metal `#no_std` Rust Linux Kernel Module (LKM) that demonstrates inline function hooking on `sys_mkdirat` (x86_64 syscall 258) without relying on `kprobes` or high-level tracing tools.

I built this project to explore direct memory patching, CR0 Write-Protection register toggling, and instruction-level interception inside the kernel.

## ⚠️ Important Warning & Disclaimer
This code is purely a **Proof of Concept (PoC) for learning kernel internals**. 

- **Expect Kernel Panics:** The module uses hardcoded offsets (`_printk`, `_stext`, etc.) specific to my local build. Running this on a different kernel version without recalculating offsets **will crash your system**.
- **VM Only:** Test this strictly inside an isolated Virtual Machine (QEMU / KVM / VirtualBox).
- **No Guarantees:** Do not run this on your daily driver or production system. You take full responsibility for any system crashes or data loss.

## 📸 Proof of Concept (`dmesg` Output)
Here is the module intercepting folder creation in real-time and logging the path to `dmesg`:

![dmesg Logs](https://github.com/user-attachments/assets/631b5129-896a-4680-af39-6a0b0a56b4d7)
