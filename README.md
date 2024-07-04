# Disclaimer
**This repository aims to learn and research shellcode using Rust.**

**This repository is for educational purposes only.**

**All code is licensed under [LICENSE](./LICENSE) and is for educational and research purposes only. We are not responsible for any other use of it.**

# Structure
- ## shellcode: Shellcode written in Rust
    
    I tried to write shellcode in pure Rust,and now it can be compiled by nightly-x86_64-pc-windows-msvc or nightly-x86_64-unknown-linux-gnu,with the config.toml in its .cargo directory.
    The linker for nightly-x86_64-pc-windows-gnu
    `linker = "x86_64-w64-mingw32-gcc"` 

    `gcc version 13.2.0 (x86_64-mcf-seh-rev1, Built by MinGW-Builds project)`.

    The manually trimmed shellcode is located in the out directory,for `x86_64-pc-windows` target.

    Now the shellcode will exec `calc.exe` on Windows.

- ## run_shellcode

    This is a simple runner for shellcode,which can run shellcode in memory.

    ### TODO
    -  Inject shellcode 
