set shell := ["pwsh", "-c"] 

default:
    @just --list --unsorted --justfile {{justfile()}}
build-native-exe:
    rustc shellcode.rs -C opt-level=z -C panic=abort -C lto=fat -C codegen-units=1 -C strip=symbols -Z pre-link-arg=/NODEFAULTLIB -C link-arg=/ENTRY:main -C link-arg=/MERGE:.edata=.rdata -C link-arg=/MERGE:.rustc=.data -C link-arg=/MERGE:.rdata=.text -C link-arg=/MERGE:.pdata=.text -C link-arg=/DEBUG:NONE -C link-arg=/EMITPOGOPHASEINFO -C target-cpu=native -C target-feature=+sse4.2 -C relocation-model=pic -C default-linker-libraries=false --crate-type bin --edition=2021
build-generic-exe:
    rustc shellcode.rs -C opt-level=z -C panic=abort -C lto=fat -C codegen-units=1 -C strip=symbols -Z pre-link-arg=/NODEFAULTLIB -C link-arg=/ENTRY:main -C link-arg=/MERGE:.edata=.rdata -C link-arg=/MERGE:.rustc=.data -C link-arg=/MERGE:.rdata=.text -C link-arg=/MERGE:.pdata=.text -C link-arg=/DEBUG:NONE -C link-arg=/EMITPOGOPHASEINFO -C target-cpu=generic -C relocation-model=pic -C default-linker-libraries=false --crate-type bin --edition=2021
run-native-exe: build-native-exe
    ./shellcode.exe
run-generic-exe: build-generic-exe
    ./shellcode.exe
clean:
    rm -Force shellcode.exe