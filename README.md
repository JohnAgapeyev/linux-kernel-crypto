# linux-kernel-crypto
Rust library for interfacing with the linux kernel's userspace crypto API

# CURRENTLY ABANDONED
The goal of this project was to emulate similar functionality as libkcapi with a Rust native interface from the system calls.
One of the key parts of a Rust interface was planned to be integration with RustCrypto traits.
All major RustCrypto traits involve compile-time values for things like block size, key size, and iv size.
Given that the linux kernel userspace crypto API is runtime only, this is fundamentally incompatbile and not possible to achieve.
This project has thus been put on indefinite hold.
