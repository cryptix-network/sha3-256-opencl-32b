# opencl_sha3_256_32b

OpenCL 1.2 SHA3-256 path for fixed 32-byte inputs.

File:
- `opencl_sha3_256_32b.cl`

Kernel:
- `sha3_256_32b_batch`

Input/Output layout:
- input buffer = `count * 32` bytes
- output buffer = `count * 32` bytes

Build:
- `-cl-std=CL1.2`
- optional define: `-D OPENCL_KECCAK_ALT=1` (default)

Notes:
- File is self-contained and includes the required Keccak permutation code.
- The implementation is specialized for fixed input size (32 bytes), not arbitrary message length streaming.

// @Cryptis - Cryptix Network
