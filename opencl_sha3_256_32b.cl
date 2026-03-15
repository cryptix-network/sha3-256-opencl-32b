// OpenCL 1.2 - SHA3-256 for fixed 32-byte inputs
// Buffer layout for kernel sha3_256_32b_batch:
// - input:  count * 32 bytes
// - output: count * 32 bytes
// @Cryptis - Cryptix Network

#ifndef OPENCL_KECCAK_ALT
#define OPENCL_KECCAK_ALT 1
#endif

__constant ulong KECCAK_RNDC[24] = {
    0x0000000000000001UL, 0x0000000000008082UL,
    0x800000000000808AUL, 0x8000000080008000UL,
    0x000000000000808BUL, 0x0000000080000001UL,
    0x8000000080008081UL, 0x8000000000008009UL,
    0x000000000000008AUL, 0x0000000000000088UL,
    0x0000000080008009UL, 0x000000008000000AUL,
    0x000000008000808BUL, 0x800000000000008BUL,
    0x8000000000008089UL, 0x8000000000008003UL,
    0x8000000000008002UL, 0x8000000000000080UL,
    0x000000000000800AUL, 0x800000008000000AUL,
    0x8000000080008081UL, 0x8000000000008080UL,
    0x0000000080000001UL, 0x8000000080008008UL
};

__constant uint KECCAK_PI_LANES[24] = {
    10U, 7U, 11U, 17U, 18U, 3U, 5U, 16U,
    8U, 21U, 24U, 4U, 15U, 23U, 19U, 13U,
    12U, 2U, 20U, 14U, 22U, 9U, 6U, 1U
};

__constant uint KECCAK_RHO_PI_ROT[24] = {
    1U, 3U, 6U, 10U, 15U, 21U, 28U, 36U,
    45U, 55U, 2U, 14U, 27U, 41U, 56U, 8U,
    25U, 43U, 62U, 18U, 39U, 61U, 20U, 44U
};

inline ulong rotl64(ulong value, uint shift) {
    shift &= 63U;
    return (value << shift) | (value >> ((64U - shift) & 63U));
}

inline ulong load64_le_private(const uchar in[32], uint offset) {
    uint base = offset;
    return ((ulong)in[base + 0U]) |
        ((ulong)in[base + 1U] << 8) |
        ((ulong)in[base + 2U] << 16) |
        ((ulong)in[base + 3U] << 24) |
        ((ulong)in[base + 4U] << 32) |
        ((ulong)in[base + 5U] << 40) |
        ((ulong)in[base + 6U] << 48) |
        ((ulong)in[base + 7U] << 56);
}

inline void store64_le_private(ulong value, uchar out[32], uint offset) {
    uint base = offset;
    out[base + 0U] = (uchar)(value & 0xFFUL);
    out[base + 1U] = (uchar)((value >> 8) & 0xFFUL);
    out[base + 2U] = (uchar)((value >> 16) & 0xFFUL);
    out[base + 3U] = (uchar)((value >> 24) & 0xFFUL);
    out[base + 4U] = (uchar)((value >> 32) & 0xFFUL);
    out[base + 5U] = (uchar)((value >> 40) & 0xFFUL);
    out[base + 6U] = (uchar)((value >> 48) & 0xFFUL);
    out[base + 7U] = (uchar)((value >> 56) & 0xFFUL);
}

inline void keccak_f1600(ulong st[25]) {
#if (OPENCL_KECCAK_ALT == 0)
    ulong b[25];

    for (uint round = 0; round < 24U; round++) {
        ulong c0 = st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20];
        ulong c1 = st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21];
        ulong c2 = st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22];
        ulong c3 = st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23];
        ulong c4 = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24];

        ulong d0 = c4 ^ rotl64(c1, 1U);
        ulong d1 = c0 ^ rotl64(c2, 1U);
        ulong d2 = c1 ^ rotl64(c3, 1U);
        ulong d3 = c2 ^ rotl64(c4, 1U);
        ulong d4 = c3 ^ rotl64(c0, 1U);

        st[0] ^= d0;
        st[5] ^= d0;
        st[10] ^= d0;
        st[15] ^= d0;
        st[20] ^= d0;

        st[1] ^= d1;
        st[6] ^= d1;
        st[11] ^= d1;
        st[16] ^= d1;
        st[21] ^= d1;

        st[2] ^= d2;
        st[7] ^= d2;
        st[12] ^= d2;
        st[17] ^= d2;
        st[22] ^= d2;

        st[3] ^= d3;
        st[8] ^= d3;
        st[13] ^= d3;
        st[18] ^= d3;
        st[23] ^= d3;

        st[4] ^= d4;
        st[9] ^= d4;
        st[14] ^= d4;
        st[19] ^= d4;
        st[24] ^= d4;

        b[0] = st[0];
        b[10] = rotl64(st[1], 1U);
        b[20] = rotl64(st[2], 62U);
        b[5] = rotl64(st[3], 28U);
        b[15] = rotl64(st[4], 27U);
        b[16] = rotl64(st[5], 36U);
        b[1] = rotl64(st[6], 44U);
        b[11] = rotl64(st[7], 6U);
        b[21] = rotl64(st[8], 55U);
        b[6] = rotl64(st[9], 20U);
        b[7] = rotl64(st[10], 3U);
        b[17] = rotl64(st[11], 10U);
        b[2] = rotl64(st[12], 43U);
        b[12] = rotl64(st[13], 25U);
        b[22] = rotl64(st[14], 39U);
        b[23] = rotl64(st[15], 41U);
        b[8] = rotl64(st[16], 45U);
        b[18] = rotl64(st[17], 15U);
        b[3] = rotl64(st[18], 21U);
        b[13] = rotl64(st[19], 8U);
        b[14] = rotl64(st[20], 18U);
        b[24] = rotl64(st[21], 2U);
        b[9] = rotl64(st[22], 61U);
        b[19] = rotl64(st[23], 56U);
        b[4] = rotl64(st[24], 14U);

        st[0] = b[0] ^ ((~b[1]) & b[2]);
        st[1] = b[1] ^ ((~b[2]) & b[3]);
        st[2] = b[2] ^ ((~b[3]) & b[4]);
        st[3] = b[3] ^ ((~b[4]) & b[0]);
        st[4] = b[4] ^ ((~b[0]) & b[1]);

        st[5] = b[5] ^ ((~b[6]) & b[7]);
        st[6] = b[6] ^ ((~b[7]) & b[8]);
        st[7] = b[7] ^ ((~b[8]) & b[9]);
        st[8] = b[8] ^ ((~b[9]) & b[5]);
        st[9] = b[9] ^ ((~b[5]) & b[6]);

        st[10] = b[10] ^ ((~b[11]) & b[12]);
        st[11] = b[11] ^ ((~b[12]) & b[13]);
        st[12] = b[12] ^ ((~b[13]) & b[14]);
        st[13] = b[13] ^ ((~b[14]) & b[10]);
        st[14] = b[14] ^ ((~b[10]) & b[11]);

        st[15] = b[15] ^ ((~b[16]) & b[17]);
        st[16] = b[16] ^ ((~b[17]) & b[18]);
        st[17] = b[17] ^ ((~b[18]) & b[19]);
        st[18] = b[18] ^ ((~b[19]) & b[15]);
        st[19] = b[19] ^ ((~b[15]) & b[16]);

        st[20] = b[20] ^ ((~b[21]) & b[22]);
        st[21] = b[21] ^ ((~b[22]) & b[23]);
        st[22] = b[22] ^ ((~b[23]) & b[24]);
        st[23] = b[23] ^ ((~b[24]) & b[20]);
        st[24] = b[24] ^ ((~b[20]) & b[21]);

        st[0] ^= KECCAK_RNDC[round];
    }
#else
    for (uint round = 0; round < 24U; round++) {
        ulong c0 = st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20];
        ulong c1 = st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21];
        ulong c2 = st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22];
        ulong c3 = st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23];
        ulong c4 = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24];

        ulong d0 = c4 ^ rotl64(c1, 1U);
        ulong d1 = c0 ^ rotl64(c2, 1U);
        ulong d2 = c1 ^ rotl64(c3, 1U);
        ulong d3 = c2 ^ rotl64(c4, 1U);
        ulong d4 = c3 ^ rotl64(c0, 1U);

        st[0] ^= d0;
        st[5] ^= d0;
        st[10] ^= d0;
        st[15] ^= d0;
        st[20] ^= d0;

        st[1] ^= d1;
        st[6] ^= d1;
        st[11] ^= d1;
        st[16] ^= d1;
        st[21] ^= d1;

        st[2] ^= d2;
        st[7] ^= d2;
        st[12] ^= d2;
        st[17] ^= d2;
        st[22] ^= d2;

        st[3] ^= d3;
        st[8] ^= d3;
        st[13] ^= d3;
        st[18] ^= d3;
        st[23] ^= d3;

        st[4] ^= d4;
        st[9] ^= d4;
        st[14] ^= d4;
        st[19] ^= d4;
        st[24] ^= d4;

        ulong t = st[1];
        for (uint i = 0; i < 24U; i++) {
            uint lane = KECCAK_PI_LANES[i];
            ulong next = st[lane];
            st[lane] = rotl64(t, KECCAK_RHO_PI_ROT[i]);
            t = next;
        }

        for (uint row = 0; row < 25U; row += 5U) {
            ulong r0 = st[row + 0U];
            ulong r1 = st[row + 1U];
            ulong r2 = st[row + 2U];
            ulong r3 = st[row + 3U];
            ulong r4 = st[row + 4U];

            st[row + 0U] = r0 ^ ((~r1) & r2);
            st[row + 1U] = r1 ^ ((~r2) & r3);
            st[row + 2U] = r2 ^ ((~r3) & r4);
            st[row + 3U] = r3 ^ ((~r4) & r0);
            st[row + 4U] = r4 ^ ((~r0) & r1);
        }

        st[0] ^= KECCAK_RNDC[round];
    }
#endif
}

inline void sha3_256_32bytes(const uchar input[32], uchar output[32]) {
    ulong st[25];
    for (uint i = 0; i < 25U; i++) {
        st[i] = 0UL;
    }

    st[0] ^= load64_le_private(input, 0U);
    st[1] ^= load64_le_private(input, 8U);
    st[2] ^= load64_le_private(input, 16U);
    st[3] ^= load64_le_private(input, 24U);

    st[4] ^= 0x06UL;
    st[16] ^= (0x80UL << 56);

    keccak_f1600(st);

    store64_le_private(st[0], output, 0U);
    store64_le_private(st[1], output, 8U);
    store64_le_private(st[2], output, 16U);
    store64_le_private(st[3], output, 24U);
}

__kernel void sha3_256_32b_batch(
    __global const uchar* in32,
    __global uchar* out32,
    uint count
) {
    uint gid = (uint)get_global_id(0);
    if (gid >= count) {
        return;
    }

    uint base = gid * 32U;
    uchar input[32];
    uchar output[32];

    #pragma unroll 32
    for (uint i = 0; i < 32U; i++) {
        input[i] = in32[base + i];
    }

    sha3_256_32bytes(input, output);

    #pragma unroll 32
    for (uint i = 0; i < 32U; i++) {
        out32[base + i] = output[i];
    }
}
