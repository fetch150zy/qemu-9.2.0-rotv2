/*
 * QEMU Root of Trust v2 PCR device
 *
 * Copyright (c) 2024-2025 ZGC Lab & CAS, ICT.
 *
 * Author(s):
 *  Zhe Wei <weizhe24s@ict.ac.cn>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "qemu/bswap.h"
#include "qemu/fifo8.h"
#include "hw/qdev-properties.h"
#include "hw/qdev-core.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "hw/registerfields.h"

#include "hw/rotv2/rot_pcr.h"

#include "tomcrypt.h"

/* clang-format off */
REG32(CTRL, 0x0u)
    FIELD(CTRL, ALG_BANK_SHA1, 0u, 1u)
    FIELD(CTRL, ALG_BANK_SHA256, 1u, 1u)
    FIELD(CTRL, ALG_BANK_SHA384, 2u, 1u)
    FIELD(CTRL, ALG_BANK_SHA512, 3u, 1u)
    FIELD(CTRL, ALG_BANK_SHA3_256, 4u, 1u)
    FIELD(CTRL, ALG_BANK_SHA3_384, 5u, 1u)
    FIELD(CTRL, ALG_BANK_SHA3_512, 6u, 1u)
    FIELD(CTRL, ALG_BANK_SM3_256, 7u, 1u)
    FIELD(CTRL, SELECTION, 8u, 5u)
    FIELD(CTRL, LOCALITY, 13u, 5u)
REG32(COMMAND, 0x4u)
    FIELD(COMMAND, CODE, 0u, 3u)
REG32(STATUS, 0x8u)
    FIELD(STATUS, OP_DONE, 0u, 1u)
    FIELD(STATUS, ALG_BANK_SHA1, 1u, 1u)
    FIELD(STATUS, ALG_BANK_SHA256, 2u, 1u)
    FIELD(STATUS, ALG_BANK_SHA384, 3u, 1u)
    FIELD(STATUS, ALG_BANK_SHA512, 4u, 1u)
    FIELD(STATUS, ALG_BANK_SHA3_256, 5u, 1u)
    FIELD(STATUS, ALG_BANK_SHA3_384, 6u, 1u)
    FIELD(STATUS, ALG_BANK_SHA3_512, 7u, 1u)
    FIELD(STATUS, ALG_BANK_SM3_256, 8u, 1u)
/* clang-format on */

#define CTRL_MASK \
    (R_CTRL_ALG_BANK_SHA1_MASK | \
     R_CTRL_ALG_BANK_SHA256_MASK | \
     R_CTRL_ALG_BANK_SHA384_MASK | \
     R_CTRL_ALG_BANK_SHA512_MASK | \
     R_CTRL_ALG_BANK_SHA3_256_MASK | \
     R_CTRL_ALG_BANK_SHA3_384_MASK | \
     R_CTRL_ALG_BANK_SHA3_512_MASK | \
     R_CTRL_ALG_BANK_SM3_256_MASK | \
     R_CTRL_SELECTION_MASK | \
     R_CTRL_LOCALITY_MASK)
#define COMMAND_MASK \
    (R_COMMAND_CODE_MASK)
#define STATUS_MASK \
    (R_STATUS_OP_DONE_MASK | \
     R_STATUS_ALG_BANK_SHA1_MASK | \
     R_STATUS_ALG_BANK_SHA256_MASK | \
     R_STATUS_ALG_BANK_SHA384_MASK | \
     R_STATUS_ALG_BANK_SHA512_MASK | \
     R_STATUS_ALG_BANK_SHA3_256_MASK | \
     R_STATUS_ALG_BANK_SHA3_384_MASK | \
     R_STATUS_ALG_BANK_SHA3_512_MASK | \
     R_STATUS_ALG_BANK_SM3_256_MASK)

#define R32_OFF(_r_) ((_r_) / sizeof(uint32_t))

#define R_LAST_REG (R_STATUS)
#define REGS_COUNT (R_LAST_REG + 1u)
#define REGS_SIZE  (REGS_COUNT * sizeof(uint32_t))
#define REG_NAME(_reg_) \
    ((((_reg_) <= REGS_COUNT) && REG_NAMES[_reg_]) ? REG_NAMES[_reg_] : "?")

#define REG_NAME_ENTRY(_reg_) [R_##_reg_] = stringify(_reg_)
static const char *REG_NAMES[REGS_COUNT] = {
    REG_NAME_ENTRY(CTRL),
    REG_NAME_ENTRY(COMMAND),
    REG_NAME_ENTRY(STATUS),
};
#undef REG_NAME_ENTRY

enum {
    ROT_PCR_CMD_ALLOCATE = 0x0u,
    ROT_PCR_CMD_RESET    = 0x1u,
    ROT_PCR_CMD_READ     = 0x2u,
    ROT_PCR_CMD_EXTEND   = 0x3u,
    ROT_PCR_CMD_EVENT    = 0x4u,
};

#define ROT_PCR_FIFO_LENGTH ROT_PCR_FIFO_SIZE
#define ROT_PCR_NUMS  24u
#define ROT_PCR_BANKS 8u

#define ROT_PCR_BANK_SHA1_LENGTH     20u
#define ROT_PCR_BANK_SHA256_LENGTH   32u
#define ROT_PCR_BANK_SHA384_LENGTH   48u
#define ROT_PCR_BANK_SHA512_LENGTH   64u
#define ROT_PCR_BANK_SHA3_256_LENGTH 32u
#define ROT_PCR_BANK_SHA3_384_LENGTH 48u
#define ROT_PCR_BANK_SHA3_512_LENGTH 64u
#define ROT_PCR_BANK_SM3_256_LENGTH  32u

// 0bxxxxx -> loc: 4 3 2 1 0
static uint8_t reset_locality_table[ROT_PCR_NUMS] = {
    /* PCR 0 - 15, static RTM, cannot reset */
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x0fu, /* PCR 16, Debug, reset loc 0, 1, 2, 3 */
    0x10u, /* PCR 17, Locality 4, reset loc 4 */
    0x10u, /* PCR 18, Locality 3, reset loc 4 */
    0x10u, /* PCR 19, Locality 2, reset loc 4 */
    0x14u, /* PCR 20, Locality 1, reset loc 2, 4 */
    0x14u, /* PCR 21, Dynamic OS, reset loc 2, 4 */
    0x14u, /* PCR 22, Dynamic OS, reset loc 2, 4 */
    0x0fu, /* PCR 23, App specific, reset loc 0, 1, 2, 3 */
};

static uint8_t extend_locality_table[ROT_PCR_NUMS] = {
    /* PCR 0 - 15, static RTM, extend all */
    0x1fu, 0x1fu, 0x1fu, 0x1fu, 0x1fu, 0x1fu, 0x1fu, 0x1fu,
    0x1fu, 0x1fu, 0x1fu, 0x1fu, 0x1fu, 0x1fu, 0x1fu, 0x1fu,
    0x1fu, /* PCR 16, Debug, extend loc 0, 1, 2, 3, 4 */
    0x1cu, /* PCR 17, Locality 4, extend loc 2, 3, 4 */
    0x1cu, /* PCR 18, Locality 3, extend loc 2, 3, 4 */
    0x0cu, /* PCR 19, Locality 2, extend loc 2, 3 */
    0x0eu, /* PCR 20, Locality 1, extend loc 1, 2, 3 */
    0x04u, /* PCR 21, Dynamic OS, extend loc 2 */
    0x04u, /* PCR 22, Dynamic OS, extend loc 2 */
    0x1fu, /* PCR 23, App specific, extend all */
};

static uint8_t reset_to_zero_table[5] = {
    16, 20, 21, 22, 23,
};

struct RoTPCRRegisters {
    uint32_t ctrl;
    uint32_t command;
    uint32_t status;
};
typedef struct RoTPCRRegisters RoTPCRRegisters;

struct RoTPCRBankSHA1 {
    uint8_t pcr[ROT_PCR_NUMS][ROT_PCR_BANK_SHA1_LENGTH];
};
typedef struct RoTPCRBankSHA1 RoTPCRBankSHA1;

struct RoTPCRBankSHA256 {
    uint8_t pcr[ROT_PCR_NUMS][ROT_PCR_BANK_SHA256_LENGTH];
};
typedef struct RoTPCRBankSHA256 RoTPCRBankSHA256;

struct RoTPCRBankSHA384 {
    uint8_t pcr[ROT_PCR_NUMS][ROT_PCR_BANK_SHA384_LENGTH];
};
typedef struct RoTPCRBankSHA384 RoTPCRBankSHA384;

struct RoTPCRBankSHA512 {
    uint8_t pcr[ROT_PCR_NUMS][ROT_PCR_BANK_SHA512_LENGTH];
};
typedef struct RoTPCRBankSHA512 RoTPCRBankSHA512;

struct RoTPCRBankSHA3_256 {
    uint8_t pcr[ROT_PCR_NUMS][ROT_PCR_BANK_SHA3_256_LENGTH];
};
typedef struct RoTPCRBankSHA3_256 RoTPCRBankSHA3_256;

struct RoTPCRBankSHA3_384 {
    uint8_t pcr[ROT_PCR_NUMS][ROT_PCR_BANK_SHA3_384_LENGTH];
};
typedef struct RoTPCRBankSHA3_384 RoTPCRBankSHA3_384;

struct RoTPCRBankSHA3_512 {
    uint8_t pcr[ROT_PCR_NUMS][ROT_PCR_BANK_SHA3_512_LENGTH];
};
typedef struct RoTPCRBankSHA3_512 RoTPCRBankSHA3_512;

struct RoTPCRBankSM3_256 {
    uint8_t pcr[ROT_PCR_NUMS][ROT_PCR_BANK_SM3_256_LENGTH];
};
typedef struct RoTPCRBankSM3_256 RoTPCRBankSM3_256;

struct RoTSM3Context {
    uint32_t state[8];
    uint8_t  buf[64];
    uint64_t cur_buf_len;
    uint64_t compressed_len;
};
typedef struct RoTSM3Context RoTSM3Context;

struct RoTPCRContext {
    RoTPCRBankSHA1     sha1;
    bool               sha1_enabled;
    RoTPCRBankSHA256   sha256;
    bool               sha256_enabled;
    RoTPCRBankSHA384   sha384;
    bool               sha384_enabled;
    RoTPCRBankSHA512   sha512;
    bool               sha512_enabled;
    RoTPCRBankSHA3_256 sha3_256;
    bool               sha3_256_enabled;
    RoTPCRBankSHA3_384 sha3_384;
    bool               sha3_384_enabled;
    RoTPCRBankSHA3_512 sha3_512;
    bool               sha3_512_enabled;
    RoTPCRBankSM3_256  sm3_256;
    bool               sm3_256_enabled;
};
typedef struct RoTPCRContext RoTPCRContext;

struct RoTPCRState {
    SysBusDevice parent_obj;

    MemoryRegion mmio;
    MemoryRegion regs_mmio;
    MemoryRegion fifo_mmio;
    
    RoTPCRRegisters *regs;
    RoTPCRContext *ctx;

    Fifo8 input_fifo;
    Fifo8 output_fifo;

    uint8_t pcr_index;
    uint8_t locality;
    uint64_t event_length;

    char *rot_id;
};

/* -------------------------------------------------------------------------- */
/* For SM3 algorithm: start */
/* -------------------------------------------------------------------------- */
#define GM_SM3_IV_A 0x7380166f
#define GM_SM3_IV_B 0x4914b2b9
#define GM_SM3_IV_C 0x172442d7
#define GM_SM3_IV_D 0xda8a0600
#define GM_SM3_IV_E 0xa96f30bc
#define GM_SM3_IV_F 0x163138aa
#define GM_SM3_IV_G 0xe38dee4d
#define GM_SM3_IV_H 0xb0fb0e4e

// Tj constants
#define GM_SM3_T_0 0x79CC4519
#define GM_SM3_T_1 0x7A879D8A

// FFj function
#define GM_SM3_FF_0(x, y, z) ( (x) ^ (y) ^ (z) )
#define GM_SM3_FF_1(x, y, z) ( ( (x) & (y) ) | ( (x) & (z) ) | ( (y) & (z) ) )

// GGj function
#define GM_SM3_GG_0(x, y, z) ( (x) ^ (y) ^ (z) )
#define GM_SM3_GG_1(x, y, z) ( ( (x) & (y) ) | ( (~(x)) & (z) ) )

// Circular left shift
#define  GM_SM3_SHL(x, n) (((x) & 0xFFFFFFFF) << (n % 32))
#define GM_SM3_ROTL(x, n) (GM_SM3_SHL((x), n) | ((x) >> (32 - (n % 32))))

// P0 P1 function
#define GM_SM3_P_0(x) ((x) ^  GM_SM3_ROTL((x),9) ^ GM_SM3_ROTL((x),17))
#define GM_SM3_P_1(x) ((x) ^  GM_SM3_ROTL((x),15) ^ GM_SM3_ROTL((x),23))

// bytes to word
#ifndef GM_GET_UINT32_BE
#define GM_GET_UINT32_BE(n, b, i)                       \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )             \
        | ( (uint32_t) (b)[(i) + 1] << 16 )             \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 3]       );            \
}
#endif

// word to bytes
#ifndef GM_PUT_UINT32_BE
#define GM_PUT_UINT32_BE(n, b ,i)                       \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

static void gm_sm3_bitow(const uint8_t *bi, uint32_t *w)
{
    GM_GET_UINT32_BE( w[ 0], bi,  0 );
    GM_GET_UINT32_BE( w[ 1], bi,  4 );
    GM_GET_UINT32_BE( w[ 2], bi,  8 );
    GM_GET_UINT32_BE( w[ 3], bi, 12 );
    GM_GET_UINT32_BE( w[ 4], bi, 16 );
    GM_GET_UINT32_BE( w[ 5], bi, 20 );
    GM_GET_UINT32_BE( w[ 6], bi, 24 );
    GM_GET_UINT32_BE( w[ 7], bi, 28 );
    GM_GET_UINT32_BE( w[ 8], bi, 32 );
    GM_GET_UINT32_BE( w[ 9], bi, 36 );
    GM_GET_UINT32_BE( w[10], bi, 40 );
    GM_GET_UINT32_BE( w[11], bi, 44 );
    GM_GET_UINT32_BE( w[12], bi, 48 );
    GM_GET_UINT32_BE( w[13], bi, 52 );
    GM_GET_UINT32_BE( w[14], bi, 56 );
    GM_GET_UINT32_BE( w[15], bi, 60 );

    for (int i = 16; i < 68; i++) {
        uint32_t tmp = w[i - 16] ^ w[i - 9] ^ GM_SM3_ROTL(w[i - 3], 15);
        w[i] = GM_SM3_P_1(tmp) ^ (GM_SM3_ROTL(w[i - 13], 7)) ^ w[i - 6];
    }
}

static void gm_sm3_wtow1(const uint32_t *w, uint32_t *w1)
{
    for (int i = 0; i < 64; i++) {
        w1[i] = w[i] ^ w[i + 4];
    }
}

static void rot_sm3_compress(RoTSM3Context *ctx)
{
    uint32_t W[68];
    uint32_t W1[64];

    gm_sm3_bitow(ctx->buf, W);
    gm_sm3_wtow1(W, W1);

    uint32_t SS1, SS2, TT1, TT2, A, B, C, D, E, F, G, H, Tj;
    int j;

    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];
    F = ctx->state[5];
    G = ctx->state[6];
    H = ctx->state[7];

    for(j = 0; j < 64; j++) {
        if (j < 16) { Tj = GM_SM3_T_0; } else { Tj = GM_SM3_T_1; }
        SS1 = GM_SM3_ROTL((GM_SM3_ROTL(A, 12) + E + GM_SM3_ROTL(Tj, j)), 7);
        SS2 = SS1 ^ GM_SM3_ROTL(A, 12);
        if (j < 16) {
            TT1 = GM_SM3_FF_0(A, B, C) + D + SS2 + W1[j];
            TT2 = GM_SM3_GG_0(E, F, G) + H + SS1 + W[j];
        } else {
            TT1 = GM_SM3_FF_1(A, B, C) + D + SS2 + W1[j];
            TT2 = GM_SM3_GG_1(E, F, G) + H + SS1 + W[j];
        }

        D = C; C = GM_SM3_ROTL(B, 9); B = A; A = TT1;
        H = G; G = GM_SM3_ROTL(F, 19); F = E; E = GM_SM3_P_0(TT2);
    }
    ctx->state[0] ^= A;
    ctx->state[1] ^= B;
    ctx->state[2] ^= C;
    ctx->state[3] ^= D;
    ctx->state[4] ^= E;
    ctx->state[5] ^= F;
    ctx->state[6] ^= G;
    ctx->state[7] ^= H;
}

static void sm3_init(RoTSM3Context *ctx)
{
    ctx->state[0] = GM_SM3_IV_A;
    ctx->state[1] = GM_SM3_IV_B;
    ctx->state[2] = GM_SM3_IV_C;
    ctx->state[3] = GM_SM3_IV_D;
    ctx->state[4] = GM_SM3_IV_E;
    ctx->state[5] = GM_SM3_IV_F;
    ctx->state[6] = GM_SM3_IV_G;
    ctx->state[7] = GM_SM3_IV_H;
    ctx->cur_buf_len = 0;
    ctx->compressed_len = 0;
}

static void sm3_process(RoTSM3Context *ctx, const uint8_t *input, uint32_t len)
{
    while (len--) {
		ctx->buf[ctx->cur_buf_len] = *input++;
		ctx->cur_buf_len++;
		if (ctx->cur_buf_len == 64) {
			rot_sm3_compress(ctx);
			ctx->compressed_len += (64 * 8);
			ctx->cur_buf_len = 0;
		}
	}
}

static const uint8_t gm_sm3_padding[64] = {
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static void sm3_done(RoTSM3Context *ctx, uint8_t output[32])
{
	uint32_t padn;
    uint8_t msglen[8];
    uint64_t total_len, high, low;

    total_len = ctx->compressed_len + (ctx->cur_buf_len << 3);
    high = (total_len >> 32) & 0x0FFFFFFFF;
    low = total_len & 0x0FFFFFFFF;

    GM_PUT_UINT32_BE(high, msglen, 0);
    GM_PUT_UINT32_BE(low,  msglen, 4);

    padn = ((ctx->cur_buf_len + 1) <= 56) ? (56 - ctx->cur_buf_len) 
                                          : (120 - ctx->cur_buf_len);

    sm3_process(ctx, (uint8_t *) gm_sm3_padding, padn);
    sm3_process(ctx, msglen, 8);

    GM_PUT_UINT32_BE(ctx->state[0], output,  0);
    GM_PUT_UINT32_BE(ctx->state[1], output,  4);
    GM_PUT_UINT32_BE(ctx->state[2], output,  8);
    GM_PUT_UINT32_BE(ctx->state[3], output, 12);
    GM_PUT_UINT32_BE(ctx->state[4], output, 16);
    GM_PUT_UINT32_BE(ctx->state[5], output, 20);
    GM_PUT_UINT32_BE(ctx->state[6], output, 24);
    GM_PUT_UINT32_BE(ctx->state[7], output, 28);
}
/* -------------------------------------------------------------------------- */
/* For SM3 algorithm: end */
/* -------------------------------------------------------------------------- */


static void rot_pcr_extend_sha1(RoTPCRState *s, uint8_t *digest)
{
    hash_state md;
    sha1_init(&md);
    sha1_process(&md, s->ctx->sha1.pcr[s->pcr_index], ROT_PCR_BANK_SHA1_LENGTH);
    sha1_process(&md, digest, ROT_PCR_BANK_SHA1_LENGTH);
    sha1_done(&md, s->ctx->sha1.pcr[s->pcr_index]);
}

static void rot_pcr_extend_sha256(RoTPCRState *s, uint8_t *digest)
{
    hash_state md;
    sha256_init(&md);
    sha256_process(&md, s->ctx->sha256.pcr[s->pcr_index], ROT_PCR_BANK_SHA256_LENGTH);
    sha256_process(&md, digest, ROT_PCR_BANK_SHA256_LENGTH);
    sha256_done(&md, s->ctx->sha256.pcr[s->pcr_index]);
}

static void rot_pcr_extend_sha384(RoTPCRState *s, uint8_t *digest)
{
    hash_state md;
    sha384_init(&md);
    sha384_process(&md, s->ctx->sha384.pcr[s->pcr_index], ROT_PCR_BANK_SHA384_LENGTH);
    sha384_process(&md, digest, ROT_PCR_BANK_SHA384_LENGTH);
    sha384_done(&md, s->ctx->sha384.pcr[s->pcr_index]);
}

static void rot_pcr_extend_sha512(RoTPCRState *s, uint8_t *digest)
{
    hash_state md;
    sha512_init(&md);
    sha512_process(&md, s->ctx->sha512.pcr[s->pcr_index], ROT_PCR_BANK_SHA512_LENGTH);
    sha512_process(&md, digest, ROT_PCR_BANK_SHA512_LENGTH);
    sha512_done(&md, s->ctx->sha512.pcr[s->pcr_index]);
}

static void rot_pcr_extend_sha3_256(RoTPCRState *s, uint8_t *digest)
{
    hash_state md;
    sha3_256_init(&md);
    sha3_process(&md, s->ctx->sha3_256.pcr[s->pcr_index], ROT_PCR_BANK_SHA3_256_LENGTH);
    sha3_process(&md, digest, ROT_PCR_BANK_SHA3_256_LENGTH);
    sha3_done(&md, s->ctx->sha3_256.pcr[s->pcr_index]);
}

static void rot_pcr_extend_sha3_384(RoTPCRState *s, uint8_t *digest)
{
    hash_state md;
    sha3_384_init(&md);
    sha3_process(&md, s->ctx->sha3_384.pcr[s->pcr_index], ROT_PCR_BANK_SHA3_384_LENGTH);
    sha3_process(&md, digest, ROT_PCR_BANK_SHA3_384_LENGTH);
    sha3_done(&md, s->ctx->sha3_384.pcr[s->pcr_index]);
}

static void rot_pcr_extend_sha3_512(RoTPCRState *s, uint8_t *digest)
{
    hash_state md;
    sha3_512_init(&md);
    sha3_process(&md, s->ctx->sha3_512.pcr[s->pcr_index], ROT_PCR_BANK_SHA3_512_LENGTH);
    sha3_process(&md, digest, ROT_PCR_BANK_SHA3_512_LENGTH);
    sha3_done(&md, s->ctx->sha3_512.pcr[s->pcr_index]);
}

static void rot_pcr_extend_sm3_256(RoTPCRState *s, uint8_t *digest)
{
    RoTSM3Context sm3_ctx;
    sm3_init(&sm3_ctx);
    sm3_process(&sm3_ctx, s->ctx->sm3_256.pcr[s->pcr_index], ROT_PCR_BANK_SM3_256_LENGTH);
    sm3_process(&sm3_ctx, digest, ROT_PCR_BANK_SM3_256_LENGTH);
    sm3_done(&sm3_ctx, s->ctx->sm3_256.pcr[s->pcr_index]);
}

static void rot_pcr_event_sha1(RoTPCRState *s, uint8_t *event)
{
    hash_state md;
    sha1_init(&md);
    sha1_process(&md, s->ctx->sha1.pcr[s->pcr_index], ROT_PCR_BANK_SHA1_LENGTH);
    sha1_process(&md, event, s->event_length);
    sha1_done(&md, s->ctx->sha1.pcr[s->pcr_index]);

    for (int i = 0; i < ROT_PCR_BANK_SHA1_LENGTH; i++) {
        fifo8_push(&s->output_fifo, s->ctx->sha1.pcr[s->pcr_index][i]);
    }
    s->regs->status |= R_STATUS_ALG_BANK_SHA1_MASK;
}

static void rot_pcr_event_sha256(RoTPCRState *s, uint8_t *event)
{
    hash_state md;
    sha256_init(&md);
    sha256_process(&md, s->ctx->sha256.pcr[s->pcr_index], ROT_PCR_BANK_SHA256_LENGTH);
    sha256_process(&md, event, s->event_length);
    sha256_done(&md, s->ctx->sha256.pcr[s->pcr_index]);

    for (int i = 0; i < ROT_PCR_BANK_SHA256_LENGTH; i++) {
        fifo8_push(&s->output_fifo, s->ctx->sha256.pcr[s->pcr_index][i]);
    }
    s->regs->status |= R_STATUS_ALG_BANK_SHA256_MASK;
}

static void rot_pcr_event_sha384(RoTPCRState *s, uint8_t *event)
{
    hash_state md;
    sha384_init(&md);
    sha384_process(&md, s->ctx->sha384.pcr[s->pcr_index], ROT_PCR_BANK_SHA384_LENGTH);
    sha384_process(&md, event, s->event_length);
    sha384_done(&md, s->ctx->sha384.pcr[s->pcr_index]);

    for (int i = 0; i < ROT_PCR_BANK_SHA384_LENGTH; i++) {
        fifo8_push(&s->output_fifo, s->ctx->sha384.pcr[s->pcr_index][i]);
    }
    s->regs->status |= R_STATUS_ALG_BANK_SHA384_MASK;
}

static void rot_pcr_event_sha512(RoTPCRState *s, uint8_t *event)
{
    hash_state md;
    sha512_init(&md);
    sha512_process(&md, s->ctx->sha512.pcr[s->pcr_index], ROT_PCR_BANK_SHA512_LENGTH);
    sha512_process(&md, event, s->event_length);
    sha512_done(&md, s->ctx->sha512.pcr[s->pcr_index]);

    for (int i = 0; i < ROT_PCR_BANK_SHA512_LENGTH; i++) {
        fifo8_push(&s->output_fifo, s->ctx->sha512.pcr[s->pcr_index][i]);
    }
    s->regs->status |= R_STATUS_ALG_BANK_SHA512_MASK;
}

static void rot_pcr_event_sha3_256(RoTPCRState *s, uint8_t *event)
{
    hash_state md;
    sha3_256_init(&md);
    sha3_process(&md, s->ctx->sha3_256.pcr[s->pcr_index], ROT_PCR_BANK_SHA3_256_LENGTH);
    sha3_process(&md, event, s->event_length);
    sha3_done(&md, s->ctx->sha3_256.pcr[s->pcr_index]);

    for (int i = 0; i < ROT_PCR_BANK_SHA3_256_LENGTH; i++) {
        fifo8_push(&s->output_fifo, s->ctx->sha3_256.pcr[s->pcr_index][i]);
    }
    s->regs->status |= R_STATUS_ALG_BANK_SHA3_256_MASK;
}

static void rot_pcr_event_sha3_384(RoTPCRState *s, uint8_t *event)
{
    hash_state md;
    sha3_384_init(&md);
    sha3_process(&md, s->ctx->sha3_384.pcr[s->pcr_index], ROT_PCR_BANK_SHA3_384_LENGTH);
    sha3_process(&md, event, s->event_length);
    sha3_done(&md, s->ctx->sha3_384.pcr[s->pcr_index]);

    for (int i = 0; i < ROT_PCR_BANK_SHA3_384_LENGTH; i++) {
        fifo8_push(&s->output_fifo, s->ctx->sha3_384.pcr[s->pcr_index][i]);
    }
    s->regs->status |= R_STATUS_ALG_BANK_SHA3_384_MASK;
}

static void rot_pcr_event_sha3_512(RoTPCRState *s, uint8_t *event)
{
    hash_state md;
    sha3_512_init(&md);
    sha3_process(&md, s->ctx->sha3_512.pcr[s->pcr_index], ROT_PCR_BANK_SHA3_512_LENGTH);
    sha3_process(&md, event, s->event_length);
    sha3_done(&md, s->ctx->sha3_512.pcr[s->pcr_index]);

    for (int i = 0; i < ROT_PCR_BANK_SHA3_512_LENGTH; i++) {
        fifo8_push(&s->output_fifo, s->ctx->sha3_512.pcr[s->pcr_index][i]);
    }
    s->regs->status |= R_STATUS_ALG_BANK_SHA3_512_MASK;
}

static void rot_pcr_event_sm3_256(RoTPCRState *s, uint8_t *event)
{
    RoTSM3Context sm3_ctx;
    sm3_init(&sm3_ctx);
    sm3_process(&sm3_ctx, s->ctx->sm3_256.pcr[s->pcr_index], ROT_PCR_BANK_SM3_256_LENGTH);
    sm3_process(&sm3_ctx, event, s->event_length);
    sm3_done(&sm3_ctx, s->ctx->sm3_256.pcr[s->pcr_index]);

    for (int i = 0; i < ROT_PCR_BANK_SM3_256_LENGTH; i++) {
        fifo8_push(&s->output_fifo, s->ctx->sm3_256.pcr[s->pcr_index][i]);
    }
    s->regs->status |= R_STATUS_ALG_BANK_SM3_256_MASK;
}

static inline void rot_clear_status_alg_banks(RoTPCRState *s)
{
    s->regs->status &= ~R_STATUS_ALG_BANK_SHA1_MASK;
    s->regs->status &= ~R_STATUS_ALG_BANK_SHA256_MASK;
    s->regs->status &= ~R_STATUS_ALG_BANK_SHA384_MASK;
    s->regs->status &= ~R_STATUS_ALG_BANK_SHA512_MASK;
    s->regs->status &= ~R_STATUS_ALG_BANK_SHA3_256_MASK;
    s->regs->status &= ~R_STATUS_ALG_BANK_SHA3_384_MASK;
    s->regs->status &= ~R_STATUS_ALG_BANK_SHA3_512_MASK;
    s->regs->status &= ~R_STATUS_ALG_BANK_SM3_256_MASK;
}

static void rot_start_process(RoTPCRState *s)
{
    switch (s->regs->command) {
    case ROT_PCR_CMD_ALLOCATE:
        qemu_log("Allocate command\n");
        if (s->regs->ctrl & R_CTRL_ALG_BANK_SHA1_MASK) {
            qemu_log("SHA1 bank allocated\n");
            s->ctx->sha1_enabled = true;
            memset(s->ctx->sha1.pcr, 0, sizeof(s->ctx->sha1.pcr));
        } else {
            qemu_log("SHA1 bank not allocated\n");
            s->ctx->sha1_enabled = false;
        }
        if (s->regs->ctrl & R_CTRL_ALG_BANK_SHA256_MASK) {
            qemu_log("SHA256 bank allocated\n");
            s->ctx->sha256_enabled = true;
            memset(s->ctx->sha256.pcr, 0, sizeof(s->ctx->sha256.pcr));
        } else {
            qemu_log("SHA256 bank not allocated\n");
            s->ctx->sha256_enabled = false;
        }
        if (s->regs->ctrl & R_CTRL_ALG_BANK_SHA384_MASK) {
            qemu_log("SHA384 bank allocated\n");
            s->ctx->sha384_enabled = true;
            memset(s->ctx->sha384.pcr, 0, sizeof(s->ctx->sha384.pcr));
        } else {
            qemu_log("SHA384 bank not allocated\n");
            s->ctx->sha384_enabled = false;
        }
        if (s->regs->ctrl & R_CTRL_ALG_BANK_SHA512_MASK) {
            qemu_log("SHA512 bank allocated\n");
            s->ctx->sha512_enabled = true;
            memset(s->ctx->sha512.pcr, 0, sizeof(s->ctx->sha512.pcr));
        } else {
            qemu_log("SHA512 bank not allocated\n");
            s->ctx->sha512_enabled = false;
        }
        if (s->regs->ctrl & R_CTRL_ALG_BANK_SHA3_256_MASK) {
            qemu_log("SHA3_256 bank allocated\n");
            s->ctx->sha3_256_enabled = true;
            memset(s->ctx->sha3_256.pcr, 0, sizeof(s->ctx->sha3_256.pcr));
        } else {
            qemu_log("SHA3_256 bank not allocated\n");
            s->ctx->sha3_256_enabled = false;
        }
        if (s->regs->ctrl & R_CTRL_ALG_BANK_SHA3_384_MASK) {
            qemu_log("SHA3_384 bank allocated\n");
            s->ctx->sha3_384_enabled = true;
            memset(s->ctx->sha3_384.pcr, 0, sizeof(s->ctx->sha3_384.pcr));
        } else {
            qemu_log("SHA3_384 bank not allocated\n");
            s->ctx->sha3_384_enabled = false;
        }
        if (s->regs->ctrl & R_CTRL_ALG_BANK_SHA3_512_MASK) {
            qemu_log("SHA3_512 bank allocated\n");
            s->ctx->sha3_512_enabled = true;
            memset(s->ctx->sha3_512.pcr, 0, sizeof(s->ctx->sha3_512.pcr));
        } else {
            qemu_log("SHA3_512 bank not allocated\n");
            s->ctx->sha3_512_enabled = false;
        }
        if (s->regs->ctrl & R_CTRL_ALG_BANK_SM3_256_MASK) {
            qemu_log("SM3_256 bank allocated\n");
            s->ctx->sm3_256_enabled = true;
            memset(s->ctx->sm3_256.pcr, 0, sizeof(s->ctx->sm3_256.pcr));
        } else {
            qemu_log("SM3_256 bank not allocated\n");
            s->ctx->sm3_256_enabled = false;
        }
        break;
    case ROT_PCR_CMD_RESET:
        /* reset all allocated banks */
        qemu_log("Reset command\n");
        bool reset_flag = (s->locality & reset_locality_table[s->pcr_index]);
        if (!reset_flag) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "%s: PCR %d is not resetable (need loc: %02x, current loc: %02x)\n",
                          __func__, s->pcr_index, reset_locality_table[s->pcr_index], s->locality);
            break;
        }
        if (s->ctx->sha1_enabled) {
            for (int i = 0; i < 5; i++) {
                if (reset_to_zero_table[i] == s->pcr_index) {
                    memset(s->ctx->sha1.pcr[s->pcr_index], 0, ROT_PCR_BANK_SHA1_LENGTH);
                } else { /* others no change */
                    qemu_log("%s: SHA1 PCR %d no change\n",
                             __func__, s->pcr_index);
                }
            }
        }
        if (s->ctx->sha256_enabled) {
            for (int i = 0; i < 5; i++) {
                if (reset_to_zero_table[i] == s->pcr_index) {
                    memset(s->ctx->sha256.pcr[s->pcr_index], 0, ROT_PCR_BANK_SHA256_LENGTH);
                } else { /* others no change */
                    qemu_log("%s: SHA256 PCR %d no change\n",
                             __func__, s->pcr_index);
                }
            }
        }
        if (s->ctx->sha384_enabled) {
            for (int i = 0; i < 5; i++) {
                if (reset_to_zero_table[i] == s->pcr_index) {
                    memset(s->ctx->sha384.pcr[s->pcr_index], 0, ROT_PCR_BANK_SHA384_LENGTH);
                } else { /* others no change */
                    qemu_log("%s: SHA384 PCR %d no change\n",
                             __func__, s->pcr_index);
                }
            }
        }
        if (s->ctx->sha512_enabled) {
            for (int i = 0; i < 5; i++) {
                if (reset_to_zero_table[i] == s->pcr_index) {
                    memset(s->ctx->sha512.pcr[s->pcr_index], 0, ROT_PCR_BANK_SHA512_LENGTH);
                } else { /* others no change */
                    qemu_log("%s: SHA512 PCR %d no change\n",
                             __func__, s->pcr_index);
                }
            }
        }
        if (s->ctx->sha3_256_enabled) {
            for (int i = 0; i < 5; i++) {
                if (reset_to_zero_table[i] == s->pcr_index) {
                    memset(s->ctx->sha3_256.pcr[s->pcr_index], 0, ROT_PCR_BANK_SHA3_256_LENGTH);
                } else { /* others no change */
                    qemu_log("%s: SHA3_256 PCR %d no change\n",
                             __func__, s->pcr_index);
                }
            }
        }
        if (s->ctx->sha3_384_enabled) {
            for (int i = 0; i < 5; i++) {
                if (reset_to_zero_table[i] == s->pcr_index) {
                    memset(s->ctx->sha3_384.pcr[s->pcr_index], 0, ROT_PCR_BANK_SHA3_384_LENGTH);
                } else { /* others no change */
                    qemu_log("%s: SHA3_384 PCR %d no change\n",
                             __func__, s->pcr_index);
                }
            }
        }
        if (s->ctx->sha3_512_enabled) {
            for (int i = 0; i < 5; i++) {
                if (reset_to_zero_table[i] == s->pcr_index) {
                    memset(s->ctx->sha3_512.pcr[s->pcr_index], 0, ROT_PCR_BANK_SHA3_512_LENGTH);
                } else { /* others no change */
                    qemu_log("%s: SHA3_512 PCR %d no change\n",
                             __func__, s->pcr_index);
                }
            }
        }
        if (s->ctx->sm3_256_enabled) {
            for (int i = 0; i < 5; i++) {
                if (reset_to_zero_table[i] == s->pcr_index) {
                    memset(s->ctx->sm3_256.pcr[s->pcr_index], 0, ROT_PCR_BANK_SM3_256_LENGTH);
                } else { /* others no change */
                    qemu_log("%s: SM3_256 PCR %d no change\n",
                             __func__, s->pcr_index);
                }
            }
        }
        break;
    case ROT_PCR_CMD_READ:
        /* clear status alg banks */
        qemu_log("Read command\n");
        rot_clear_status_alg_banks(s);
        /* read PCR value(selected PCR register) from selected bank */
        if (s->ctx->sha1_enabled) { /* sha1 bank is allocated */
            if (s->regs->ctrl & R_CTRL_ALG_BANK_SHA1_MASK) { /* sha1 bank is selected */
                for (int i = 0; i < ROT_PCR_BANK_SHA1_LENGTH; i++) {
                    fifo8_push(&s->output_fifo, s->ctx->sha1.pcr[s->pcr_index][i]);
                }
            }
            /* software use this bit to unmarshal the output FIFO(sha1 PCR value) */
            s->regs->status |= R_STATUS_ALG_BANK_SHA1_MASK;
        }
        if (s->ctx->sha256_enabled) { /* sha256 bank is allocated */
            if (s->regs->ctrl & R_CTRL_ALG_BANK_SHA256_MASK) { /* sha256 bank is selected */
                for (int i = 0; i < ROT_PCR_BANK_SHA256_LENGTH; i++) {
                    fifo8_push(&s->output_fifo, s->ctx->sha256.pcr[s->pcr_index][i]);
                }
            }
            /* software use this bit to unmarshal the output FIFO(sha256 PCR value) */
            s->regs->status |= R_STATUS_ALG_BANK_SHA256_MASK;
        }
        if (s->ctx->sha384_enabled) { /* sha384 bank is allocated */
            if (s->regs->ctrl & R_CTRL_ALG_BANK_SHA384_MASK) { /* sha384 bank is selected */
                for (int i = 0; i < ROT_PCR_BANK_SHA384_LENGTH; i++) {
                    fifo8_push(&s->output_fifo, s->ctx->sha384.pcr[s->pcr_index][i]);
                }
            }
            /* software use this bit to unmarshal the output FIFO(sha384 PCR value) */
            s->regs->status |= R_STATUS_ALG_BANK_SHA384_MASK;
        }
        if (s->ctx->sha512_enabled) { /* sha512 bank is allocated */
            if (s->regs->ctrl & R_CTRL_ALG_BANK_SHA512_MASK) { /* sha512 bank is selected */
                for (int i = 0; i < ROT_PCR_BANK_SHA512_LENGTH; i++) {
                    fifo8_push(&s->output_fifo, s->ctx->sha512.pcr[s->pcr_index][i]);
                }
            }
            /* software use this bit to unmarshal the output FIFO(sha512 PCR value) */
            s->regs->status |= R_STATUS_ALG_BANK_SHA512_MASK;
        }
        if (s->ctx->sha3_256_enabled) { /* sha3_256 bank is allocated */
            if (s->regs->ctrl & R_CTRL_ALG_BANK_SHA3_256_MASK) { /* sha3_256 bank is selected */
                for (int i = 0; i < ROT_PCR_BANK_SHA3_256_LENGTH; i++) {
                    fifo8_push(&s->output_fifo, s->ctx->sha3_256.pcr[s->pcr_index][i]);
                }
            }
            /* software use this bit to unmarshal the output FIFO(sha3_256 PCR value) */
            s->regs->status |= R_STATUS_ALG_BANK_SHA3_256_MASK;
        }
        if (s->ctx->sha3_384_enabled) { /* sha3_384 bank is allocated */
            if (s->regs->ctrl & R_CTRL_ALG_BANK_SHA3_384_MASK) { /* sha3_384 bank is selected */
                for (int i = 0; i < ROT_PCR_BANK_SHA3_384_LENGTH; i++) {
                    fifo8_push(&s->output_fifo, s->ctx->sha3_384.pcr[s->pcr_index][i]);
                }
            }
            /* software use this bit to unmarshal the output FIFO(sha3_384 PCR value) */
            s->regs->status |= R_STATUS_ALG_BANK_SHA3_384_MASK;
        }
        if (s->ctx->sha3_512_enabled) { /* sha3_512 bank is allocated */
            if (s->regs->ctrl & R_CTRL_ALG_BANK_SHA3_512_MASK) { /* sha3_512 bank is selected */
                for (int i = 0; i < ROT_PCR_BANK_SHA3_512_LENGTH; i++) {
                    fifo8_push(&s->output_fifo, s->ctx->sha3_512.pcr[s->pcr_index][i]);
                }
            }
            /* software use this bit to unmarshal the output FIFO(sha3_512 PCR value) */
            s->regs->status |= R_STATUS_ALG_BANK_SHA3_512_MASK;
        }
        if (s->ctx->sm3_256_enabled) { /* sm3_256 bank is allocated */
            if (s->regs->ctrl & R_CTRL_ALG_BANK_SM3_256_MASK) { /* sm3_256 bank is selected */
                for (int i = 0; i < ROT_PCR_BANK_SM3_256_LENGTH; i++) {
                    fifo8_push(&s->output_fifo, s->ctx->sm3_256.pcr[s->pcr_index][i]);
                }
            }
            /* software use this bit to unmarshal the output FIFO(sm3_256 PCR value) */
            s->regs->status |= R_STATUS_ALG_BANK_SM3_256_MASK;
        }
        break;
    case ROT_PCR_CMD_EXTEND:
        /* extend PCR value(selected PCR register) from selected bank */
        qemu_log("Extend command\n");
        bool extend_flag = (s->locality & extend_locality_table[s->pcr_index]);
        if (s->ctx->sha1_enabled) { /* sha1 bank is allocated */
            if (s->regs->ctrl & R_CTRL_ALG_BANK_SHA1_MASK) { /* sha1 bank is selected */
                uint8_t digest[ROT_PCR_BANK_SHA1_LENGTH];
                for (int i = 0; i < ROT_PCR_BANK_SHA1_LENGTH; i++) {
                    digest[i] = fifo8_pop(&s->input_fifo);
                }
                if (extend_flag) { /* locality is valid */
                    rot_pcr_extend_sha1(s, digest);
                } else {
                    qemu_log_mask(LOG_GUEST_ERROR,
                                "%s: SHA1 PCR %d is not extendable (loc: %02x)\n",
                                __func__, s->pcr_index, s->locality);
                }
            }
        }
        if (s->ctx->sha256_enabled) { /* sha256 bank is allocated */
            if (s->regs->ctrl & R_CTRL_ALG_BANK_SHA256_MASK) { /* sha256 bank is selected */
                uint8_t digest[ROT_PCR_BANK_SHA256_LENGTH];
                for (int i = 0; i < ROT_PCR_BANK_SHA256_LENGTH; i++) {
                    digest[i] = fifo8_pop(&s->input_fifo);
                }
                if (extend_flag) { /* locality is valid */
                    rot_pcr_extend_sha256(s, digest);
                } else {
                qemu_log_mask(LOG_GUEST_ERROR,
                              "%s: SHA256 PCR %d is not extendable (loc: %02x)\n",
                              __func__, s->pcr_index, s->locality);
                }
            }
        }
        if (s->ctx->sha384_enabled) { /* sha384 bank is allocated */
            if (s->regs->ctrl & R_CTRL_ALG_BANK_SHA384_MASK) { /* sha384 bank is selected */
                uint8_t digest[ROT_PCR_BANK_SHA384_LENGTH];
                for (int i = 0; i < ROT_PCR_BANK_SHA384_LENGTH; i++) {
                    digest[i] = fifo8_pop(&s->input_fifo);
                }
                if (extend_flag) { /* locality is valid */
                    rot_pcr_extend_sha384(s, digest);
                } else {
                    qemu_log_mask(LOG_GUEST_ERROR,
                                "%s: SHA384 PCR %d is not extendable (loc: %02x)\n",
                                __func__, s->pcr_index, s->locality);
                }
            }
        }
        if (s->ctx->sha512_enabled) { /* sha512 bank is allocated */
            if (s->regs->ctrl & R_CTRL_ALG_BANK_SHA512_MASK) { /* sha512 bank is selected */
                uint8_t digest[ROT_PCR_BANK_SHA512_LENGTH];
                for (int i = 0; i < ROT_PCR_BANK_SHA512_LENGTH; i++) {
                    digest[i] = fifo8_pop(&s->input_fifo);
                }
                if (extend_flag) { /* locality is valid */
                    rot_pcr_extend_sha512(s, digest);
                } else {
                    qemu_log_mask(LOG_GUEST_ERROR,
                                "%s: SHA512 PCR %d is not extendable (loc: %02x)\n",
                                __func__, s->pcr_index, s->locality);
                }
            }
        }
        if (s->ctx->sha3_256_enabled) { /* sha3_256 bank is allocated */
            if (s->regs->ctrl & R_CTRL_ALG_BANK_SHA3_256_MASK) { /* sha3_256 bank is selected */
                uint8_t digest[ROT_PCR_BANK_SHA3_256_LENGTH];
                for (int i = 0; i < ROT_PCR_BANK_SHA3_256_LENGTH; i++) {
                    digest[i] = fifo8_pop(&s->input_fifo);
                }
                if (extend_flag) { /* locality is valid */
                    rot_pcr_extend_sha3_256(s, digest);
                } else {
                    qemu_log_mask(LOG_GUEST_ERROR,
                                "%s: SHA3_256 PCR %d is not extendable (loc: %02x)\n",
                                __func__, s->pcr_index, s->locality);
                }
            }
        }
        if (s->ctx->sha3_384_enabled) { /* sha3_384 bank is allocated */
            if (s->regs->ctrl & R_CTRL_ALG_BANK_SHA3_384_MASK) { /* sha3_384 bank is selected */
                uint8_t digest[ROT_PCR_BANK_SHA3_384_LENGTH];
                for (int i = 0; i < ROT_PCR_BANK_SHA3_384_LENGTH; i++) {
                    digest[i] = fifo8_pop(&s->input_fifo);
                }
                if (extend_flag) { /* locality is valid */
                    rot_pcr_extend_sha3_384(s, digest);
                } else {
                    qemu_log_mask(LOG_GUEST_ERROR,
                                "%s: SHA3_384 PCR %d is not extendable (loc: %02x)\n",
                                __func__, s->pcr_index, s->locality);
                }
            }
        }
        if (s->ctx->sha3_512_enabled) { /* sha3_512 bank is allocated */
            if (s->regs->ctrl & R_CTRL_ALG_BANK_SHA3_512_MASK) { /* sha3_512 bank is selected */
                uint8_t digest[ROT_PCR_BANK_SHA3_512_LENGTH];
                for (int i = 0; i < ROT_PCR_BANK_SHA3_512_LENGTH; i++) {
                    digest[i] = fifo8_pop(&s->input_fifo);
                }
                if (extend_flag) { /* locality is valid */
                    rot_pcr_extend_sha3_512(s, digest);
                } else {
                    qemu_log_mask(LOG_GUEST_ERROR,
                                "%s: SHA3_512 PCR %d is not extendable (loc: %02x)\n",
                                __func__, s->pcr_index, s->locality);
                }
            }
        }
        if (s->ctx->sm3_256_enabled) { /* sm3_256 bank is allocated */
            if (s->regs->ctrl & R_CTRL_ALG_BANK_SM3_256_MASK) { /* sm3_256 bank is selected */
                uint8_t digest[ROT_PCR_BANK_SM3_256_LENGTH];
                for (int i = 0; i < ROT_PCR_BANK_SM3_256_LENGTH; i++) {
                    digest[i] = fifo8_pop(&s->input_fifo);
                }
                if (extend_flag) { /* locality is valid */
                    rot_pcr_extend_sm3_256(s, digest);
                } else {
                    qemu_log_mask(LOG_GUEST_ERROR,
                              "%s: SM3_256 PCR %d is not extendable (loc: %02x)\n",
                              __func__, s->pcr_index, s->locality);
                }
            }
        }
        s->event_length = 0;
        break;
    case ROT_PCR_CMD_EVENT:
        /* clear status alg banks */
        qemu_log("Event command\n");
        rot_clear_status_alg_banks(s);
        /* event PCR value(selected PCR register) from selected bank */
        bool event_flag = (s->locality & extend_locality_table[s->pcr_index]);
        uint8_t event[ROT_PCR_FIFO_LENGTH];
        for (int i = 0; i < s->event_length; i++) {
            event[i] = fifo8_pop(&s->input_fifo);
        }
        if (s->ctx->sha1_enabled) { /* sha1 bank is allocated */
            if (s->regs->ctrl & R_CTRL_ALG_BANK_SHA1_MASK) { /* sha1 bank is selected */
                if (event_flag) { /* locality is valid */
                    rot_pcr_event_sha1(s, event);
                } else {
                    qemu_log_mask(LOG_GUEST_ERROR,
                                "%s: SHA1 PCR %d is not event extendable (loc: %02x)\n",
                                __func__, s->pcr_index, s->locality);
                }
            }
        }
        if (s->ctx->sha256_enabled) { /* sha256 bank is allocated */
            if (s->regs->ctrl & R_CTRL_ALG_BANK_SHA256_MASK) { /* sha256 bank is selected */
                if (event_flag) { /* locality is valid */
                    rot_pcr_event_sha256(s, event);
                } else {
                qemu_log_mask(LOG_GUEST_ERROR,
                              "%s: SHA256 PCR %d is not event extendable (loc: %02x)\n",
                              __func__, s->pcr_index, s->locality);
                }
            }
        }
        if (s->ctx->sha384_enabled) { /* sha384 bank is allocated */
            if (s->regs->ctrl & R_CTRL_ALG_BANK_SHA384_MASK) { /* sha384 bank is selected */
                if (event_flag) { /* locality is valid */
                    rot_pcr_event_sha384(s, event);
                } else {
                    qemu_log_mask(LOG_GUEST_ERROR,
                                "%s: SHA384 PCR %d is not event extendable (loc: %02x)\n",
                                __func__, s->pcr_index, s->locality);
                }
            }
        }
        if (s->ctx->sha512_enabled) { /* sha512 bank is allocated */
            if (s->regs->ctrl & R_CTRL_ALG_BANK_SHA512_MASK) { /* sha512 bank is selected */
                if (event_flag) { /* locality is valid */
                    rot_pcr_event_sha512(s, event);
                } else {
                qemu_log_mask(LOG_GUEST_ERROR,
                              "%s: SHA512 PCR %d is not event extendable (loc: %02x)\n",
                              __func__, s->pcr_index, s->locality);
                }
            }
        }
        if (s->ctx->sha3_256_enabled) { /* sha3_256 bank is allocated */
            if (s->regs->ctrl & R_CTRL_ALG_BANK_SHA3_256_MASK) { /* sha3_256 bank is selected */
                if (event_flag) { /* locality is valid */
                    rot_pcr_event_sha3_256(s, event);
                } else {
                    qemu_log_mask(LOG_GUEST_ERROR,
                                "%s: SHA3_256 PCR %d is not event extendable (loc: %02x)\n",
                                __func__, s->pcr_index, s->locality);
                }
            }
        }
        if (s->ctx->sha3_384_enabled) { /* sha3_384 bank is allocated */
            if (s->regs->ctrl & R_CTRL_ALG_BANK_SHA3_384_MASK) { /* sha3_384 bank is selected */
                if (event_flag) { /* locality is valid */
                    rot_pcr_event_sha3_384(s, event);
                } else {
                    qemu_log_mask(LOG_GUEST_ERROR,
                                "%s: SHA3_384 PCR %d is not event extendable (loc: %02x)\n",
                                __func__, s->pcr_index, s->locality);
                }
            }
        }
        if (s->ctx->sha3_512_enabled) { /* sha3_512 bank is allocated */
            if (s->regs->ctrl & R_CTRL_ALG_BANK_SHA3_512_MASK) { /* sha3_512 bank is selected */
                if (event_flag) { /* locality is valid */
                    rot_pcr_event_sha3_512(s, event);
                } else {
                    qemu_log_mask(LOG_GUEST_ERROR,
                                "%s: SHA3_512 PCR %d is not event extendable (loc: %02x)\n",
                                __func__, s->pcr_index, s->locality);
                }
            }
        }
        if (s->ctx->sm3_256_enabled) { /* sm3_256 bank is allocated */
            if (s->regs->ctrl & R_CTRL_ALG_BANK_SM3_256_MASK) { /* sm3_256 bank is selected */
                if (event_flag) { /* locality is valid */
                    rot_pcr_event_sm3_256(s, event);
                } else {
                qemu_log_mask(LOG_GUEST_ERROR,
                              "%s: SM3_256 PCR %d is not event extendable (loc: %02x)\n",
                              __func__, s->pcr_index, s->locality);
                }
            }
        }
        s->event_length = 0;
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: invalid command\n",
                      __func__);
        break;
    }

    s->regs->status |= R_STATUS_OP_DONE_MASK;
}

static uint64_t rot_pcr_regs_read(void *opaque, hwaddr addr, unsigned size)
{
    RoTPCRState *s = ROT_PCR(opaque);
    (void)size;
    uint32_t val32 = 0;
    hwaddr reg = R32_OFF(addr);

    switch (reg) {
    case R_CTRL:    // wo
    case R_COMMAND: // wo
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: W/O register 0x%02" HWADDR_PRIx " (%s)\n",
                      __func__, addr, REG_NAME(reg));
        val32 = 0;

        break;
    // ro
    case R_STATUS:
        val32 = s->regs->status;

        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR, 
                      "%s: bad offset 0x%" HWADDR_PRIx "\n",
                      __func__, addr);
        val32 = 0;

        break;
    }

    return (uint64_t)val32;
}

static void rot_pcr_regs_write(void *opaque, hwaddr addr, uint64_t val,
                               unsigned size)
{
    RoTPCRState *s = ROT_PCR(opaque);
    (void)size;
    uint32_t val32 = (uint32_t)val;
    hwaddr reg = R32_OFF(addr);

    switch (reg) {
    // wo
    case R_CTRL:
        s->regs->ctrl = (val32 & CTRL_MASK);
        s->pcr_index = FIELD_EX32(s->regs->ctrl, CTRL, SELECTION);
        s->locality = FIELD_EX32(s->regs->ctrl, CTRL, LOCALITY);

        /* clear status */
        s->regs->status &= ~R_STATUS_OP_DONE_MASK;

        break;
    // wo
    case R_COMMAND:
        s->regs->command = (val32 & COMMAND_MASK);

        rot_start_process(s);

        break;
    // ro
    case R_STATUS:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: R/O register 0x%02" HWADDR_PRIx " (%s)\n",
                      __func__, addr, REG_NAME(reg));

        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR, 
                      "%s: bad offset 0x%" HWADDR_PRIx "\n",
                      __func__, addr);
        
        break;
    }
}

static uint64_t rot_pcr_fifo_read(void *opaque, hwaddr addr, unsigned size)
{
    RoTPCRState *s = ROT_PCR(opaque);
    uint64_t ret = 0;

    for (unsigned i = 0; i < size && !fifo8_is_empty(&s->output_fifo); i++) {
        uint8_t val = fifo8_pop(&s->output_fifo);
        ret |= (uint64_t)val << (i * 8);
    }

    return ret;
}

static void rot_pcr_fifo_write(void *opaque, hwaddr addr, uint64_t val,
                               unsigned size)
{
    RoTPCRState *s = ROT_PCR(opaque);
    (void)size;
    (void)addr;
    
    for (unsigned i = 0; i < size; i++) {
        uint8_t b = val;
        g_assert(!fifo8_is_full(&s->input_fifo));
        qemu_log("size: %d, push byte: %02x\n", size, b);
        fifo8_push(&s->input_fifo, b);
        val >>= 8u;
    }

    /* total bytes of event */
    s->event_length += (uint64_t)size;
}

static const MemoryRegionOps rot_pcr_regs_ops = {
    .read  = &rot_pcr_regs_read,
    .write = &rot_pcr_regs_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static const MemoryRegionOps rot_pcr_fifo_ops = {
    .read  = &rot_pcr_fifo_read,
    .write = &rot_pcr_fifo_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
};

static void rot_pcr_init(Object *obj)
{
    RoTPCRState *s = ROT_PCR(obj);

    s->regs = g_new0(RoTPCRRegisters, 1u);
    s->ctx = g_new0(RoTPCRContext, 1u);

    // TODO
    // for (unsigned ix = 0; ix < PARAM_NUM_IRQS; ix++) {
    //     rot_sysbus_init_irq(obj, &s->irqs[ix]);
    // }

    memory_region_init(&s->mmio, OBJECT(s), TYPE_ROT_PCR, ROT_PCR_MMIO_SIZE);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->mmio);

    memory_region_init_io(&s->regs_mmio, obj, &rot_pcr_regs_ops, s,
                          TYPE_ROT_PCR ".regs", REGS_SIZE);
    memory_region_add_subregion(&s->mmio, ROT_PCR_REGS_BASE, &s->regs_mmio);

    memory_region_init_io(&s->fifo_mmio, obj, &rot_pcr_fifo_ops, s,
                          TYPE_ROT_PCR ".fifo", ROT_PCR_FIFO_SIZE);
    memory_region_add_subregion(&s->mmio, ROT_PCR_FIFO_BASE, &s->fifo_mmio);

    fifo8_create(&s->input_fifo, ROT_PCR_FIFO_LENGTH);
    fifo8_create(&s->output_fifo, ROT_PCR_FIFO_LENGTH);
}

static void rot_pcr_reset(DeviceState *dev)
{
    RoTPCRState *s = ROT_PCR(dev);
    
    memset(s->regs, 0, sizeof(*(s->regs)));
    memset(s->ctx, 0, sizeof(*(s->ctx)));

    // TODO
    // rot_pcr_update_irqs(s);

    fifo8_reset(&s->input_fifo);
    fifo8_reset(&s->output_fifo);
}

static void rot_pcr_realize(DeviceState *dev, Error **errp)
{
    (void)errp;

    RoTPCRState *s = ROT_PCR(dev);
    
    g_assert(s->rot_id);
}

static Property rot_pcr_properties[] = {
    DEFINE_PROP_STRING("rot-id", RoTPCRState, rot_id),
    DEFINE_PROP_END_OF_LIST(),
};

static void rot_pcr_class_init(ObjectClass *klass, void *data)
{
    (void)data;
    DeviceClass *dc = DEVICE_CLASS(klass);

    device_class_set_legacy_reset(dc, &rot_pcr_reset);
    dc->realize = &rot_pcr_realize;

    device_class_set_props(dc, rot_pcr_properties);
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo rot_pcr_info = {
    .name          = TYPE_ROT_PCR,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(RoTPCRState),
    .instance_init = &rot_pcr_init,
    .class_init    = &rot_pcr_class_init,
};

static void rot_pcr_register_types(void)
{
    type_register_static(&rot_pcr_info);
}

type_init(rot_pcr_register_types)
