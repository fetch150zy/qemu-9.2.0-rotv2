/*
 * QEMU Root of Trust v2 SM4 device
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
#include "hw/qdev-properties.h"
#include "hw/qdev-core.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "hw/registerfields.h"

#include "hw/rotv2/rot_sm4.h"


/* clang-format off */
REG32(CTRL_SIGNALS, 0x0u)
    FIELD(CTRL_SIGNALS, SM4_ENABLE_IN, 0u, 1u)
    FIELD(CTRL_SIGNALS, ENCDEC_SEL_IN, 1u, 1u)
    FIELD(CTRL_SIGNALS, ENABLE_KEY_EXP_IN, 2u, 1u)
    FIELD(CTRL_SIGNALS, USER_KEY_VALID_IN, 3u, 1u)
    FIELD(CTRL_SIGNALS, ENCDEC_ENABLE_IN, 4u, 1u)
    FIELD(CTRL_SIGNALS, VALID_IN, 5u, 1u)
REG32(STATE_SIGNALS, 0x4u)
    FIELD(STATE_SIGNALS, KEY_EXP_READY_OUT, 0u, 1u)
    FIELD(STATE_SIGNALS, VALID_OUT, 1u, 1u)
REG32(KEY_0, 0x8u)
REG32(KEY_1, 0xcu)
REG32(KEY_2, 0x10u)
REG32(KEY_3, 0x14u)
REG32(DATA_IN_0, 0x18u)
REG32(DATA_IN_1, 0x1cu)
REG32(DATA_IN_2, 0x20u)
REG32(DATA_IN_3, 0x24u)
REG32(RESULT_OUT_0, 0x28u)
REG32(RESULT_OUT_1, 0x2cu)
REG32(RESULT_OUT_2, 0x30u)
REG32(RESULT_OUT_3, 0x34u)
/* clang-format on */

#define CTRL_SIGNALS_MASK                    \
    (R_CTRL_SIGNALS_SM4_ENABLE_IN_MASK |     \
     R_CTRL_SIGNALS_ENABLE_KEY_EXP_IN_MASK | \
     R_CTRL_SIGNALS_ENCDEC_SEL_IN_MASK |     \
     R_CTRL_SIGNALS_USER_KEY_VALID_IN_MASK | \
     R_CTRL_SIGNALS_ENCDEC_ENABLE_IN_MASK |  \
     R_CTRL_SIGNALS_VALID_IN_MASK)

#define R32_OFF(_r_) ((_r_) / sizeof(uint32_t))

#define R_LAST_REG (R_RESULT_OUT_3)
#define REGS_COUNT (R_LAST_REG + 1u)
#define REGS_SIZE  (REGS_COUNT * sizeof(uint32_t))
#define REG_NAME(_reg_) \
    ((((_reg_) <= REGS_COUNT) && REG_NAMES[_reg_]) ? REG_NAMES[_reg_] : "?")

#define REG_NAME_ENTRY(_reg_) [R_##_reg_] = stringify(_reg_)
static const char *REG_NAMES[REGS_COUNT] = {
    REG_NAME_ENTRY(CTRL_SIGNALS),
    REG_NAME_ENTRY(STATE_SIGNALS),
    REG_NAME_ENTRY(KEY_0),
    REG_NAME_ENTRY(KEY_1),
    REG_NAME_ENTRY(KEY_2),
    REG_NAME_ENTRY(KEY_3),
    REG_NAME_ENTRY(DATA_IN_0),
    REG_NAME_ENTRY(DATA_IN_1),
    REG_NAME_ENTRY(DATA_IN_2),
    REG_NAME_ENTRY(DATA_IN_3),
    REG_NAME_ENTRY(RESULT_OUT_0),
    REG_NAME_ENTRY(RESULT_OUT_1),
    REG_NAME_ENTRY(RESULT_OUT_2),
    REG_NAME_ENTRY(RESULT_OUT_3),
};
#undef REG_NAME_ENTRY

#define ROT_SM4_REGS_KEY_LENGTH    16u
#define ROT_SM4_REGS_DATA_LENGTH   16u
#define ROT_SM4_REGS_RESULT_LENGTH 16u
#define ROT_SM4_CTX_RK_LENGTH      128u
#define ROT_SM4_CTX_BUF_LENGTH     16u
#define ROT_SM4_CTX_IV_LENGTH      16u

struct RoTSM4Registers {
    uint32_t ctrl_signals;
    uint32_t state_signals;
    uint32_t key[ROT_SM4_REGS_KEY_LENGTH / sizeof(uint32_t)];
    uint32_t data_in[ROT_SM4_REGS_DATA_LENGTH / sizeof(uint32_t)];
    uint32_t result_out[ROT_SM4_REGS_RESULT_LENGTH / sizeof(uint32_t)];
};
typedef struct RoTSM4Registers RoTSM4Registers;

struct RoTSM4Context {
    uint32_t rk[ROT_SM4_CTX_RK_LENGTH / sizeof(uint32_t)];
    uint8_t  buf[ROT_SM4_CTX_BUF_LENGTH];
    uint8_t  iv[ROT_SM4_CTX_IV_LENGTH];
    uint32_t cur_buf_len;
    uint32_t total_len;
    uint32_t state;
};
typedef struct RoTSM4Context RoTSM4Context;

struct RoTSM4State {
    SysBusDevice parent_obj;
    
    MemoryRegion mmio;
    
    RoTSM4Registers *regs;
    RoTSM4Context *ctx;

    bool sm4_on;
    /* false: calculating done, true: in calculating */
    bool calculating; 

    char *rot_id;
};

static inline bool rot_sm4_is_sm4_enabled(RoTSM4State *s)
{
    return (s->regs->ctrl_signals & R_CTRL_SIGNALS_SM4_ENABLE_IN_MASK);
}

static inline bool rot_sm4_is_enc_dec_enabled(RoTSM4State *s)
{
    return (s->regs->ctrl_signals & R_CTRL_SIGNALS_ENCDEC_ENABLE_IN_MASK);
}

static inline bool rot_sm4_is_enc_mode(RoTSM4State *s)
{
    return (s->regs->ctrl_signals & R_CTRL_SIGNALS_ENCDEC_SEL_IN_MASK) == 0;
}

static inline bool rot_sm4_is_dec_mode(RoTSM4State *s)
{
    return (s->regs->ctrl_signals & R_CTRL_SIGNALS_ENCDEC_SEL_IN_MASK) ==
           R_CTRL_SIGNALS_ENCDEC_SEL_IN_MASK;
}

static inline bool rot_sm4_is_key_exp_enabled(RoTSM4State *s)
{
    return (s->regs->ctrl_signals & R_CTRL_SIGNALS_ENABLE_KEY_EXP_IN_MASK);
}

static inline bool rot_sm4_is_key_valid(RoTSM4State *s)
{
    return (s->regs->ctrl_signals & R_CTRL_SIGNALS_USER_KEY_VALID_IN_MASK);
}

static inline bool rot_sm4_is_data_valid(RoTSM4State *s)
{
    return (s->regs->ctrl_signals & R_CTRL_SIGNALS_VALID_IN_MASK);
}

static inline bool rot_sm4_is_key_exp_ready(RoTSM4State *s)
{
    return (s->regs->state_signals & R_STATE_SIGNALS_KEY_EXP_READY_OUT_MASK);
}

static inline bool rot_sm4_is_result_ready(RoTSM4State *s)
{
    return (s->regs->state_signals & R_STATE_SIGNALS_VALID_OUT_MASK);
}


/* -------------------------------------------------------------------------- */
/* For SM4 algorithm: start */
/* -------------------------------------------------------------------------- */
#define GM_SHL(x,n) (((x) & 0xFFFFFFFF) << (n % 32))
#define GM_ROTL(x,n) (GM_SHL((x),n) | ((x) >> (32 - (n % 32))))

#ifndef GM_GET_UINT32_BE
#define GM_GET_UINT32_BE(n, b, i)                       \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )             \
        | ( (uint32_t) (b)[(i) + 1] << 16 )             \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 3]       );            \
}
#endif

#ifndef GM_PUT_UINT32_BE
#define GM_PUT_UINT32_BE(n, b ,i)                       \
{                                                       \
    (b)[(i)    ] = (uint8_t) ( (n) >> 24 );             \
    (b)[(i) + 1] = (uint8_t) ( (n) >> 16 );             \
    (b)[(i) + 2] = (uint8_t) ( (n) >>  8 );             \
    (b)[(i) + 3] = (uint8_t) ( (n)       );             \
}
#endif

#define GM_SM4_NON_LINEAR_OP(in, out)                       \
{                                                           \
	(out)  = ( GM_SM4_SBOX[ ((in) >> 24) & 0x0FF ] ) << 24; \
	(out) |= ( GM_SM4_SBOX[ ((in) >> 16) & 0x0FF ] ) << 16; \
	(out) |= ( GM_SM4_SBOX[ ((in) >> 8)  & 0x0FF ] ) << 8;  \
	(out) |= ( GM_SM4_SBOX[ (in)         & 0x0FF ] );       \
}

uint32_t GM_SM4_CK[32] = {
	0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
	0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
	0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
	0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

uint8_t GM_SM4_SBOX[256] = {
	0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7,
    0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
	0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 
    0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
	0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 
    0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
	0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 
    0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
	0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 
    0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
	0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 
    0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
	0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 
    0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
	0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 
    0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
	0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 
    0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
	0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 
    0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
	0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 
    0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
	0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 
    0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
	0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 
    0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
	0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 
    0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
	0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 
    0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
	0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 
    0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

uint32_t GM_SM4_FK[4] = {0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC};

static void gm_sm4_key_schedule(const uint8_t *key, uint32_t *rk)
{
	uint32_t tmp1, tmp2, K[36];
	int i;

    GM_GET_UINT32_BE( K[0], key, 0);
    GM_GET_UINT32_BE( K[1], key, 4);
    GM_GET_UINT32_BE( K[2], key, 8);
    GM_GET_UINT32_BE( K[3], key, 12);

    K[0] ^= GM_SM4_FK[0];
    K[1] ^= GM_SM4_FK[1];
    K[2] ^= GM_SM4_FK[2];
    K[3] ^= GM_SM4_FK[3];

	for(i = 0; i < 32; i++) {
		tmp1 = K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ GM_SM4_CK[i];
		GM_SM4_NON_LINEAR_OP(tmp1, tmp2);
		rk[i] = K[i + 4] = K[i] ^ (tmp2 ^ GM_ROTL(tmp2, 13) ^ GM_ROTL(tmp2, 23));
	}
}

static void gm_sm4_one_round(uint32_t rk[32], int forEncryption, const uint8_t *in,
                      uint8_t *out)
{
	uint32_t X[36], tmp1, tmp2;
	int i;

	GM_GET_UINT32_BE( X[0], in, 0);
    GM_GET_UINT32_BE( X[1], in, 4);
    GM_GET_UINT32_BE( X[2], in, 8);
    GM_GET_UINT32_BE( X[3], in, 12);

	for(i = 0; i < 32; i++) {
		tmp1 = X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[( forEncryption ? i : 31 - i )];
		GM_SM4_NON_LINEAR_OP(tmp1, tmp2);
		unsigned int tt = (tmp2 ^ GM_ROTL(tmp2, 2) ^ GM_ROTL(tmp2, 10) ^ 
                          GM_ROTL(tmp2, 18) ^ GM_ROTL(tmp2, 24));
		X[i + 4] = X[i] ^ tt;
	}

    GM_PUT_UINT32_BE(X[35], out,  0);
    GM_PUT_UINT32_BE(X[34], out,  4);
    GM_PUT_UINT32_BE(X[33], out,  8);
    GM_PUT_UINT32_BE(X[32], out, 12);
}

static void gm_sm4_init(RoTSM4State *s, const uint8_t key[16], 
	                    int forEncryption, int pkcs7Padding, const uint8_t iv[16])
{
    if (rot_sm4_is_key_exp_enabled(s)) {
        gm_sm4_key_schedule(key, s->ctx->rk);
        /* set key expansion ready state bit */
        s->regs->state_signals |= R_STATE_SIGNALS_KEY_EXP_READY_OUT_MASK;
    } else {
        // TODO: use default round key
    }
	s->ctx->state = s->ctx->cur_buf_len = s->ctx->total_len = 0;
	if(forEncryption) {
		s->ctx->state |= 0x01;
	}
	if(pkcs7Padding) {
		s->ctx->state |= 0x02;
	}
	if(iv != NULL) {
		memcpy(s->ctx->iv, iv, 16);
		s->ctx->state |= 0x04;
	}
}

static void gm_sm4_update_one_round(RoTSM4Context *ctx, uint8_t *output)
{
	int isCBC = (ctx->state & 0x04) > 0;
	int i;

	if(ctx->state & 0x01) {
    	if(isCBC) {
        	for(i = 0; i < 16; i++) {
        		ctx->buf[i] ^= ctx->iv[i];
        	}
        }
    	gm_sm4_one_round(ctx->rk, 1, ctx->buf, output);
    	if(isCBC) {
        	memcpy(ctx->iv, output, 16);
        }
    } else {
    	gm_sm4_one_round(ctx->rk, 0, ctx->buf, output);

    	if(isCBC) {
        	for(i = 0; i < 16; i++) {
        		output[i] ^= ctx->iv[i];
        		ctx->iv[i] = ctx->buf[i];
        	}
        }
    }
}

static uint32_t gm_sm4_update(RoTSM4Context *ctx, const uint8_t *input,
                              uint32_t iLen, uint8_t *output)
{
	uint32_t rLen = 0;

	do {
        if (ctx->cur_buf_len == 16) {
            gm_sm4_update_one_round(ctx, output + rLen);
            ctx->total_len += 16;
            ctx->cur_buf_len = 0;
            rLen += 16;
        }

		ctx->buf[ctx->cur_buf_len++] = *input++;
	} while(--iLen);
	return rLen;
}

static int gm_sm4_done(RoTSM4Context *ctx, uint8_t *output)
{
	int rLen = 0;

	int pad = 0;
	if((ctx->state & 0x01) && (ctx->state & 0x02) && (ctx->cur_buf_len != 16)) {
		pad = 16 - ctx->cur_buf_len;
		memset(ctx->buf + ctx->cur_buf_len, pad, pad);
		ctx->cur_buf_len += pad;
	}

	if(ctx->cur_buf_len != 16) {
		return -1;
	}
	gm_sm4_update_one_round(ctx, output);
	ctx->total_len += 16;
    ctx->cur_buf_len = 0;
	rLen = 16;

	if(ctx->state & 0x01) {
		if((ctx->state & 0x02)) {
			if(pad == 0) {
				memset(ctx->buf, 16, 16);
				ctx->cur_buf_len = 16;
				gm_sm4_update_one_round(ctx, output + rLen);
				ctx->total_len += 16;
	            ctx->cur_buf_len = 0;
				rLen += 16;
			}
		}
	}else {
		if((ctx->state & 0x02)) {
			if(output[15] > 16 || output[15] <= 0) {
				return -1;
			}
			rLen -= output[15];
		}
	}

	return rLen;
}
/* -------------------------------------------------------------------------- */
/* For SM4 algorithm: end */
/* -------------------------------------------------------------------------- */


static void rot_sm4_calculate(RoTSM4State *s)
{
    uint8_t key[ROT_SM4_REGS_KEY_LENGTH],
            in[ROT_SM4_REGS_DATA_LENGTH],
            out[ROT_SM4_REGS_RESULT_LENGTH];

    memcpy(key, s->regs->key, ROT_SM4_REGS_KEY_LENGTH);
    memcpy(in, s->regs->data_in, ROT_SM4_REGS_DATA_LENGTH);

    int enc_dec_mode = rot_sm4_is_enc_mode(s) ? 1 : 0;
    /* no pkcs7 padding, ECB mode */
    gm_sm4_init(s, key, enc_dec_mode, 0, NULL);
    
    int len = gm_sm4_update(s->ctx, in, ROT_SM4_REGS_DATA_LENGTH, out);

    len = gm_sm4_done(s->ctx, out + len);

    for (int i = 0; i < 4; i++) {
        uint32_t tmp;
        GM_GET_UINT32_BE(tmp, out, i * 4);
        s->regs->result_out[i] = tmp;
    }

    s->calculating = false;
    s->regs->state_signals |= R_STATE_SIGNALS_VALID_OUT_MASK;
}

static uint64_t rot_sm4_regs_read(void *opaque, hwaddr addr, unsigned size)
{
    RoTSM4State *s = ROT_SM4(opaque);
    (void)size;
    uint32_t val32 = 0;
    hwaddr reg = R32_OFF(addr);

    switch (reg) {
    // rw
    case R_CTRL_SIGNALS: 
        val32 = s->regs->ctrl_signals;

        break;
    // ro
    case R_STATE_SIGNALS:
        val32 = s->regs->state_signals;

        break;
    case R_KEY_0: // rw
    case R_KEY_1: // rw
    case R_KEY_2: // rw
    case R_KEY_3: // rw
        if (rot_sm4_is_key_valid(s)) {
            val32 = bswap32(s->regs->key[reg - R_KEY_0]);
        } else {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "%s: key is not valid (%s)\n",
                          __func__, REG_NAME(reg));
            val32 = 0;
        }

        break;
    case R_DATA_IN_0: // rw
    case R_DATA_IN_1: // rw
    case R_DATA_IN_2: // rw
    case R_DATA_IN_3: // rw
        if (rot_sm4_is_data_valid(s)) {
            val32 = bswap32(s->regs->data_in[reg - R_DATA_IN_0]);
        } else {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "%s: plain text is not valid (%s)\n",
                          __func__, REG_NAME(reg));
            val32 = 0;
        }

        break;
    case R_RESULT_OUT_0: // ro
    case R_RESULT_OUT_1: // ro
    case R_RESULT_OUT_2: // ro
    case R_RESULT_OUT_3: // ro
        if (rot_sm4_is_result_ready(s)) {
            val32 = s->regs->result_out[reg - R_RESULT_OUT_0];
        } else {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "%s: result is not ready (%s)\n",
                          __func__, REG_NAME(reg));
            val32 = 0;
        }

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

static void rot_sm4_regs_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    RoTSM4State *s = ROT_SM4(opaque);
    (void)size;
    uint32_t val32 = (uint32_t)val;
    hwaddr reg = R32_OFF(addr);

    switch (reg) {
    // rw
    case R_CTRL_SIGNALS:
        s->regs->ctrl_signals = (val32 & CTRL_SIGNALS_MASK);

        /* if sm4 is not enabled, clear ctrl signals and state signals */
        if (!rot_sm4_is_sm4_enabled(s)) {
            s->calculating = false;
            s->regs->ctrl_signals = 0;
            s->regs->state_signals = 0;
        }

        if (!s->calculating && rot_sm4_is_sm4_enabled(s)
            && rot_sm4_is_enc_dec_enabled(s) && rot_sm4_is_key_valid(s)
            && rot_sm4_is_data_valid(s)) {
            s->calculating = true;
            rot_sm4_calculate(s);
        }

        break;
    case R_KEY_0: // rw
    case R_KEY_1: // rw
    case R_KEY_2: // rw
    case R_KEY_3: // rw
        if (rot_sm4_is_sm4_enabled(s) && !s->calculating) {
            s->regs->key[(reg - R_KEY_0)] = bswap32(val32);
        } else {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "%s: SM4 is not enabled or in calculating (%s)\n",
                          __func__, REG_NAME(reg));
        }

        break;
    case R_DATA_IN_0: // rw
    case R_DATA_IN_1: // rw
    case R_DATA_IN_2: // rw
    case R_DATA_IN_3: // rw
        if (rot_sm4_is_sm4_enabled(s) && !s->calculating) {
            s->regs->data_in[(reg - R_DATA_IN_0)] = bswap32(val32);
        } else {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "%s: SM4 is not enabled or in calculating (%s)\n",
                          __func__, REG_NAME(reg));
        }

        break;
    case R_STATE_SIGNALS: // ro
    case R_RESULT_OUT_0:  // ro
    case R_RESULT_OUT_1:  // ro
    case R_RESULT_OUT_2:  // ro
    case R_RESULT_OUT_3:  // ro
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

static const MemoryRegionOps rot_sm4_ops = {
    .read  = &rot_sm4_regs_read,
    .write = &rot_sm4_regs_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static void rot_sm4_init(Object *obj)
{
    RoTSM4State *s = ROT_SM4(obj);

    s->regs = g_new0(RoTSM4Registers, 1u);
    s->ctx  = g_new0(RoTSM4Context, 1u);

    memory_region_init_io(&s->mmio, obj, &rot_sm4_ops, s,
                         TYPE_ROT_SM4, REGS_SIZE);
    sysbus_init_mmio(SYS_BUS_DEVICE(obj), &s->mmio);
}

static void rot_sm4_reset(DeviceState *dev)
{
    RoTSM4State *s = ROT_SM4(dev);
    
    memset(s->regs, 0, sizeof(*(s->regs)));
    memset(s->ctx, 0, sizeof(*(s->ctx)));

    s->calculating = false;
}

static void rot_sm4_realize(DeviceState *dev, Error **errp)
{
    (void)errp;

    RoTSM4State *s = ROT_SM4(dev);
    
    g_assert(s->rot_id);
}

static Property rot_sm4_properties[] = {
    DEFINE_PROP_STRING("rot-id", RoTSM4State, rot_id),
    DEFINE_PROP_END_OF_LIST(),
};

static void rot_sm4_class_init(ObjectClass *klass, void *data)
{
    (void)data;
    DeviceClass *dc = DEVICE_CLASS(klass);

    device_class_set_legacy_reset(dc, &rot_sm4_reset);
    dc->realize = &rot_sm4_realize;

    device_class_set_props(dc, rot_sm4_properties);
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo rot_sm4_info = {
    .name          = TYPE_ROT_SM4,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(RoTSM4State),
    .instance_init = &rot_sm4_init,
    .class_init    = &rot_sm4_class_init,
};

static void rot_sm4_register_types(void)
{
    type_register_static(&rot_sm4_info);
}

type_init(rot_sm4_register_types)
