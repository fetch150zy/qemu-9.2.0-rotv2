/*
 * QEMU Root of Trust v2 SM3 device
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

#include "hw/rot/ot_sm3.h"


/* clang-format off */
REG32(CTRL_SIGNALS, 0x0u)
    FIELD(CTRL_SIGNALS, MSG_INPT_LST, 0u, 1u)
    FIELD(CTRL_SIGNALS, MSG_INPT_VLD_BYTE_0, 1u, 1u)
    FIELD(CTRL_SIGNALS, MSG_INPT_VLD_BYTE_1, 2u, 1u)
    FIELD(CTRL_SIGNALS, MSG_INPT_VLD_BYTE_2, 3u, 1u)
    FIELD(CTRL_SIGNALS, MSG_INPT_VLD_BYTE_3, 4u, 1u)
REG32(STATE_SIGNALS, 0x4u)
    FIELD(STATE_SIGNALS, CMPRSS_OTPT_VLD, 0u, 1u)
    FIELD(STATE_SIGNALS, MSG_INPT_RDY, 1u, 1u)
REG32(MESSAGE_IN, 0x8u)
REG32(RESULT_OUT_0, 0xcu)
REG32(RESULT_OUT_1, 0x10u)
REG32(RESULT_OUT_2, 0x14u)
REG32(RESULT_OUT_3, 0x18u)
REG32(RESULT_OUT_4, 0x1cu)
REG32(RESULT_OUT_5, 0x20u)
REG32(RESULT_OUT_6, 0x24u)
REG32(RESULT_OUT_7, 0x28u)
/* clang-format on */

#define CTRL_SIGNALS_MSG_INPT_VLD_MASK \
    (R_CTRL_SIGNALS_MSG_INPT_VLD_BYTE_0_MASK | R_CTRL_SIGNALS_MSG_INPT_VLD_BYTE_1_MASK | \
     R_CTRL_SIGNALS_MSG_INPT_VLD_BYTE_2_MASK | R_CTRL_SIGNALS_MSG_INPT_VLD_BYTE_3_MASK)

#define R32_OFF(_r_) ((_r_) / sizeof(uint32_t))

#define R_LAST_REG (R_RESULT_OUT_7)
#define REGS_COUNT (R_LAST_REG + 1u)
#define REGS_SIZE  (REGS_COUNT * sizeof(uint32_t))
#define REG_NAME(_reg_) \
    ((((_reg_) <= REGS_COUNT) && REG_NAMES[_reg_]) ? REG_NAMES[_reg_] : "?")

#define REG_NAME_ENTRY(_reg_) [R_##_reg_] = stringify(_reg_)
static const char *REG_NAMES[REGS_COUNT] = {
    REG_NAME_ENTRY(CTRL_SIGNALS),
    REG_NAME_ENTRY(STATE_SIGNALS),
    REG_NAME_ENTRY(MESSAGE_IN),
    REG_NAME_ENTRY(RESULT_OUT_0),
    REG_NAME_ENTRY(RESULT_OUT_1),
    REG_NAME_ENTRY(RESULT_OUT_2),
    REG_NAME_ENTRY(RESULT_OUT_3),
    REG_NAME_ENTRY(RESULT_OUT_4),
    REG_NAME_ENTRY(RESULT_OUT_5),
    REG_NAME_ENTRY(RESULT_OUT_6),
    REG_NAME_ENTRY(RESULT_OUT_7),
};
#undef REG_NAME_ENTRY

#define ROT_SM3_CTX_STATE_LENGTH       32u
#define ROT_SM3_CTX_BUF_LENGTH         64u
#define ROT_SM3_REGS_RESULT_OUT_LENGTH 32u
#define ROT_SM3_MESSAGE_LENGTH         256u

struct RoTSM3Registers {
    uint32_t ctrl_signals;
    uint32_t state_signals;
    uint32_t message_in;
    uint32_t result_out[ROT_SM3_REGS_RESULT_OUT_LENGTH / sizeof(uint32_t)];
};
typedef struct RoTSM3Registers RoTSM3Registers;

struct RoTSM3Context {
    uint32_t state[ROT_SM3_CTX_STATE_LENGTH / sizeof(uint32_t)];
    uint8_t  buf[ROT_SM3_CTX_BUF_LENGTH];
    uint64_t cur_buf_len;
    uint64_t compressed_len;
};
typedef struct RoTSM3Context RoTSM3Context;

struct RoTSM3State {
    SysBusDevice parent_obj;
    MemoryRegion mmio;
    
    RoTSM3Registers *regs;
    RoTSM3Context *ctx;

    bool calculating;
    uint8_t message[ROT_SM3_MESSAGE_LENGTH];
    uint8_t valid_bytes;
    uint8_t valid_bytes_count;

    char *rot_id;
};

static inline bool rot_sm3_is_last_message(RoTSM3State *s)
{
    return s->regs->ctrl_signals & R_CTRL_SIGNALS_MSG_INPT_LST_MASK;
}


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

static void gm_sm3_init(RoTSM3Context *ctx)
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

static void gm_sm3_update(RoTSM3Context *ctx, const uint8_t *input, uint32_t len)
{
    while (len--) {
		ctx->buf[ctx->cur_buf_len] = *input++;
		ctx->cur_buf_len++;
		if (ctx->cur_buf_len == ROT_SM3_CTX_BUF_LENGTH) {
			rot_sm3_compress(ctx);
			ctx->compressed_len += (ROT_SM3_CTX_BUF_LENGTH * 8);
			ctx->cur_buf_len = 0;
		}
	}
}

static const uint8_t gm_sm3_padding[ROT_SM3_CTX_BUF_LENGTH] = {
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static void gm_sm3_done(RoTSM3Context *ctx, uint8_t output[ROT_SM3_REGS_RESULT_OUT_LENGTH])
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

    gm_sm3_update(ctx, (uint8_t *) gm_sm3_padding, padn);
    gm_sm3_update(ctx, msglen, 8);

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


static uint64_t rot_sm3_regs_read(void *opaque, hwaddr addr, unsigned size)
{
    RoTSM3State *s = ROT_SM3(opaque);
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
    // rw
    case R_MESSAGE_IN:
        val32 = s->regs->message_in;

        break;
    case R_RESULT_OUT_0: // ro
	case R_RESULT_OUT_1: // ro 
	case R_RESULT_OUT_2: // ro
	case R_RESULT_OUT_3: // ro
	case R_RESULT_OUT_4: // ro
	case R_RESULT_OUT_5: // ro
	case R_RESULT_OUT_6: // ro
	case R_RESULT_OUT_7: // ro
        if (!(s->regs->state_signals & R_STATE_SIGNALS_CMPRSS_OTPT_VLD_MASK)) {
            qemu_log_mask(LOG_GUEST_ERROR,
                         "%s: result is not ready (%s)\n",
                         __func__, REG_NAME(reg));
            val32 = 0;
        } else {
            val32 = bswap32(s->regs->result_out[reg - R_RESULT_OUT_0]);
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

static void rot_sm3_regs_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    RoTSM3State *s = ROT_SM3(opaque);
    (void)size;
    uint32_t val32 = (uint32_t)val;
    hwaddr reg = R32_OFF(addr);

    switch (reg) {
    // rw
    case R_CTRL_SIGNALS:
        s->regs->ctrl_signals = (val32 & (R_CTRL_SIGNALS_MSG_INPT_LST_MASK |
                                CTRL_SIGNALS_MSG_INPT_VLD_MASK));

        s->valid_bytes += FIELD_EX32(val32, CTRL_SIGNALS, MSG_INPT_VLD_BYTE_0) +
                          FIELD_EX32(val32, CTRL_SIGNALS, MSG_INPT_VLD_BYTE_1) +
                          FIELD_EX32(val32, CTRL_SIGNALS, MSG_INPT_VLD_BYTE_2) +
                          FIELD_EX32(val32, CTRL_SIGNALS, MSG_INPT_VLD_BYTE_3);
        
        s->valid_bytes_count += FIELD_EX32(val32, CTRL_SIGNALS, MSG_INPT_VLD_BYTE_0) +
                                FIELD_EX32(val32, CTRL_SIGNALS, MSG_INPT_VLD_BYTE_1) +
                                FIELD_EX32(val32, CTRL_SIGNALS, MSG_INPT_VLD_BYTE_2) +
                                FIELD_EX32(val32, CTRL_SIGNALS, MSG_INPT_VLD_BYTE_3);

        break;
    // rw
    case R_MESSAGE_IN:
        s->regs->message_in = val32;

        uint8_t msg_bytes[4];
        for (int i = 0; i < s->valid_bytes; i++) {
            msg_bytes[i] = (val32 >> ((s->valid_bytes - 1) * 8 - i * 8)) & 0xFF;
        }
        memcpy(s->message + s->valid_bytes_count - s->valid_bytes, msg_bytes, s->valid_bytes);

        if (!s->calculating) {
            gm_sm3_init(s->ctx);
            s->calculating = true;
        }
        
        if (rot_sm3_is_last_message(s) && s->calculating) {
            gm_sm3_update(s->ctx, s->message, s->valid_bytes_count);
            uint8_t output[ROT_SM3_REGS_RESULT_OUT_LENGTH];
            gm_sm3_done(s->ctx, output);

            memcpy(s->regs->result_out, output, ROT_SM3_REGS_RESULT_OUT_LENGTH);

            s->regs->state_signals |= R_STATE_SIGNALS_CMPRSS_OTPT_VLD_MASK;
            s->regs->ctrl_signals &= ~R_CTRL_SIGNALS_MSG_INPT_LST_MASK;
            s->calculating = false;
            s->valid_bytes_count = 0;
            /* after calculating, clear the message */
            memset(s->message, 0, sizeof(s->message));
        }
        s->valid_bytes = 0;

        break;
    case R_STATE_SIGNALS: // ro
	case R_RESULT_OUT_0:  // ro
	case R_RESULT_OUT_1:  // ro
	case R_RESULT_OUT_2:  // ro
	case R_RESULT_OUT_3:  // ro
	case R_RESULT_OUT_4:  // ro
	case R_RESULT_OUT_5:  // ro
	case R_RESULT_OUT_6:  // ro
	case R_RESULT_OUT_7:  // ro
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

static const MemoryRegionOps rot_sm3_ops = {
    .read  = &rot_sm3_regs_read,
    .write = &rot_sm3_regs_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static void rot_sm3_init(Object *obj)
{
    RoTSM3State *s = ROT_SM3(obj);

    s->regs = g_new0(RoTSM3Registers, 1u);
    s->ctx = g_new0(RoTSM3Context, 1u);

    memory_region_init_io(&s->mmio, obj, &rot_sm3_ops, s,
                         TYPE_ROT_SM3, ROT_SM3_MMIO_SIZE);
    sysbus_init_mmio(SYS_BUS_DEVICE(obj), &s->mmio);
}

static void rot_sm3_reset(DeviceState *dev)
{
    RoTSM3State *s = ROT_SM3(dev);
    
    memset(s->regs, 0, sizeof(*(s->regs)));
    memset(s->ctx, 0, sizeof(*(s->ctx)));

    s->calculating = false;
    s->valid_bytes = 0;
    s->valid_bytes_count = 0;
    memset(s->message, 0, sizeof(s->message));
}

static void rot_sm3_realize(DeviceState *dev, Error **errp)
{
    (void)errp;

    RoTSM3State *s = ROT_SM3(dev);
    if (!s->rot_id) {
        s->rot_id =
            g_strdup(object_get_canonical_path_component(OBJECT(s)->parent));
    }
}

static Property rot_sm3_properties[] = {
    DEFINE_PROP_STRING("ot-id", RoTSM3State, rot_id),
    DEFINE_PROP_END_OF_LIST(),
};

static void rot_sm3_class_init(ObjectClass *klass, void *data)
{
    (void)data;
    DeviceClass *dc = DEVICE_CLASS(klass);

    device_class_set_legacy_reset(dc, &rot_sm3_reset);
    dc->realize = &rot_sm3_realize;

    device_class_set_props(dc, rot_sm3_properties);
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo rot_sm3_info = {
    .name          = TYPE_ROT_SM3,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(RoTSM3State),
    .instance_init = &rot_sm3_init,
    .class_init    = &rot_sm3_class_init,
};

static void rot_sm3_register_types(void)
{
    type_register_static(&rot_sm3_info);
}

type_init(rot_sm3_register_types)
