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
#include "hw/qdev-properties.h"
#include "hw/qdev-core.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "hw/registerfields.h"

#include "hw/rot/ot_pcr.h"


/* clang-format off */
REG32(CTRL, 0x0u)
    FIELD(CTRL, SELECT, 0u, 5u)
    FIELD(CTRL, WR_EN, 5u, 1u)
    FIELD(CTRL, RD_EN, 6u, 1u)
REG32(PCR_WR_0, 0x4u)
REG32(PCR_WR_1, 0x8u)
REG32(PCR_WR_2, 0xcu)
REG32(PCR_WR_3, 0x10u)
REG32(PCR_WR_4, 0x14u)
REG32(PCR_WR_5, 0x18u)
REG32(PCR_WR_6, 0x1cu)
REG32(PCR_WR_7, 0x20u)
REG32(PCR_RD_0, 0x24u)
REG32(PCR_RD_1, 0x28u)
REG32(PCR_RD_2, 0x2cu)
REG32(PCR_RD_3, 0x30u)
REG32(PCR_RD_4, 0x34u)
REG32(PCR_RD_5, 0x38u)
REG32(PCR_RD_6, 0x3cu)
REG32(PCR_RD_7, 0x40u)
/* clang-format on */

#define CTRL_MASK \
    (R_CTRL_SELECT_MASK | R_CTRL_WR_EN_MASK | \
     R_CTRL_RD_EN_MASK)

#define R32_OFF(_r_) ((_r_) / sizeof(uint32_t))

#define R_LAST_REG (R_PCR_RD_7)
#define REGS_COUNT (R_LAST_REG + 1u)
#define REGS_SIZE  (REGS_COUNT * sizeof(uint32_t))
#define REG_NAME(_reg_) \
    ((((_reg_) <= REGS_COUNT) && REG_NAMES[_reg_]) ? REG_NAMES[_reg_] : "?")

#define REG_NAME_ENTRY(_reg_) [R_##_reg_] = stringify(_reg_)
static const char *REG_NAMES[REGS_COUNT] = {
    REG_NAME_ENTRY(CTRL),
    REG_NAME_ENTRY(PCR_WR_0),
    REG_NAME_ENTRY(PCR_WR_1),
    REG_NAME_ENTRY(PCR_WR_2),
    REG_NAME_ENTRY(PCR_WR_3),
    REG_NAME_ENTRY(PCR_WR_4),
    REG_NAME_ENTRY(PCR_WR_5),
    REG_NAME_ENTRY(PCR_WR_6),
    REG_NAME_ENTRY(PCR_WR_7),
    REG_NAME_ENTRY(PCR_RD_0),
    REG_NAME_ENTRY(PCR_RD_1),
    REG_NAME_ENTRY(PCR_RD_2),
    REG_NAME_ENTRY(PCR_RD_3),
    REG_NAME_ENTRY(PCR_RD_4),
    REG_NAME_ENTRY(PCR_RD_5),
    REG_NAME_ENTRY(PCR_RD_6),
    REG_NAME_ENTRY(PCR_RD_7),
};
#undef REG_NAME_ENTRY

/* Use SM3 algorithm to calculate the PCR value */
#define ROT_PCR_REGS_PCR_WR_LENGTH    32u
#define ROT_PCR_REGS_PCR_RD_LENGTH    32u
#define ROT_PCR_REGS_PCR_VALUE_LENGTH 32u

struct RoTPCRRegisters {
    uint32_t ctrl;
    uint32_t pcr_wr[ROT_PCR_REGS_PCR_WR_LENGTH / sizeof(uint32_t)];
    uint32_t pcr_rd[ROT_PCR_REGS_PCR_RD_LENGTH / sizeof(uint32_t)];
};
typedef struct RoTPCRRegisters RoTPCRRegisters;

struct RoTPCRContext {
    uint32_t pcr_1[ROT_PCR_REGS_PCR_VALUE_LENGTH / sizeof(uint32_t)];
    uint32_t pcr_2[ROT_PCR_REGS_PCR_VALUE_LENGTH / sizeof(uint32_t)];
    uint32_t pcr_3[ROT_PCR_REGS_PCR_VALUE_LENGTH / sizeof(uint32_t)];
    uint32_t pcr_4[ROT_PCR_REGS_PCR_VALUE_LENGTH / sizeof(uint32_t)];
    uint32_t pcr_5[ROT_PCR_REGS_PCR_VALUE_LENGTH / sizeof(uint32_t)];
    uint32_t pcr_6[ROT_PCR_REGS_PCR_VALUE_LENGTH / sizeof(uint32_t)];
    uint32_t pcr_7[ROT_PCR_REGS_PCR_VALUE_LENGTH / sizeof(uint32_t)];
    uint32_t pcr_8[ROT_PCR_REGS_PCR_VALUE_LENGTH / sizeof(uint32_t)];
    uint32_t pcr_9[ROT_PCR_REGS_PCR_VALUE_LENGTH / sizeof(uint32_t)];
    uint32_t pcr_10[ROT_PCR_REGS_PCR_VALUE_LENGTH / sizeof(uint32_t)];
    uint32_t pcr_11[ROT_PCR_REGS_PCR_VALUE_LENGTH / sizeof(uint32_t)];
    uint32_t pcr_12[ROT_PCR_REGS_PCR_VALUE_LENGTH / sizeof(uint32_t)];
    uint32_t pcr_13[ROT_PCR_REGS_PCR_VALUE_LENGTH / sizeof(uint32_t)];
    uint32_t pcr_14[ROT_PCR_REGS_PCR_VALUE_LENGTH / sizeof(uint32_t)];
    uint32_t pcr_15[ROT_PCR_REGS_PCR_VALUE_LENGTH / sizeof(uint32_t)];
    uint32_t pcr_16[ROT_PCR_REGS_PCR_VALUE_LENGTH / sizeof(uint32_t)];
    uint32_t pcr_17[ROT_PCR_REGS_PCR_VALUE_LENGTH / sizeof(uint32_t)];
    uint32_t pcr_18[ROT_PCR_REGS_PCR_VALUE_LENGTH / sizeof(uint32_t)];
    uint32_t pcr_19[ROT_PCR_REGS_PCR_VALUE_LENGTH / sizeof(uint32_t)];
    uint32_t pcr_20[ROT_PCR_REGS_PCR_VALUE_LENGTH / sizeof(uint32_t)];
    uint32_t pcr_21[ROT_PCR_REGS_PCR_VALUE_LENGTH / sizeof(uint32_t)];
    uint32_t pcr_22[ROT_PCR_REGS_PCR_VALUE_LENGTH / sizeof(uint32_t)];
    uint32_t pcr_23[ROT_PCR_REGS_PCR_VALUE_LENGTH / sizeof(uint32_t)];
    uint32_t pcr_24[ROT_PCR_REGS_PCR_VALUE_LENGTH / sizeof(uint32_t)];
};
typedef struct RoTPCRContext RoTPCRContext;

struct RoTPCRState {
    SysBusDevice parent_obj;

    MemoryRegion mmio;
    
    RoTPCRRegisters *regs;
    RoTPCRContext *ctx;

    char *rot_id;
};

static inline uint32_t rot_pcr_get_pcr_idx(uint32_t ctrl)
{
    return FIELD_EX32(ctrl, CTRL, SELECT);
}

static uint64_t rot_pcr_regs_read(void *opaque, hwaddr addr, unsigned size)
{
    RoTPCRState *s = ROT_PCR(opaque);
    (void)size;
    uint32_t val32 = 0;
    hwaddr reg = R32_OFF(addr);

    uint32_t pcr_idx;

    switch (reg) {
    // rw
    case R_CTRL:
        val32 = s->regs->ctrl;

        break;
    case R_PCR_RD_0: // ro
    case R_PCR_RD_1: // ro
    case R_PCR_RD_2: // ro
    case R_PCR_RD_3: // ro
    case R_PCR_RD_4: // ro
    case R_PCR_RD_5: // ro
    case R_PCR_RD_6: // ro
    case R_PCR_RD_7: // ro
        if (s->regs->ctrl & R_CTRL_RD_EN_MASK) {
            pcr_idx = rot_pcr_get_pcr_idx(s->regs->ctrl);
            if (pcr_idx > 24 || pcr_idx == 0) {
                qemu_log_mask(LOG_GUEST_ERROR, 
                              "%s: invalid PCR index %d\n",
                              __func__, pcr_idx);
                val32 = 0;
                break;
            }

            uint32_t *selected_pcr = NULL;
            switch (pcr_idx) {
                case 1:  selected_pcr = s->ctx->pcr_1;  break;
                case 2:  selected_pcr = s->ctx->pcr_2;  break;
                case 3:  selected_pcr = s->ctx->pcr_3;  break;
                case 4:  selected_pcr = s->ctx->pcr_4;  break;
                case 5:  selected_pcr = s->ctx->pcr_5;  break;
                case 6:  selected_pcr = s->ctx->pcr_6;  break;
                case 7:  selected_pcr = s->ctx->pcr_7;  break;
                case 8:  selected_pcr = s->ctx->pcr_8;  break;
                case 9:  selected_pcr = s->ctx->pcr_9;  break;
                case 10: selected_pcr = s->ctx->pcr_10; break;
                case 11: selected_pcr = s->ctx->pcr_11; break;
                case 12: selected_pcr = s->ctx->pcr_12; break;
                case 13: selected_pcr = s->ctx->pcr_13; break;
                case 14: selected_pcr = s->ctx->pcr_14; break;
                case 15: selected_pcr = s->ctx->pcr_15; break;
                case 16: selected_pcr = s->ctx->pcr_16; break;
                case 17: selected_pcr = s->ctx->pcr_17; break;
                case 18: selected_pcr = s->ctx->pcr_18; break;
                case 19: selected_pcr = s->ctx->pcr_19; break;
                case 20: selected_pcr = s->ctx->pcr_20; break;
                case 21: selected_pcr = s->ctx->pcr_21; break;
                case 22: selected_pcr = s->ctx->pcr_22; break;
                case 23: selected_pcr = s->ctx->pcr_23; break;
                case 24: selected_pcr = s->ctx->pcr_24; break;
                default: break;
            }

            s->regs->pcr_rd[reg - R_PCR_RD_0] = selected_pcr[reg - R_PCR_RD_0];
            val32 = s->regs->pcr_rd[reg - R_PCR_RD_0];
            /* clear the read enable bit and PCR select bit */
            if (reg == R_PCR_RD_7) {
                s->regs->ctrl &= ~R_CTRL_RD_EN_MASK;
                s->regs->ctrl &= ~R_CTRL_SELECT_MASK;
            }
        } else {
            qemu_log_mask(LOG_GUEST_ERROR, 
                          "%s: CTRL RD_EN not enabled, %s is R/O\n",
                          __func__, REG_NAME(reg));
            val32 = 0;
        }

        break;
    case R_PCR_WR_0: // wo
    case R_PCR_WR_1: // wo
    case R_PCR_WR_2: // wo
    case R_PCR_WR_3: // wo
    case R_PCR_WR_4: // wo
    case R_PCR_WR_5: // wo
    case R_PCR_WR_6: // wo
    case R_PCR_WR_7: // wo
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: W/O register 0x%02" HWADDR_PRIx " (%s)\n",
                      __func__, addr, REG_NAME(reg));
        val32 = 0;

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

static void rot_pcr_regs_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    RoTPCRState *s = ROT_PCR(opaque);
    (void)size;
    uint32_t val32 = (uint32_t)val;
    hwaddr reg = R32_OFF(addr);

    uint32_t pcr_idx;

    switch (reg) {
    // rw
    case R_CTRL:
        s->regs->ctrl = (val32 & CTRL_MASK);

        if (s->regs->ctrl == 0)
            break;

        pcr_idx = rot_pcr_get_pcr_idx(s->regs->ctrl);
        if (pcr_idx > 24 || pcr_idx == 0) {
            qemu_log_mask(LOG_GUEST_ERROR, 
                          "%s: invalid PCR index %d\n",
                          __func__, pcr_idx);
            /* clear the ctrl register */
            s->regs->ctrl &= ~(R_CTRL_SELECT_MASK | R_CTRL_WR_EN_MASK | \
                              R_CTRL_RD_EN_MASK);
        }

        break;
    case R_PCR_WR_0: // wo
    case R_PCR_WR_1: // wo
    case R_PCR_WR_2: // wo
    case R_PCR_WR_3: // wo
    case R_PCR_WR_4: // wo
    case R_PCR_WR_5: // wo
    case R_PCR_WR_6: // wo
    case R_PCR_WR_7: // wo
        if (s->regs->ctrl & R_CTRL_WR_EN_MASK) {
            pcr_idx = rot_pcr_get_pcr_idx(s->regs->ctrl);
            if (pcr_idx > 24 || pcr_idx == 0) {
                qemu_log_mask(LOG_GUEST_ERROR, 
                              "%s: invalid PCR index %d\n",
                              __func__, pcr_idx);
                break;
            }

            uint32_t *selected_pcr = NULL;
            switch (pcr_idx) {
                case 1:  selected_pcr = s->ctx->pcr_1;  break;
                case 2:  selected_pcr = s->ctx->pcr_2;  break;
                case 3:  selected_pcr = s->ctx->pcr_3;  break;
                case 4:  selected_pcr = s->ctx->pcr_4;  break;
                case 5:  selected_pcr = s->ctx->pcr_5;  break;
                case 6:  selected_pcr = s->ctx->pcr_6;  break;
                case 7:  selected_pcr = s->ctx->pcr_7;  break;
                case 8:  selected_pcr = s->ctx->pcr_8;  break;
                case 9:  selected_pcr = s->ctx->pcr_9;  break;
                case 10: selected_pcr = s->ctx->pcr_10; break;
                case 11: selected_pcr = s->ctx->pcr_11; break;
                case 12: selected_pcr = s->ctx->pcr_12; break;
                case 13: selected_pcr = s->ctx->pcr_13; break;
                case 14: selected_pcr = s->ctx->pcr_14; break;
                case 15: selected_pcr = s->ctx->pcr_15; break;
                case 16: selected_pcr = s->ctx->pcr_16; break;
                case 17: selected_pcr = s->ctx->pcr_17; break;
                case 18: selected_pcr = s->ctx->pcr_18; break;
                case 19: selected_pcr = s->ctx->pcr_19; break;
                case 20: selected_pcr = s->ctx->pcr_20; break;
                case 21: selected_pcr = s->ctx->pcr_21; break;
                case 22: selected_pcr = s->ctx->pcr_22; break;
                case 23: selected_pcr = s->ctx->pcr_23; break;
                case 24: selected_pcr = s->ctx->pcr_24; break;
                default: break;
            }

            s->regs->pcr_wr[reg - R_PCR_WR_0] = val32;
            selected_pcr[reg - R_PCR_WR_0] = s->regs->pcr_wr[reg - R_PCR_WR_0];
            /* clear the write enable bit and PCR select bit */ 
            if (reg == R_PCR_WR_7) {
                s->regs->ctrl &= ~R_CTRL_WR_EN_MASK;
                s->regs->ctrl &= ~R_CTRL_SELECT_MASK;
            }
        } else {
            qemu_log_mask(LOG_GUEST_ERROR, 
                          "%s: CTRL WR_EN not enabled, %s is R/O\n",
                          __func__, REG_NAME(reg));
        }

        break;
    case R_PCR_RD_0: // ro
    case R_PCR_RD_1: // ro
    case R_PCR_RD_2: // ro
    case R_PCR_RD_3: // ro
    case R_PCR_RD_4: // ro
    case R_PCR_RD_5: // ro
    case R_PCR_RD_6: // ro
    case R_PCR_RD_7: // ro
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

static const MemoryRegionOps rot_pcr_ops = {
    .read  = &rot_pcr_regs_read,
    .write = &rot_pcr_regs_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static void rot_pcr_init(Object *obj)
{
    RoTPCRState *s = ROT_PCR(obj);

    s->regs = g_new0(RoTPCRRegisters, 1u);
    s->ctx = g_new0(RoTPCRContext, 1u);

    memory_region_init_io(&s->mmio, obj, &rot_pcr_ops, s,
                         TYPE_ROT_PCR, ROT_PCR_MMIO_SIZE);
    sysbus_init_mmio(SYS_BUS_DEVICE(obj), &s->mmio);
}

static void rot_pcr_reset(DeviceState *dev)
{
    RoTPCRState *s = ROT_PCR(dev);
    
    memset(s->regs, 0, sizeof(*(s->regs)));
    memset(s->ctx, 0, sizeof(*(s->ctx)));
}

static void rot_pcr_realize(DeviceState *dev, Error **errp)
{
    (void)errp;

    RoTPCRState *s = ROT_PCR(dev);
    if (!s->rot_id) {
        s->rot_id =
            g_strdup(object_get_canonical_path_component(OBJECT(s)->parent));
    }
}

static Property rot_pcr_properties[] = {
    DEFINE_PROP_STRING("ot-id", RoTPCRState, rot_id),
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
