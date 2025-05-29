/*
 * QEMU Root of Trust v2 Key Manager device
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
#include "qemu/bswap.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "hw/qdev-core.h"
#include "hw/qdev-properties.h"
#include "hw/registerfields.h"
#include "hw/sysbus.h"

// #include "hw/riscv/rotv2_irq.h"

#include "hw/rotv2/rot_kmac.h"
#include "hw/rotv2/rot_keymgr.h"
#include "hw/rotv2/common.h"


/* clang-format off */
REG32(INTR_STATE, 0x0u)
    SHARED_FIELD(INTR_OP_DONE, 0u, 1u)
REG32(INTR_ENABLE, 0x4u)
REG32(INTR_TEST, 0x8u)
REG32(ALERT_TEST, 0xcu)
    FIELD(ALERT_TEST, RECOV_OPERATION_ERR, 0u, 1u)
    FIELD(ALERT_TEST, FATAL_FAULT_ERR, 1u, 1u)
REG32(CFG_REGWEN, 0x10u)
    FIELD(CFG_REGWEN, EN, 0u, 1u)
REG32(START, 0x14u)
    FIELD(START, EN, 0u, 1u)
REG32(CONTROL_SHADOWED, 0x18u)
    FIELD(CONTROL_SHADOWED, OPERATION, 4u, 3u)
    FIELD(CONTROL_SHADOWED, CDI_SEL, 7u, 1u)
    FIELD(CONTROL_SHADOWED, DEST_SEL, 12u, 2u)
REG32(SIDELOAD_CLEAR, 0x1cu)
    FIELD(SIDELOAD_CLEAR, VAL, 0u, 3u)
REG32(RESEED_INTERVAL_REGWEN, 0x20u)
    FIELD(RESEED_INTERVAL_REGWEN, EN, 0u, 1u)
REG32(RESEED_INTERVAL_SHADOWED, 0x24u)
    FIELD(RESEED_INTERVAL_SHADOWED, VAL, 0u, 16u)
REG32(SW_BINDING_REGWEN, 0x28u)
    FIELD(SW_BINDING_REGWEN, EN, 0u, 1u)
REG32(SEALING_SW_BINDING_0, 0x2cu)
REG32(SEALING_SW_BINDING_1, 0x30u)
REG32(SEALING_SW_BINDING_2, 0x34u)
REG32(SEALING_SW_BINDING_3, 0x38u)
REG32(SEALING_SW_BINDING_4, 0x3cu)
REG32(SEALING_SW_BINDING_5, 0x40u)
REG32(SEALING_SW_BINDING_6, 0x44u)
REG32(SEALING_SW_BINDING_7, 0x48u) 
REG32(ATTEST_SW_BINDING_0, 0x4cu)
REG32(ATTEST_SW_BINDING_1, 0x50u)
REG32(ATTEST_SW_BINDING_2, 0x54u)
REG32(ATTEST_SW_BINDING_3, 0x58u)
REG32(ATTEST_SW_BINDING_4, 0x5cu)
REG32(ATTEST_SW_BINDING_5, 0x60u)
REG32(ATTEST_SW_BINDING_6, 0x64u)
REG32(ATTEST_SW_BINDING_7, 0x68u)
REG32(SALT_0, 0x6cu)
REG32(SALT_1, 0x70u)
REG32(SALT_2, 0x74u)
REG32(SALT_3, 0x78u)
REG32(SALT_4, 0x7cu)
REG32(SALT_5, 0x80u)
REG32(SALT_6, 0x84u)
REG32(SALT_7, 0x88u)
REG32(KEY_VERSION, 0x8cu)
REG32(MAX_CREATOR_KEY_VER_REGWEN, 0x90u)
    FIELD(MAX_CREATOR_KEY_VER_REGWEN, EN, 0u, 1u)
REG32(MAX_CREATOR_KEY_VER_SHADOWED, 0x94u)
REG32(MAX_OWNER_INT_KEY_VER_REGWEN, 0x98u)
    FIELD(MAX_OWNER_INT_KEY_VER_REGWEN, EN, 0u, 1u)
REG32(MAX_OWNER_INT_KEY_VER_SHADOWED, 0x9cu)
REG32(MAX_OWNER_KEY_VER_REGWEN, 0xa0u)
    FIELD(MAX_OWNER_KEY_VER_REGWEN, EN, 0u, 1u)
REG32(MAX_OWNER_KEY_VER_SHADOWED, 0xa4u)
REG32(SW_SHARE0_OUTPUT_0, 0xa8u)
REG32(SW_SHARE0_OUTPUT_1, 0xacu)
REG32(SW_SHARE0_OUTPUT_2, 0xb0u)
REG32(SW_SHARE0_OUTPUT_3, 0xb4u)
REG32(SW_SHARE0_OUTPUT_4, 0xb8u)
REG32(SW_SHARE0_OUTPUT_5, 0xbcu)
REG32(SW_SHARE0_OUTPUT_6, 0xc0u)
REG32(SW_SHARE0_OUTPUT_7, 0xc4u)
REG32(SW_SHARE1_OUTPUT_0, 0xc8u)
REG32(SW_SHARE1_OUTPUT_1, 0xccu)
REG32(SW_SHARE1_OUTPUT_2, 0xd0u)
REG32(SW_SHARE1_OUTPUT_3, 0xd4u)
REG32(SW_SHARE1_OUTPUT_4, 0xd8u)
REG32(SW_SHARE1_OUTPUT_5, 0xdcu)
REG32(SW_SHARE1_OUTPUT_6, 0xe0u)
REG32(SW_SHARE1_OUTPUT_7, 0xe4u)
REG32(WORKING_STATE, 0xe8u)
    FIELD(WORKING_STATE, STATE, 0u, 3u)
REG32(OP_STATUS, 0xecu)
    FIELD(OP_STATUS, STATUS, 0u, 2u)
REG32(ERR_CODE, 0xf0u)
    FIELD(ERR_CODE, INVALID_OP, 0u, 1u)
    FIELD(ERR_CODE, INVALID_KMAC_INPUT, 1u, 1u)
    FIELD(ERR_CODE, INVALID_SHADOW_UPDATE, 2u, 1u)
REG32(FAULT_STATUS, 0xf4u)
    FIELD(FAULT_STATUS, CMD, 0u, 1u)
    FIELD(FAULT_STATUS, KMAC_FSM, 1u, 1u)
    FIELD(FAULT_STATUS, KMAC_DONE, 2u, 1u)
    FIELD(FAULT_STATUS, KMAC_OP, 3u, 1u)
    FIELD(FAULT_STATUS, KMAC_OUT, 4u, 1u)
    FIELD(FAULT_STATUS, REGFILE_INTG, 5u, 1u)
    FIELD(FAULT_STATUS, SHADOW, 6u, 1u)
    FIELD(FAULT_STATUS, CTRL_FSM_INTG, 7u, 1u)
    FIELD(FAULT_STATUS, CTRL_FSM_CHK, 8u, 1u)
    FIELD(FAULT_STATUS, CTRL_FSM_CNT, 9u, 1u)
    FIELD(FAULT_STATUS, RESEED_CNT, 10u, 1u)
    FIELD(FAULT_STATUS, SIDE_CTRL_FSM, 11u, 1u)
    FIELD(FAULT_STATUS, SIDE_CTRL_SEL, 12u, 1u)
    FIELD(FAULT_STATUS, KEY_ECC, 13u, 1u)
REG32(DEBUG, 0xf8u)
    FIELD(DEBUG, INVALID_CREATOR_SEED, 0u, 1u)
    FIELD(DEBUG, INVALID_OWNER_SEED, 1u, 1u)
    FIELD(DEBUG, INVALID_DEV_ID, 2u, 1u)
    FIELD(DEBUG, INVALID_HEALTH_STATE, 3u, 1u)
    FIELD(DEBUG, INVALID_KEY_VERSION, 4u, 1u)
    FIELD(DEBUG, INVALID_KEY, 5u, 1u)
    FIELD(DEBUG, INVALID_DIGEST, 6u, 1u)
/* clang-format on */

#define ALERT_TEST_MASK \
    (R_ALERT_TEST_RECOV_OPERATION_ERR_MASK | R_ALERT_TEST_FATAL_FAULT_ERR_MASK)
#define CONTROL_SHADOWED_MASK \
    (R_CONTROL_SHADOWED_OPERATION_MASK | R_CONTROL_SHADOWED_CDI_SEL_MASK | \
     R_CONTROL_SHADOWED_DEST_SEL_MASK)
#define ERR_CODE_MASK \
    (R_ERR_CODE_INVALID_OP_MASK | R_ERR_CODE_INVALID_KMAC_INPUT_MASK | \
     R_ERR_CODE_INVALID_SHADOW_UPDATE_MASK)
#define FAULT_STATUS_MASK \
    (R_FAULT_STATUS_CMD_MASK | R_FAULT_STATUS_KMAC_FSM_MASK | \
     R_FAULT_STATUS_KMAC_DONE_MASK | R_FAULT_STATUS_KMAC_OP_MASK | \
     R_FAULT_STATUS_KMAC_OUT_MASK | R_FAULT_STATUS_REGFILE_INTG_MASK | \
     R_FAULT_STATUS_SHADOW_MASK | R_FAULT_STATUS_CTRL_FSM_INTG_MASK | \
     R_FAULT_STATUS_CTRL_FSM_CHK_MASK | R_FAULT_STATUS_CTRL_FSM_CNT_MASK | \
     R_FAULT_STATUS_RESEED_CNT_MASK | R_FAULT_STATUS_SIDE_CTRL_FSM_MASK | \
     R_FAULT_STATUS_SIDE_CTRL_SEL_MASK | R_FAULT_STATUS_KEY_ECC_MASK)
#define DEBUG_MASK \
    (R_DEBUG_INVALID_CREATOR_SEED_MASK | R_DEBUG_INVALID_OWNER_SEED_MASK | \
     R_DEBUG_INVALID_DEV_ID_MASK | R_DEBUG_INVALID_HEALTH_STATE_MASK | \
     R_DEBUG_INVALID_KEY_VERSION_MASK | R_DEBUG_INVALID_KEY_MASK | \
     R_DEBUG_INVALID_DIGEST_MASK)

#define R32_OFF(_r_) ((_r_) / sizeof(uint32_t))

#define R_LAST_REG (R_DEBUG)
#define REGS_COUNT (R_LAST_REG + 1u)
#define REGS_SIZE  (REGS_COUNT * sizeof(uint32_t))
#define REG_NAME(_reg_) \
    ((((_reg_) <= REGS_COUNT) && REG_NAMES[_reg_]) ? REG_NAMES[_reg_] : "?")

#define REG_NAME_ENTRY(_reg_) [R_##_reg_] = stringify(_reg_)
static const char *REG_NAMES[REGS_COUNT] = {
    REG_NAME_ENTRY(INTR_STATE),
    REG_NAME_ENTRY(INTR_ENABLE),
    REG_NAME_ENTRY(INTR_TEST),
    REG_NAME_ENTRY(ALERT_TEST),
    REG_NAME_ENTRY(CFG_REGWEN),
    REG_NAME_ENTRY(START),
    REG_NAME_ENTRY(CONTROL_SHADOWED),
    REG_NAME_ENTRY(SIDELOAD_CLEAR),
    REG_NAME_ENTRY(RESEED_INTERVAL_REGWEN),
    REG_NAME_ENTRY(RESEED_INTERVAL_SHADOWED),
    REG_NAME_ENTRY(SW_BINDING_REGWEN),
    REG_NAME_ENTRY(SEALING_SW_BINDING_0),
    REG_NAME_ENTRY(SEALING_SW_BINDING_1),
    REG_NAME_ENTRY(SEALING_SW_BINDING_2),
    REG_NAME_ENTRY(SEALING_SW_BINDING_3),
    REG_NAME_ENTRY(SEALING_SW_BINDING_4),
    REG_NAME_ENTRY(SEALING_SW_BINDING_5),
    REG_NAME_ENTRY(SEALING_SW_BINDING_6),
    REG_NAME_ENTRY(SEALING_SW_BINDING_7),
    REG_NAME_ENTRY(ATTEST_SW_BINDING_0),
    REG_NAME_ENTRY(ATTEST_SW_BINDING_1),
    REG_NAME_ENTRY(ATTEST_SW_BINDING_2),
    REG_NAME_ENTRY(ATTEST_SW_BINDING_3),
    REG_NAME_ENTRY(ATTEST_SW_BINDING_4),
    REG_NAME_ENTRY(ATTEST_SW_BINDING_5),
    REG_NAME_ENTRY(ATTEST_SW_BINDING_6),
    REG_NAME_ENTRY(ATTEST_SW_BINDING_7),
    REG_NAME_ENTRY(SALT_0),
    REG_NAME_ENTRY(SALT_1),
    REG_NAME_ENTRY(SALT_2),
    REG_NAME_ENTRY(SALT_3),
    REG_NAME_ENTRY(SALT_4),
    REG_NAME_ENTRY(SALT_5),
    REG_NAME_ENTRY(SALT_6),
    REG_NAME_ENTRY(SALT_7),
    REG_NAME_ENTRY(KEY_VERSION),
    REG_NAME_ENTRY(MAX_CREATOR_KEY_VER_REGWEN),
    REG_NAME_ENTRY(MAX_CREATOR_KEY_VER_SHADOWED),
    REG_NAME_ENTRY(MAX_OWNER_INT_KEY_VER_REGWEN),
    REG_NAME_ENTRY(MAX_OWNER_INT_KEY_VER_SHADOWED),
    REG_NAME_ENTRY(MAX_OWNER_KEY_VER_REGWEN),
    REG_NAME_ENTRY(MAX_OWNER_KEY_VER_SHADOWED),
    REG_NAME_ENTRY(SW_SHARE0_OUTPUT_0),
    REG_NAME_ENTRY(SW_SHARE0_OUTPUT_1),
    REG_NAME_ENTRY(SW_SHARE0_OUTPUT_2),
    REG_NAME_ENTRY(SW_SHARE0_OUTPUT_3),
    REG_NAME_ENTRY(SW_SHARE0_OUTPUT_4),
    REG_NAME_ENTRY(SW_SHARE0_OUTPUT_5),
    REG_NAME_ENTRY(SW_SHARE0_OUTPUT_6),
    REG_NAME_ENTRY(SW_SHARE0_OUTPUT_7),
    REG_NAME_ENTRY(SW_SHARE1_OUTPUT_0),
    REG_NAME_ENTRY(SW_SHARE1_OUTPUT_1),
    REG_NAME_ENTRY(SW_SHARE1_OUTPUT_2),
    REG_NAME_ENTRY(SW_SHARE1_OUTPUT_3),
    REG_NAME_ENTRY(SW_SHARE1_OUTPUT_4),
    REG_NAME_ENTRY(SW_SHARE1_OUTPUT_5),
    REG_NAME_ENTRY(SW_SHARE1_OUTPUT_6),
    REG_NAME_ENTRY(SW_SHARE1_OUTPUT_7),
    REG_NAME_ENTRY(WORKING_STATE),
    REG_NAME_ENTRY(OP_STATUS),
    REG_NAME_ENTRY(ERR_CODE),
    REG_NAME_ENTRY(FAULT_STATUS),
    REG_NAME_ENTRY(DEBUG),
};
#undef REG_NAME_ENTRY

typedef enum {
    KEYMGR_ST_RESET,
    KEYMGR_ST_INITIALIZED,
    KEYMGR_ST_CREATOR_ROOT_KEY,
    KEYMGR_ST_OWNER_INTERMEDIATE_KEY,
    KEYMGR_ST_OWNER_KEY,
    KEYMGR_ST_DISABLED,
    KEYMGR_ST_INVALID,
} RoTKeyMgrFsmState;

#define STATE_NAME_ENTRY(_st_) [_st_] = stringify(_st_)
static const char *STATE_NAMES[] = {
    STATE_NAME_ENTRY(KEYMGR_RESET),
    STATE_NAME_ENTRY(KEYMGR_INITIALIZED),
    STATE_NAME_ENTRY(KEYMGR_CREATOR_ROOT_KEY),
    STATE_NAME_ENTRY(KEYMGR_OWNER_INTERMEDIATE_KEY),
    STATE_NAME_ENTRY(KEYMGR_OWNER_ROOT_KEY),
    STATE_NAME_ENTRY(KEYMGR_DISABLED),
    STATE_NAME_ENTRY(KEYMGR_INVALID),
};
#undef STATE_NAME_ENTRY
#define STATE_NAME(_st_) \
    ((_st_) >= 0 && (_st_) < ARRAY_SIZE(STATE_NAMES) ? STATE_NAMES[(_st_)] : \
                                                       "?")

#define ROT_KEYMGR_SEALING_SW_BINDING_LENGTH 32u
#define ROT_KEYMGR_ATTEST_SW_BINDING_LENGTH  32u
#define ROT_KEYMGR_SALT_LENGTH               32u
#define ROT_KEYMGR_SW_SHARE0_OUTPUT_LENGTH   32u
#define ROT_KEYMGR_SW_SHARE1_OUTPUT_LENGTH   32u

enum {
    KEYMGR_CONTROL_OP_ADVANCE        = 0x0,
    KEYMGR_CONTROL_OP_GENERATE_ID    = 0x1,
    KEYMGR_CONTROL_OP_GENERATE_SW    = 0x2,
    KEYMGR_CONTROL_OP_GENERATE_HW    = 0x3,
    KEYMGR_CONTROL_OP_DISABLE        = 0x4,
};

enum {
    KEYMGR_CONTROL_CDI_SEL_SEALING     = 0x0,
    KEYMGR_CONTROL_CDI_SEL_ATTESTATION = 0x1,
};

enum {
    KEYMGR_CONTROL_DEST_SEL_NONE = 0x0,
    KEYMGR_CONTROL_DEST_SEL_AES  = 0x1,
    KEYMGR_CONTROL_DEST_SEL_KMAC = 0x2,
    KEYMGR_CONTROL_DEST_SEL_OTBN = 0x3,
};

enum {
    KEYMGR_SIDELOAD_CLEAR_NONE = 0x0,
    KEYMGR_SIDELOAD_CLEAR_AES  = 0x1,
    KEYMGR_SIDELOAD_CLEAR_KMAC = 0x2,
    KEYMGR_SIDELOAD_CLEAR_OTBN = 0x3,
};

enum {
    KEYMGR_OP_STATUS_IDLE         = 0x0,
    KEYMGR_OP_STATUS_WIP          = 0x1,
    KEYMGR_OP_STATUS_DONE_SUCCESS = 0x2,
    KEYMGR_OP_STATUS_DONE_ERROR   = 0x3,
};

struct RoTKeyMgrRegisters {
    uint32_t intr_state;
    uint32_t intr_enable;
    uint32_t intr_test;
    uint32_t alert_test;
    uint32_t cfg_regwen;
    uint32_t start;
    uint32_t control_shadowed;
    uint32_t sideload_clear;
    uint32_t reseed_interval_regwen;
    uint32_t reseed_interval_shadowed;
    uint32_t sw_binding_regwen;
    uint32_t sealing_sw_binding[ROT_KEYMGR_SEALING_SW_BINDING_LENGTH / sizeof(uint32_t)];
    uint32_t attest_sw_binding[ROT_KEYMGR_ATTEST_SW_BINDING_LENGTH / sizeof(uint32_t)];
    uint32_t salt[ROT_KEYMGR_SALT_LENGTH / sizeof(uint32_t)];
    uint32_t key_version;
    uint32_t max_creator_key_ver_regwen;
    uint32_t max_creator_key_ver_shadowed;
    uint32_t max_owner_int_key_ver_regwen;
    uint32_t max_owner_int_key_ver_shadowed;
    uint32_t max_owner_key_ver_regwen;
    uint32_t max_owner_key_ver_shadowed;
    uint32_t sw_share0_output[ROT_KEYMGR_SW_SHARE0_OUTPUT_LENGTH / sizeof(uint32_t)];
    uint32_t sw_share1_output[ROT_KEYMGR_SW_SHARE1_OUTPUT_LENGTH / sizeof(uint32_t)];
    uint32_t working_state;
    uint32_t op_status;
    uint32_t err_code;
    uint32_t fault_status;
    uint32_t debug;
};
typedef struct RoTKeyMgrRegisters RoTKeyMgrRegisters;

struct RoTKeyMgrState {
    SysBusDevice parent_obj;
    
    MemoryRegion mmio;
    
    RoTKeyMgrRegisters *regs;
    RoTShadowReg control;
    RoTShadowReg reseed_interval;
    RoTShadowReg max_creator_key_ver;
    RoTShadowReg max_owner_int_key_ver;
    RoTShadowReg max_owner_key_ver;

    RoTKeyMgrFsmState state;

    RoTKMACState *kmac;
    uint32_t size;

    char *rot_id;
};

// static void rot_keymgr_update_irqs(RoTKeyMgrState *s)
// {
//     uint32_t levels = s->regs->intr_state & s->regs->intr_enable;
//     for (unsigned ix = 0; ix < PARAM_NUM_IRQS; ix++) {
//         rot_irq_set(&s->irqs[ix], (int)((levels >> ix) & 0x1u));
//     }
// }

// TODO: need check if the state transition is valid
static void rot_keymgr_change_state_line(RoTKeyMgrState *s, 
                                         RoTKeyMgrFsmState state, int line)
{
    RoTKeyMgrFsmState old_state = s->state;
    bool valid_transition = false;
    
    switch (old_state) {
    case KEYMGR_ST_RESET:
        valid_transition = (state == KEYMGR_ST_INITIALIZED ||
                           state == KEYMGR_ST_DISABLED || 
                           state == KEYMGR_ST_INVALID);
        break;
    case KEYMGR_ST_INITIALIZED:
        valid_transition = (state == KEYMGR_ST_CREATOR_ROOT_KEY ||
                           state == KEYMGR_ST_DISABLED || 
                           state == KEYMGR_ST_INVALID);
        break;
    case KEYMGR_ST_CREATOR_ROOT_KEY:
        valid_transition = (state == KEYMGR_ST_OWNER_INTERMEDIATE_KEY ||
                           state == KEYMGR_ST_DISABLED || 
                           state == KEYMGR_ST_INVALID);
        break;
    case KEYMGR_ST_OWNER_INTERMEDIATE_KEY:
        valid_transition = (state == KEYMGR_ST_OWNER_ROOT_KEY ||
                           state == KEYMGR_ST_DISABLED || 
                           state == KEYMGR_ST_INVALID);
        break;
    case KEYMGR_ST_OWNER_KEY:
        valid_transition = (state == KEYMGR_ST_DISABLED || 
                           state == KEYMGR_ST_INVALID);
        break;
    case KEYMGR_ST_DISABLED:
        valid_transition = false;
        break;
    case KEYMGR_ST_INVALID:
        valid_transition = false;
        break;
    default:
        valid_transition = false;
        break;
    }
    
    if (!valid_transition && state != old_state) {
        qemu_log_mask(LOG_GUEST_ERROR,
                     "%s: Invalid state transition from %s to %s (line %d)\n",
                     __func__, STATE_NAME(old_state), STATE_NAME(state), line);
        s->state = KEYMGR_ST_INVALID;
        s->regs->working_state = KEYMGR_ST_INVALID;
        return;
    }
    
    s->state = state;
    s->regs->working_state = state;
}

#define rot_keymgr_change_state(_s_, _st_) \
    rot_keymgr_change_state_line(_s_, _st_, __LINE__)

// TODO: need implement sideload key clear
static void rot_keymgr_sideload_key_slots_clear(uint32_t sideload_clear)
{
    switch (sideload_clear) {
    case KEYMGR_SIDELOAD_CLEAR_NONE:
        /* do nothing */
        break;
    case KEYMGR_SIDELOAD_CLEAR_AES:
        /* clear aes */
        qemu_log_mask(LOG_UNIMP,
                      "%s: Clearing AES sideload key not implemented\n",
                      __func__);
        break;
    case KEYMGR_SIDELOAD_CLEAR_KMAC:
        /* clear kmac */
        qemu_log_mask(LOG_UNIMP,
                      "%s: Clearing KMAC sideload key not implemented\n",
                      __func__);
        break;
    case KEYMGR_SIDELOAD_CLEAR_OTBN:
        /* clear otbn */
        qemu_log_mask(LOG_UNIMP,
                      "%s: Clearing OTBN sideload key not implemented\n",
                      __func__);
        break;
    default:
        /* clear all */
        qemu_log_mask(LOG_UNIMP,
                      "%s: Clearing ALL sideload keys not implemented\n",
                      __func__);
        break;
    }
}

static inline bool rot_keymgr_config_enabled(RoTKeyMgrState *s)
{
    // TODO: when keymgr operation is started, can't config (or KEYMGR_RESTART state?)
    return s->regs->op_status == KEYMGR_OP_STATUS_IDLE;
}

static inline bool rot_keymgr_check_reg_write(RoTKeyMgrState *s, hwaddr reg)
{
    if (!rot_keymgr_config_enabled(s)) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: Write to %s ignored while busy\n",
                      __func__, REG_NAME(reg));
        return false;
    }

    return true;
}

static void rot_keymgr_handle_advance(RoTKeyMgrState *s)
{
    RoTKeyMgrFsmState next_state;
    
    switch (s->state) {
    case KEYMGR_RESET:
        next_state = KEYMGR_INITIALIZED;
        break;
    case KEYMGR_INITIALIZED:
        next_state = KEYMGR_CREATOR_ROOT_KEY;
        break;
    case KEYMGR_CREATOR_ROOT_KEY:
        next_state = KEYMGR_OWNER_INTERMEDIATE_KEY;
        break;
    case KEYMGR_OWNER_INTERMEDIATE_KEY:
        next_state = KEYMGR_OWNER_ROOT_KEY;
        break;
    case KEYMGR_OWNER_ROOT_KEY:
        next_state = KEYMGR_DISABLED;
        break;
    case KEYMGR_DISABLED:
    case KEYMGR_INVALID:
    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                     "%s: Cannot advance from terminal state %s\n",
                     __func__, STATE_NAME(s->state));
        s->regs->err_code |= R_ERR_CODE_INVALID_OP_MASK;
        s->regs->op_status = KEYMGR_OP_STATUS_DONE_ERROR;
        return;
    }
    
    rot_keymgr_change_state(s, next_state);
    
    s->regs->sw_binding_regwen = 0x1u;
    
    s->regs->op_status = KEYMGR_OP_STATUS_DONE_SUCCESS;
}

static void rot_keymgr_handle_generate_id(RoTKeyMgrState *s)
{
    switch (s->state) {
    case KEYMGR_CREATOR_ROOT_KEY:
    case KEYMGR_OWNER_INTERMEDIATE_KEY:
    case KEYMGR_OWNER_ROOT_KEY:
        break;
    case KEYMGR_RESET:
    case KEYMGR_INITIALIZED:
    case KEYMGR_DISABLED:
    case KEYMGR_INVALID:
    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                     "%s: Cannot generate ID in state %s\n",
                     __func__, STATE_NAME(s->state));
        s->regs->err_code |= R_ERR_CODE_INVALID_OP_MASK;
        s->regs->op_status = KEYMGR_OP_STATUS_DONE_ERROR;
        return;
    }

    // this is a mock implementation
    uint32_t id_value = 0xabcd0000 | (uint32_t)s->state;
    for (int i = 0; i < ROT_KEYMGR_SW_SHARE0_OUTPUT_LENGTH / sizeof(uint32_t); i++) {
        s->regs->sw_share0_output[i] = id_value + i;
        s->regs->sw_share1_output[i] = ~(id_value + i);
    }

    // TODO: KMAC
    
    s->regs->op_status = KEYMGR_OP_STATUS_DONE_SUCCESS;
}

static void rot_keymgr_handle_generate_sw_output(RoTKeyMgrState *s)
{
    switch (s->state) {
    case KEYMGR_CREATOR_ROOT_KEY:
    case KEYMGR_OWNER_INTERMEDIATE_KEY:
    case KEYMGR_OWNER_ROOT_KEY:
        break;
    case KEYMGR_RESET:
    case KEYMGR_INITIALIZED:
    case KEYMGR_DISABLED:
    case KEYMGR_INVALID:
    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                     "%s: Cannot generate SW output in state %s\n",
                     __func__, STATE_NAME(s->state));
        s->regs->err_code |= R_ERR_CODE_INVALID_OP_MASK;
        s->regs->op_status = KEYMGR_OP_STATUS_DONE_ERROR;
        return;
    }

    uint32_t cdi_sel = FIELD_EX32(rot_shadow_reg_peek(&s->control), 
                                 CONTROL_SHADOWED, CDI_SEL);
    uint32_t dest_sel = FIELD_EX32(rot_shadow_reg_peek(&s->control), 
                                  CONTROL_SHADOWED, DEST_SEL);
    
    qemu_log_mask(LOG_UNIMP,
                 "%s: Generating SW output in state %s with CDI=%u, DEST=%u\n",
                 __func__, STATE_NAME(s->state), cdi_sel, dest_sel);
    
    uint32_t sw_output_value = 0x5a5a0000 | 
                              ((uint32_t)s->state << 8) | 
                              (cdi_sel << 4) | dest_sel;
    
    for (int i = 0; i < ROT_KEYMGR_SW_SHARE0_OUTPUT_LENGTH / sizeof(uint32_t); i++) {
        s->regs->sw_share0_output[i] = sw_output_value + i;
        s->regs->sw_share1_output[i] = ~(sw_output_value + i);
    }
    
    // TODO: KMAC
    
    s->regs->op_status = KEYMGR_OP_STATUS_DONE_SUCCESS;
}

static void rot_keymgr_handle_generate_hw_output(RoTKeyMgrState *s)
{
    switch (s->state) {
    case KEYMGR_CREATOR_ROOT_KEY:
    case KEYMGR_OWNER_INTERMEDIATE_KEY:
    case KEYMGR_OWNER_ROOT_KEY:
        break;
    case KEYMGR_RESET:
    case KEYMGR_INITIALIZED:
    case KEYMGR_DISABLED:
    case KEYMGR_INVALID:
    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                     "%s: Cannot generate HW output in state %s\n",
                     __func__, STATE_NAME(s->state));
        s->regs->err_code |= R_ERR_CODE_INVALID_OP_MASK;
        s->regs->op_status = KEYMGR_OP_STATUS_DONE_ERROR;
        return;
    }
    
    uint32_t cdi_sel = FIELD_EX32(rot_shadow_reg_peek(&s->control), 
                                 CONTROL_SHADOWED, CDI_SEL);
    uint32_t dest_sel = FIELD_EX32(rot_shadow_reg_peek(&s->control), 
                                  CONTROL_SHADOWED, DEST_SEL);
    
    if (dest_sel == KEYMGR_DEST_NONE) {
        qemu_log_mask(LOG_GUEST_ERROR,
                     "%s: Invalid DEST_SEL for HW output: %u\n",
                     __func__, dest_sel);
        s->regs->err_code |= R_ERR_CODE_INVALID_OP_MASK;
        s->regs->op_status = KEYMGR_OP_STATUS_DONE_ERROR;
        return;
    }
    
    qemu_log_mask(LOG_UNIMP,
                 "%s: Generating HW output in state %s with CDI=%u for DEST=%u\n",
                 __func__, STATE_NAME(s->state), cdi_sel, dest_sel);
    
    // TODO: 实际实现应该:
    // 1. 计算密钥
    // 2. 将密钥发送给相应的硬件模块（AES, KMAC, OTBN）
    
    s->regs->op_status = KEYMGR_OP_STATUS_DONE_SUCCESS;
}

static void rot_keymgr_handle_disable(RoTKeyMgrState *s)
{
    if (s->state == KEYMGR_INVALID) {
        qemu_log_mask(LOG_GUEST_ERROR,
                     "%s: Cannot disable from INVALID state\n", __func__);
        s->regs->err_code |= R_ERR_CODE_INVALID_OP_MASK;
        s->regs->op_status = KEYMGR_OP_STATUS_DONE_ERROR;
        return;
    }
    
    qemu_log_mask(LOG_UNIMP,
                 "%s: Disabling key manager from state %s\n", 
                 __func__, STATE_NAME(s->state));
    
    rot_keymgr_change_state(s, KEYMGR_DISABLED);
    
    rot_keymgr_sideload_key_slots_clear(0xFF);
    
    s->regs->op_status = KEYMGR_OP_STATUS_DONE_SUCCESS;
}

static void rot_keymgr_process_operation(RoTKeyMgrState *s)
{
    uint32_t operation;
    
    operation = FIELD_EX32(rot_shadow_reg_peek(&s->control), 
                          CONTROL_SHADOWED, OPERATION);
    
    s->regs->op_status = KEYMGR_OP_STATUS_WIP;
    
    switch (operation) {
    case KEYMGR_OP_ADVANCE:
        /* Advance key manager state. Advances key manager to the next
           stage. If key manager is already at last functional state,
           the advance operation is equivalent to the disable operation.*/
        rot_keymgr_handle_advance(s);
        break;
    case KEYMGR_OP_GENERATE_ID:
        /* Generates an identity seed from the current state. */
        rot_keymgr_handle_generate_id(s);
        break;
    case KEYMGR_OP_GENERATE_SW:
        /* Generates a key manager output that is visible
           to software from the current state */
        rot_keymgr_handle_generate_sw_output(s);
        break;
    case KEYMGR_OP_GENERATE_HW:
        /* Generates a key manager output that is visible only
           to hardware crypto blocks. */
        rot_keymgr_handle_generate_hw_output(s);
        break;
    case KEYMGR_OP_DISABLE:
        /* Into disabled state (it's a terminal state), 
           cannot be recovered without a reset */
        rot_keymgr_handle_disable(s);
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                     "%s: Invalid key manager operation\n", 
                     __func__);
        s->regs->err_code |= R_ERR_CODE_INVALID_OP_MASK;
        s->regs->op_status = KEYMGR_OP_STATUS_DONE_ERROR;
        break;
    }
    
    s->regs->intr_state |= INTR_OP_DONE_MASK;
    // rot_keymgr_update_irqs(s);
}

static uint64_t rot_keymgr_regs_read(void *opaque, hwaddr addr, unsigned size)
{
    RoTKeyMgrState *s = ROT_KEYMGR(opaque);
    (void)size;
    uint32_t val32;
    hwaddr reg = R32_OFF(addr);

    switch (reg) {
    // rw1c
    case R_INTR_STATE:
        val32 = s->regs->intr_state;
        
        break;
    // rw
    case R_INTR_ENABLE:
        val32 = s->regs->intr_enable;
        
        break;
    // ro
    case R_CFG_REGWEN:
        val32 = rot_keymgr_config_enabled(s) ? R_CFG_REGWEN_EN_MASK : 0u;

        break;
    // rw
    case R_START:
        val32 = s->regs->start;

        break;
    // rw
    case R_CONTROL_SHADOWED:
        val32 = rot_shadow_reg_read(&s->control);

        break;
    // rw
    case R_SIDELOAD_CLEAR:
        val32 = s->regs->sideload_clear;

        break;
    // rw0c
    case R_RESEED_INTERVAL_REGWEN:
        val32 = s->regs->reseed_interval_regwen;

        break;
    // rw
    case R_RESEED_INTERVAL_SHADOWED:
        val32 = rot_shadow_reg_read(&s->reseed_interval);

        break;
    // rw0c
    case R_SW_BINDING_REGWEN:
        val32 = s->regs->sw_binding_regwen;

        break;
    case R_SEALING_SW_BINDING_0: // rw
    case R_SEALING_SW_BINDING_1: // rw
    case R_SEALING_SW_BINDING_2: // rw
    case R_SEALING_SW_BINDING_3: // rw
    case R_SEALING_SW_BINDING_4: // rw
    case R_SEALING_SW_BINDING_5: // rw
    case R_SEALING_SW_BINDING_6: // rw
    case R_SEALING_SW_BINDING_7: // rw
        val32 = s->regs->sealing_sw_binding[reg - R_SEALING_SW_BINDING_0];

        break;
    case R_ATTEST_SW_BINDING_0: // rw
    case R_ATTEST_SW_BINDING_1: // rw
    case R_ATTEST_SW_BINDING_2: // rw
    case R_ATTEST_SW_BINDING_3: // rw
    case R_ATTEST_SW_BINDING_4: // rw
    case R_ATTEST_SW_BINDING_5: // rw
    case R_ATTEST_SW_BINDING_6: // rw
    case R_ATTEST_SW_BINDING_7: // rw
        val32 = s->regs->attest_sw_binding[reg - R_ATTEST_SW_BINDING_0];

        break;
    case R_SALT_0: // rw
    case R_SALT_1: // rw
    case R_SALT_2: // rw
    case R_SALT_3: // rw
    case R_SALT_4: // rw
    case R_SALT_5: // rw
    case R_SALT_6: // rw
    case R_SALT_7: // rw
        val32 = s->regs->salt[reg - R_SALT_0];

        break;
    // rw
    case R_KEY_VERSION:
        val32 = s->regs->key_version;

        break;
    // rw0c
    case R_MAX_CREATOR_KEY_VER_REGWEN:
        val32 = s->regs->max_creator_key_ver_regwen;

        break;
    // rw
    case R_MAX_CREATOR_KEY_VER_SHADOWED:
        val32 = rot_shadow_reg_read(&s->max_creator_key_ver);

        break;
    // rw0c
    case R_MAX_OWNER_INT_KEY_VER_REGWEN:
        val32 = s->regs->max_owner_int_key_ver_regwen;

        break;
    // rw
    case R_MAX_OWNER_INT_KEY_VER_SHADOWED:
        val32 = rot_shadow_reg_read(&s->max_owner_int_key_ver);

        break;
    // rw0c
    case R_MAX_OWNER_KEY_VER_REGWEN:
        val32 = s->regs->max_owner_key_ver_regwen;

        break;
    // rw
    case R_MAX_OWNER_KEY_VER_SHADOWED:
        val32 = rot_shadow_reg_read(&s->max_owner_key_ver);

        break;
    case R_SW_SHARE0_OUTPUT_0: // rc
    case R_SW_SHARE0_OUTPUT_1: // rc
    case R_SW_SHARE0_OUTPUT_2: // rc
    case R_SW_SHARE0_OUTPUT_3: // rc
    case R_SW_SHARE0_OUTPUT_4: // rc
    case R_SW_SHARE0_OUTPUT_5: // rc
    case R_SW_SHARE0_OUTPUT_6: // rc
    case R_SW_SHARE0_OUTPUT_7: // rc
        val32 = s->regs->sw_share0_output[reg - R_SW_SHARE0_OUTPUT_0];
        /* clear share0 output */
        s->regs->sw_share0_output[reg - R_SW_SHARE0_OUTPUT_0] = 0;

        break;
    case R_SW_SHARE1_OUTPUT_0: // rc
    case R_SW_SHARE1_OUTPUT_1: // rc
    case R_SW_SHARE1_OUTPUT_2: // rc
    case R_SW_SHARE1_OUTPUT_3: // rc
    case R_SW_SHARE1_OUTPUT_4: // rc
    case R_SW_SHARE1_OUTPUT_5: // rc
    case R_SW_SHARE1_OUTPUT_6: // rc
    case R_SW_SHARE1_OUTPUT_7: // rc
        val32 = s->regs->sw_share1_output[reg - R_SW_SHARE1_OUTPUT_0];
        /* clear share1 output */
        s->regs->sw_share1_output[reg - R_SW_SHARE1_OUTPUT_0] = 0;

        break;
    // ro
    case R_WORKING_STATE:
        val32 = s->regs->working_state;

        break;
    // rw1c
    case R_OP_STATUS:
        /* key manager status
         * 0x0 IDLE
         * 0x1 WIP (work in progress)
         * 0x2 DONE_SUCCESS
         * 0x3 DONE_ERROR (operation finished with error, see ERR_CODE)
         */
        val32 = s->regs->op_status;

        break;
    // rw1c
    case R_ERR_CODE:
        /*
         * bit 0: invalid operation, synchronous error
         * bit 1: invalid kmac input, synchronous error
         * bit 2: invalid shadow update, asynchronous error
         */
        val32 = s->regs->err_code;

        break;
    // ro
    case R_FAULT_STATUS:
        /* represents both synchronous and asynchronous fatal faults */
        val32 = s->regs->fault_status;

        break;
    // rw0c
    case R_DEBUG:
        val32 = s->regs->debug;

        break;
    case R_INTR_TEST:  // wo
    case R_ALERT_TEST: // wo
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

static void rot_keymgr_regs_write(void *opaque, hwaddr addr, uint64_t val,
                                 unsigned size)
{
    RoTKeyMgrState *s = ROT_KEYMGR(opaque);
    (void)size;
    uint32_t val32 = (uint32_t)val;
    hwaddr reg = R32_OFF(addr);

    switch (reg) {
    // rw1c
    case R_INTR_STATE:
        s->regs->intr_state &= ~(val32 & INTR_OP_DONE_MASK);
        // rot_keymgr_update_irqs(s);

        break;
    // rw
    case R_INTR_ENABLE:
        s->regs->intr_enable = (val32 & INTR_OP_DONE_MASK);
        // rot_keymgr_update_irqs(s);

        break;
    // wo
    case R_INTR_TEST:
        s->regs->intr_state |= (val32 & INTR_OP_DONE_MASK);
        // rot_keymgr_update_irqs(s);

        break;
    // wo
    case R_ALERT_TEST:
        s->regs->alert_test = (val32 & ALERT_TEST_MASK);

        break;
    // rw
    case R_START:
        if (!rot_keymgr_check_reg_write(s, reg)) {
            break;
        }

        /* to trigger a start */
        s->regs->start = (val32 & R_START_EN_MASK);

        // TODO: check control operation

        break;
    // rw
    case R_CONTROL_SHADOWED:
        if (!rot_keymgr_check_reg_write(s, reg)) {
            break;
        }

        /* key manager operation controls */
        val32 &= CONTROL_SHADOWED_MASK;
        switch (rot_shadow_reg_write(&s->control, val32)) {
        case ROT_SHADOW_REG_STAGED:
        case ROT_SHADOW_REG_COMMITTED:
            break;
        case ROT_SHADOW_REG_ERROR:
        default:
            s->regs->err_code |= ERR_CODE_INVALID_SHADOW_UPDATE_MASK;
            break;
        }

        break;
    // rw
    case R_SIDELOAD_CLEAR:
        if (!rot_keymgr_check_reg_write(s, reg)) {
            break;
        }

        /* sideload key slots clear */
        s->regs->sideload_clear = (val32 & R_SIDELOAD_CLEAR_VAL_MASK);
        /* clear the different key slots with entropy */
        rot_keymgr_sideload_key_slots_clear(s->regs->sideload_clear);

        break;
    // rw0c
    case R_RESEED_INTERVAL_REGWEN:
        /* regwen for reseed interval */
        s->regs->reseed_interval_regwen &= (val32 & 
                                              R_RESEED_INTERVAL_REGWEN_EN_MASK);

        break;
    // rw
    case R_RESEED_INTERVAL_SHADOWED:
        /* reseed interval for key manager entropy reseed */
        if (s->regs->reseed_interval_regwen & R_RESEED_INTERVAL_REGWEN_EN_MASK) {
            /* value: number of key manager cycles before the entropy is reseeded */
            val32 &= R_RESEED_INTERVAL_SHADOWED_VAL_MASK;
            switch (rot_shadow_reg_write(&s->reseed_interval, val32)) {
            case ROT_SHADOW_REG_STAGED:
            case ROT_SHADOW_REG_COMMITTED:
                break;
            case ROT_SHADOW_REG_ERROR:
            default:
                s->regs->err_code |= ERR_CODE_INVALID_SHADOW_UPDATE_MASK;
                break;
            }
        } else {
            qemu_log_mask(LOG_GUEST_ERROR, 
                          "%s: RESEED_INTERVAL_REGWEN not enabled, "
                          "can't write to (%s)\n", 
                          __func__, REG_NAME(reg));
        }

        break;
    // rw0c
    case R_SW_BINDING_REGWEN:
        /* register write enable for SOFTWARE_BINDING */
        // TODO: this is locked by sw and unlocked by hw upon a successful advance call
        s->regs->sw_binding_regwen &= (val32 & R_SW_BINDING_REGWEN_EN_MASK);

        break;
    case R_SEALING_SW_BINDING_0: // rw
    case R_SEALING_SW_BINDING_1: // rw
    case R_SEALING_SW_BINDING_2: // rw
    case R_SEALING_SW_BINDING_3: // rw
    case R_SEALING_SW_BINDING_4: // rw
    case R_SEALING_SW_BINDING_5: // rw
    case R_SEALING_SW_BINDING_6: // rw
    case R_SEALING_SW_BINDING_7: // rw
        /* software binding input to sealing portion of the key manager */
        // TODO: this is locked by sw and unlocked by hw upon a successful advance call
        // TODO: this binding value is not considered secret, however its integrity is important
        if (s->regs->sw_binding_regwen & R_SW_BINDING_REGWEN_EN_MASK) {
            s->regs->sealing_sw_binding[reg - R_SEALING_SW_BINDING_0] = val32;
        } else {
            qemu_log_mask(LOG_GUEST_ERROR, 
                          "%s: SW_BINDING_REGWEN not enabled, "
                          "can't write to (%s)\n", 
                          __func__, REG_NAME(reg));
        }

        break;
    case R_ATTEST_SW_BINDING_0: // rw
    case R_ATTEST_SW_BINDING_1: // rw
    case R_ATTEST_SW_BINDING_2: // rw
    case R_ATTEST_SW_BINDING_3: // rw
    case R_ATTEST_SW_BINDING_4: // rw
    case R_ATTEST_SW_BINDING_5: // rw
    case R_ATTEST_SW_BINDING_6: // rw
    case R_ATTEST_SW_BINDING_7: // rw
        /* software binding input to attestation portion of the key manager */
        // TODO: this is locked by sw and unlocked by hw upon a successful advance call
        // TODO: this binding value is not considered secret, however its integrity is important
        if (s->regs->sw_binding_regwen & R_SW_BINDING_REGWEN_EN_MASK) {
            s->regs->attest_sw_binding[reg - R_ATTEST_SW_BINDING_0] = val32;
        } else {
            qemu_log_mask(LOG_GUEST_ERROR, 
                          "%s: SW_BINDING_REGWEN not enabled, "
                          "can't write to (%s)\n", 
                          __func__, REG_NAME(reg));
        }

        break;
    case R_SALT_0: // rw
    case R_SALT_1: // rw
    case R_SALT_2: // rw
    case R_SALT_3: // rw
    case R_SALT_4: // rw
    case R_SALT_5: // rw
    case R_SALT_6: // rw
    case R_SALT_7: // rw
        /* salt value used as part of output generation */
        if (!rot_keymgr_check_reg_write(s, reg)) {
            break;
        }

        s->regs->salt[reg - R_SALT_0] = val32;

        break;
    // rw
    case R_KEY_VERSION:
        /* version used as part of output generation */
        if (!rot_keymgr_check_reg_write(s, reg)) {
            break;
        }

        s->regs->key_version = val32;

        break;
    // rw0c
    case R_MAX_CREATOR_KEY_VER_REGWEN:
        /* register write enable for MAX_CREATOR_KEY_VER */
        s->regs->max_creator_key_ver_regwen &= (val32 & 
                                          R_MAX_CREATOR_KEY_VER_REGWEN_EN_MASK);

        break;
    // rw
    case R_MAX_CREATOR_KEY_VER_SHADOWED:
        /* max creator key version */
        if (s->regs->max_creator_key_ver_regwen & 
                                         R_MAX_CREATOR_KEY_VER_REGWEN_EN_MASK) {
            /* any key version up to the value specified in this register is valid */
            switch (s->regs->max_creator_key_ver_shadowed = val32) {
            case ROT_SHADOW_REG_STAGED:
            case ROT_SHADOW_REG_COMMITTED:
                break;
            case ROT_SHADOW_REG_ERROR:
            default:
                s->regs->err_code |= ERR_CODE_INVALID_SHADOW_UPDATE_MASK;
                break;
            }
        } else {
            qemu_log_mask(LOG_GUEST_ERROR, 
                          "%s: MAX_CREATOR_KEY_VER_REGWEN not enabled, "
                          "can't write to (%s)\n", 
                          __func__, REG_NAME(reg));
        }

        break;
    // rw0c
    case R_MAX_OWNER_INT_KEY_VER_REGWEN:
        /* register write enable for MAX_OWNER_INT_KEY_VER */
        s->regs->max_owner_int_key_ver_regwen &= (val32 & 
                                        R_MAX_OWNER_INT_KEY_VER_REGWEN_EN_MASK);

        break;
    // rw
    case R_MAX_OWNER_INT_KEY_VER_SHADOWED:
        /* max owner intermediate key version */
        if (s->regs->max_owner_int_key_ver_regwen & 
                                       R_MAX_OWNER_INT_KEY_VER_REGWEN_EN_MASK) {
            /* any key version up to the value specified in this register is valid */
            switch (s->regs->max_owner_int_key_ver_shadowed = val32) {
            case ROT_SHADOW_REG_STAGED:
            case ROT_SHADOW_REG_COMMITTED:
                break;
            case ROT_SHADOW_REG_ERROR:
            default:
                s->regs->err_code |= ERR_CODE_INVALID_SHADOW_UPDATE_MASK;
                break;
            }
        } else {
            qemu_log_mask(LOG_GUEST_ERROR, 
                          "%s: MAX_OWNER_INT_KEY_VER_REGWEN not enabled, "
                          "can't write to (%s)\n", 
                          __func__, REG_NAME(reg));
        }

        break;
    // rw0c
    case R_MAX_OWNER_KEY_VER_REGWEN:
        /* register write enable for MAX_OWNER_KEY_VER */
        s->regs->max_owner_key_ver_regwen &= (val32 & 
                                            R_MAX_OWNER_KEY_VER_REGWEN_EN_MASK);

        break;
    // rw
    case R_MAX_OWNER_KEY_VER_SHADOWED:
        /* max owner key version */
        if (s->regs->max_owner_key_ver_regwen & 
                                       R_MAX_OWNER_KEY_VER_REGWEN_EN_MASK) {
            /* any key version up to the value specified in this register is valid */
            switch (s->regs->max_owner_key_ver_shadowed = val32) {
            case ROT_SHADOW_REG_STAGED:
            case ROT_SHADOW_REG_COMMITTED:
                break;
            case ROT_SHADOW_REG_ERROR:
            default:
                s->regs->err_code |= ERR_CODE_INVALID_SHADOW_UPDATE_MASK;
                break;
            }
        } else {
            qemu_log_mask(LOG_GUEST_ERROR, 
                          "%s: MAX_OWNER_KEY_VER_REGWEN not enabled, "
                          "can't write to (%s)\n", 
                          __func__, REG_NAME(reg));
        }

        break;
    // rw1c
    case R_OP_STATUS:
        /* key manager status
         * hardware sets the status based on software initiated operations
         * this register must be explicitly cleared by software
         * software clears by writing back whatever is reads
         */
        s->regs->op_status &= ~(val32 & R_OP_STATUS_STATUS_MASK);

        break;
    // rw1c
    case R_ERR_CODE:
        /* key manager error code, must be explicitly cleared by software */
        s->regs->err_code &= ~(val32 & ERR_CODE_MASK);
        
        break;
    // rw0c
    case R_DEBUG:
        /* holds some debug information if keymgr misbehaves */
        s->regs->debug &= (val32 & DEBUG_MASK);

        break;
    case R_CFG_REGWEN:         // ro
    case R_SW_SHARE0_OUTPUT_0: // rc
    case R_SW_SHARE0_OUTPUT_1: // rc
    case R_SW_SHARE0_OUTPUT_2: // rc
    case R_SW_SHARE0_OUTPUT_3: // rc
    case R_SW_SHARE0_OUTPUT_4: // rc
    case R_SW_SHARE0_OUTPUT_5: // rc
    case R_SW_SHARE0_OUTPUT_6: // rc
    case R_SW_SHARE0_OUTPUT_7: // rc
    case R_SW_SHARE1_OUTPUT_0: // rc
    case R_SW_SHARE1_OUTPUT_1: // rc
    case R_SW_SHARE1_OUTPUT_2: // rc
    case R_SW_SHARE1_OUTPUT_3: // rc
    case R_SW_SHARE1_OUTPUT_4: // rc
    case R_SW_SHARE1_OUTPUT_5: // rc
    case R_SW_SHARE1_OUTPUT_6: // rc
    case R_SW_SHARE1_OUTPUT_7: // rc
    case R_WORKING_STATE:      // ro
    case R_FAULT_STATUS:       // ro
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

static const MemoryRegionOps rot_keymgr_regs_ops = {
    .read  = &rot_keymgr_regs_read,
    .write = &rot_keymgr_regs_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static void rot_keymgr_init(Object *obj)
{
    RoTKeyMgrState *s = ROT_KEYMGR(obj);

    s->regs = g_new0(RoTKeyMgrRegisters, 1u);

    memory_region_init_io(&s->mmio, obj, &rot_keymgr_regs_ops, s,
                         TYPE_ROT_KEYMGR, REGS_SIZE);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->mmio);

    // TODO    
}

static void rot_keymgr_reset(DeviceState *dev)
{
    RoTKeyMgrState *s = ROT_KEYMGR(dev);

    // TODO: reset the state
    rot_keymgr_change_state(s, KEYMGR_RESET);
    
    memset(s->regs, 0, sizeof(*(s->regs)));

    s->regs->cfg_regwen                     = 0x1u;
    s->regs->reseed_interval_regwen         = 0x1u;
    s->regs->sw_binding_regwen              = 0x1u;
    s->regs->max_creator_key_ver_regwen     = 0x1u;
    s->regs->max_owner_int_key_ver_regwen   = 0x1u;
    s->regs->max_owner_key_ver_regwen       = 0x1u;

    rot_shadow_reg_init(&s->control, 0x10u);
    rot_shadow_reg_init(&s->reseed_interval, 0x100u);
    rot_shadow_reg_init(&s->max_creator_key_ver, 0x0u);
    rot_shadow_reg_init(&s->max_owner_int_key_ver, 0x1u);
    rot_shadow_reg_init(&s->max_owner_key_ver, 0x0u);

    // rot_keymgr_update_irqs(s);
}

static void rot_keymgr_realize(DeviceState *dev, Error **errp)
{
    (void)errp;

    RoTKeyMgrState *s = ROT_KEYMGR(dev);
    if (!s->rot_id) {
        s->rot_id = 
            g_strdup(object_get_canonical_path_component(OBJECT(s)->parent));
    }
}

static Property rot_keymgr_properties[] = {
    DEFINE_PROP_LINK("kmac", RoTKeyMgrState, kmac, TYPE_ROT_KMAC, RoTKMACState *),
    DEFINE_PROP_UINT32("size", RoTKeyMgrState, size, UINT32_MAX),
    DEFINE_PROP_STRING("rot-id", RoTKeyMgrState, rot_id),
    DEFINE_PROP_END_OF_LIST(),
};

static void rot_keymgr_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    (void)data;

    device_class_set_legacy_reset(dc, &rot_keymgr_reset);
    dc->realize = rot_keymgr_realize;

    device_class_set_props(dc, rot_keymgr_properties);
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo rot_keymgr_info = {
    .name          = TYPE_ROT_KEYMGR,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(RoTKeyMgrState),
    .instance_init = &rot_keymgr_init,
    .class_init    = &rot_keymgr_class_init,
};

static void rot_keymgr_register_types(void)
{
    type_register_static(&rot_keymgr_info);
}

type_init(rot_keymgr_register_types)
