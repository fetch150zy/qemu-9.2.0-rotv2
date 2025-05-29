/*
 * QEMU OpenTitan utilities
 *
 * Copyright (c) 2023-2024 Rivos, Inc.
 * Copyright (c) 2025 lowRISC contributors.
 *
 * Author(s):
 *  Emmanuel Blot <eblot@rivosinc.com>
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
#include "qemu/config-file.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "qemu/option.h"
#include "qemu/option_int.h"
#include "qemu/queue.h"
#include "qemu/typedefs.h"
#include "qapi/error.h"
#include "qapi/util.h"
#include "qom/object.h"
#include "hw/rot/ot_common.h"
#include "hw/rot/ot_rom_ctrl.h"
#include "hw/rot/ot_rom_ctrl_img.h"

typedef struct OtCommonObjectNode {
    Object *obj;
    QSIMPLEQ_ENTRY(OtCommonObjectNode) node;
} OtCommonObjectNode;

typedef QSIMPLEQ_HEAD(OtCommonObjectList,
                      OtCommonObjectNode) OtCommonObjectList;

typedef struct {
    const char *type; /* which type of object should be matched */
    unsigned count; /* how many object should be matched */
    OtCommonObjectList list; /* list of matched objects */
} OtCommonObjectNodes;

static const char *OT_COMMON_PROP_STRINGS[] = {
    "str",
    "string",
};

static const char *OT_COMMON_PROP_UINT[] = {
    "uint8",
    "uint16",
    "uint32",
    "uint64",
};

static const char *OT_COMMON_PROP_BOOL[] = { "bool" };

static int ot_common_node_child_walker(Object *child, void *opaque)
{
    OtCommonObjectNodes *nodes = opaque;
    if (!object_dynamic_cast(child, nodes->type)) {
        /* continue walking the children hierarchy */
        return 0;
    }

    OtCommonObjectNode *node = g_new0(OtCommonObjectNode, 1u);
    node->obj = child;
    object_ref(child);

    QSIMPLEQ_INSERT_TAIL(&nodes->list, node, node);

    nodes->count--;

    /* stop walking the hierarchy immediately if max count has been reached */
    return nodes->count ? 0 : 1;
}

CPUState *ot_common_get_local_cpu(DeviceState *s)
{
    BusState *bus = s->parent_bus;
    if (!bus) {
        return NULL;
    }

    Object *parent;
    if (bus->parent) {
        parent = OBJECT(bus->parent);
    } else if (bus == sysbus_get_default()) {
        parent = qdev_get_machine();
    } else {
        return NULL;
    }

    OtCommonObjectNodes nodes = {
        .type = TYPE_CPU,
        .count = 1u,
    };
    QSIMPLEQ_INIT(&nodes.list);

    /* find one of the closest CPU (should be only one with OT platforms) */
    if (object_child_foreach_recursive(OBJECT(parent),
                                       &ot_common_node_child_walker, &nodes)) {
        g_assert(!QSIMPLEQ_EMPTY(&nodes.list));
        OtCommonObjectNode *node = QSIMPLEQ_FIRST(&nodes.list);
        object_unref(node->obj);
        CPUState *cpu = CPU(node->obj);
        g_free(node);
        return cpu;
    }

    return NULL;
}

AddressSpace *ot_common_get_local_address_space(DeviceState *s)
{
    CPUState *cpu = ot_common_get_local_cpu(s);

    return cpu ? cpu->as : NULL;
}
