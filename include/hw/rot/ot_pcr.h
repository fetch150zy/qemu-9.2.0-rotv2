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

#ifndef HW_ROTV2_ROT_PCR_H
#define HW_ROTV2_ROT_PCR_H

#include "qom/object.h"

#define TYPE_ROT_PCR "rot-pcr"
OBJECT_DECLARE_SIMPLE_TYPE(RoTPCRState, ROT_PCR)

#define ROT_PCR_MMIO_SIZE 0x1000u

#define ROT_PCR_REGS_BASE 0x0u
#define ROT_PCR_FIFO_BASE 0x800u
#define ROT_PCR_FIFO_SIZE 0x800u

#endif /* HW_ROTV2_ROT_PCR_H */
