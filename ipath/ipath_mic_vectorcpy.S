##############################################################################
#
# Copyright (C) 2008-2012 Intel Corporation. All right reserved.
#
# The information and source code contained herein is the exclusive property
# of Intel Corporation and may not be disclosed, examined, or reproduced
# in whole or in part without explicit written authorization from the Company.
#
##############################################################################

##############################################################################
#
# cvs_id[] = "$Id: fastmemcpy-lrb2.S 27119 2012-07-06 01:25:10Z azvezdin $";
#
##############################################################################

##############################################################################
#
# Intel Corporation is the author of this code, and requests that all
# problem reports or change requests be submitted to
#
#       manel.fernandez@intel.com
#
#       Author: Manel Fernandez (based on a SSE2 version of Patrick J. Fay)
#       Date:   February, 2008
#
#       defines _intel_lrb_memcpy() - copies source block to dest block.
#       Should be completely compatible with memcpy/memmove,
#       and properly handle overlapping source/dest for memmove.
#       LRB implementation
#
##############################################################################
##############################################################################
#
# Modification history:
#
# 001 Added support for Non Globally Ordered (NGO) stores, which are available
#     in KNC B-stepping.
#     azvezdin 25-Jun-2012
#
# On Mar. 2013
# modified by CQ Tang from __intel_fast_memcpy() for MIC:fastmemcpy-lrb2.S
#
# On Dec. 2013
# Andrew Friedley: added ipath_mic_vectorcpy_64a routine for writing packet
# headers in a single operation.
#
#
##############################################################################

#
# Copy method constants
#
#            MEM_OPS_USE_KNC_NGO = 4 (KNCni, starting from B-stepping)
#            MEM_OPS_USE_LRB     = 3 (A-stepping KNCni, no NGO stores)
#            MEM_OPS_USE_SSE2    = 2 (N/A, use REG)
#            MEM_OPS_USE_MMX     = 1 (N/A, use REG)
#            MEM_OPS_USE_REG     = 0
#            MEM_OPS_NOT_INITED  = -1
#
# Algorithm thresholds
#
#            THRESHOLD_BIG      = 64    # big array threshold
#            THRESHOLD_LOOP     = 256   # unrolled limit theshold
#

#
# REGISTER RULES (KNC)
# parameter registers   RDI, RSI, RDX, RCX, R8, R9, ZMM0-ZMM7
# scratch registers     RAX, RCX, RDX, RSI, RDI, R8-R11, ST(0)-ST(7), ZMM0-ZMM31
# callee-save registers RBX, RBP, R12-R15
# registers for return  RAX, RDX, ZMM0, ZMM1, st(0), st(1)
#

#ifdef __MIC__

.intel_syntax noprefix

            .text

            .balign     64
            .global     ipath_mic_vectorcpy_64a

#
# Function entry point (tgt = rdi, src = rsi)
#
# Copies 64 bytes from src address to tgt address.
# Assumes both addresses are 64-byte aligned!
# No checking is performed.
#
ipath_mic_vectorcpy_64a:
        vmovdqa64 zmm0,[rsi]
        vmovdqa64 [rdi],zmm0
        ret

    .balign 16
    .type ipath_mic_vectorcpy_64a,@function
    .size ipath_mic_vectorcpy_64a,.-ipath_mic_vectorcpy_64a



            .balign     64
            .global     ipath_mic_vectorcpy

#
# Function entry point (tgt = rdi, src = rsi, len = rdx)
#
# Check if size is > THRESHOLD_BIG bytes.
# If so, then we'll try using higher performing logic.
# Otherwise, just do the moves in a jump table.
#
ipath_mic_vectorcpy:
            mov         r8, rdx                 # reassign input arguments
            mov         rax, rdi                # memcpy return the dest address
            cmp         r8, 64                  # check against THRESHOLD_BIG
            jg          short lrb_method

            # small buffers, update pointers
            lea         r11, fwdPxQx[rip]
            add         rdi, r8
            add         rsi, r8

            # The jump table is constructed such that all the sizes with
            #   ('size % 8' == 0) go to one stream (the P0Dx stream).
            # The 'x' is x = int(size/8).
            # All the ('size % 8' == 1) sizes goto the P1Qx stream, etc.
            # This saves us from having another jump table at the end to handle the
            #   the trailing (size % 8) bytes.
#if !defined(PIC)
            jmp         qword ptr [r11+r8*8]
#else
            mov         r10, [r11+r8*8]
            lea         r11, [r10+r11]
            jmp         r11
#endif

#
# We will check also which datatypes will be used for copy
# we pre-prefetch the first data line in this body
# It usual to hava a DTLB miss, and according to Larry the prefetch is dropped
# That's why we redo the prefetch once the above miss is served (after the icache miss after jz)
#
            .balign     16
lrb_method:
            # The fall-through path is to do LRB load/stores
            # First, align dest to 64 byte boundary.
            lea         r11, HeadPxQx[rip]
            mov         r10, rdi            # get source pointer
            mov         rcx, rsi            # save src ptr on tmp
            neg         r10                 # get disalignment head size
            add         r10, 64
            vprefetch0  [rsi]               # prefetch 1st src line
            vprefetche0 [rdi]               # prefetch 1st dst line
            and         r10, 63

            # If aligning dst makes src be 4 byte unaligned (element size),
            #   then there is no benefit in aligning beyond 32/16 bytes.
            #   (besides, aligning to 64 bytes would generate unaligned vloads).
            # RCX will keep if src is 64 bytes (0), 32 (2), or 16 bytes aligned (1,3)
            add         rcx, r10            # get final src ptr
            and         rcx, 3              # would it be unaligned?
            jz          short aligned_src

            # src ptr would be unaligned, align dst to 32/16 bytes instead
            and         r10, 31             # get only disalignment head size [0..31]
            cmp         rcx, 2              # would it be 2 byte unaligned?
            je          short aligned_src
            and         r10, 15             # get only disalignment head size [0..15]
            # fall-though!!!

aligned_src:
            # assume cache-line dst ptr is the default case
            cmp         r10, 0
            vprefetch0  [rsi]               # (re)prefetch 1st src line
            vprefetche0 [rdi]               # (re)prefetch 1st dst line
            jz          aligned_now

            # update pointers
            add         rdi, r10            # get high nearest aligned dst ptr
            add         rsi, r10            # advance same bytes for src ptr
            sub         r8, r10             # skip non-aligned bytes from total size
#if !defined(PIC)
            jmp         qword ptr [r11+r10*8]
#else
            mov         r9, [r11+r10*8]
            lea         r11, [r9+r11]
            jmp         r11
#endif

#
# Copy unaligned head based on head size (64 byte alignment)
#
            .balign     16
#if !defined(PIC)
HeadPxQx:   .quad       HP0Q0,HP1Q0,HP2Q0,HP3Q0,HP4Q0,HP5Q0,HP6Q0,HP7Q0
            .quad       HP0Q1,HP1Q1,HP2Q1,HP3Q1,HP4Q1,HP5Q1,HP6Q1,HP7Q1
            .quad       HP0Q2,HP1Q2,HP2Q2,HP3Q2,HP4Q2,HP5Q2,HP6Q2,HP7Q2
            .quad       HP0Q3,HP1Q3,HP2Q3,HP3Q3,HP4Q3,HP5Q3,HP6Q3,HP7Q3
            .quad       HP0Q4,HP1Q4,HP2Q4,HP3Q4,HP4Q4,HP5Q4,HP6Q4,HP7Q4
            .quad       HP0Q5,HP1Q5,HP2Q5,HP3Q5,HP4Q5,HP5Q5,HP6Q5,HP7Q5
            .quad       HP0Q6,HP1Q6,HP2Q6,HP3Q6,HP4Q6,HP5Q6,HP6Q6,HP7Q6
            .quad       HP0Q7,HP1Q7,HP2Q7,HP3Q7,HP4Q7,HP5Q7,HP6Q7,HP7Q7
#else
HeadPxQx:   .quad       HP0Q0-HeadPxQx
            .quad       HP1Q0-HeadPxQx
            .quad       HP2Q0-HeadPxQx
            .quad       HP3Q0-HeadPxQx
            .quad       HP4Q0-HeadPxQx
            .quad       HP5Q0-HeadPxQx
            .quad       HP6Q0-HeadPxQx
            .quad       HP7Q0-HeadPxQx

            .quad       HP0Q1-HeadPxQx
            .quad       HP1Q1-HeadPxQx
            .quad       HP2Q1-HeadPxQx
            .quad       HP3Q1-HeadPxQx
            .quad       HP4Q1-HeadPxQx
            .quad       HP5Q1-HeadPxQx
            .quad       HP6Q1-HeadPxQx
            .quad       HP7Q1-HeadPxQx

            .quad       HP0Q2-HeadPxQx
            .quad       HP1Q2-HeadPxQx
            .quad       HP2Q2-HeadPxQx
            .quad       HP3Q2-HeadPxQx
            .quad       HP4Q2-HeadPxQx
            .quad       HP5Q2-HeadPxQx
            .quad       HP6Q2-HeadPxQx
            .quad       HP7Q2-HeadPxQx

            .quad       HP0Q3-HeadPxQx
            .quad       HP1Q3-HeadPxQx
            .quad       HP2Q3-HeadPxQx
            .quad       HP3Q3-HeadPxQx
            .quad       HP4Q3-HeadPxQx
            .quad       HP5Q3-HeadPxQx
            .quad       HP6Q3-HeadPxQx
            .quad       HP7Q3-HeadPxQx

            .quad       HP0Q4-HeadPxQx
            .quad       HP1Q4-HeadPxQx
            .quad       HP2Q4-HeadPxQx
            .quad       HP3Q4-HeadPxQx
            .quad       HP4Q4-HeadPxQx
            .quad       HP5Q4-HeadPxQx
            .quad       HP6Q4-HeadPxQx
            .quad       HP7Q4-HeadPxQx

            .quad       HP0Q5-HeadPxQx
            .quad       HP1Q5-HeadPxQx
            .quad       HP2Q5-HeadPxQx
            .quad       HP3Q5-HeadPxQx
            .quad       HP4Q5-HeadPxQx
            .quad       HP5Q5-HeadPxQx
            .quad       HP6Q5-HeadPxQx
            .quad       HP7Q5-HeadPxQx

            .quad       HP0Q6-HeadPxQx
            .quad       HP1Q6-HeadPxQx
            .quad       HP2Q6-HeadPxQx
            .quad       HP3Q6-HeadPxQx
            .quad       HP4Q6-HeadPxQx
            .quad       HP5Q6-HeadPxQx
            .quad       HP6Q6-HeadPxQx
            .quad       HP7Q6-HeadPxQx

            .quad       HP0Q7-HeadPxQx
            .quad       HP1Q7-HeadPxQx
            .quad       HP2Q7-HeadPxQx
            .quad       HP3Q7-HeadPxQx
            .quad       HP4Q7-HeadPxQx
            .quad       HP5Q7-HeadPxQx
            .quad       HP6Q7-HeadPxQx
            .quad       HP7Q7-HeadPxQx
#endif

# rsi = updated (not necessarily aligned) src pointer
# rdi = updated (16-, 32- or 64-byte aligned) dst pointer

            .balign     16
HP1Q0:      mov         r9b, byte  ptr[rsi-1]
            mov         byte  ptr[rdi-1], r9b
HP0Q0:      jmp         aligned_now

HP3Q0:      mov         r9b, byte  ptr[rsi-3]
            mov         byte  ptr[rdi-3], r9b
HP2Q0:      mov         r9w, word  ptr[rsi-2]
            mov         word  ptr[rdi-2], r9w
            jmp         aligned_now

HP5Q0:      mov         r9b, byte  ptr[rsi-5]
            mov         byte  ptr[rdi-5], r9b
HP4Q0:      mov         r9d,  dword ptr[rsi-4]
            mov         dword ptr[rdi-4], r9d
            jmp         aligned_now

HP7Q0:      mov         r9b, byte  ptr[rsi-7]
            mov         byte  ptr[rdi-7], r9b
HP6Q0:      mov         r9w, word  ptr[rsi-6]
            mov         word  ptr[rdi-6], r9w
            mov         r9d,  dword ptr[rsi-4]
            mov         dword ptr[rdi-4], r9d
            jmp         aligned_now

HP1Q1:      mov         r9b, byte  ptr[rsi-9]
            mov         byte  ptr[rdi-9], r9b
HP0Q1:      mov         r9,   qword ptr[rsi-8]
            mov         qword ptr[rdi-8], r9
            jmp         aligned_now

HP3Q1:      mov         r9b, byte  ptr[rsi-11]
            mov         byte  ptr[rdi-11], r9b
HP2Q1:      mov         r9w, word  ptr[rsi-10]
            mov         word  ptr[rdi-10], r9w
            mov         r9,   qword ptr[rsi-8]
            mov         qword ptr[rdi-8], r9
            jmp         aligned_now

HP5Q1:      mov         r9b, byte  ptr[rsi-13]
            mov         byte  ptr[rdi-13], r9b
HP4Q1:      mov         r9d,  dword ptr[rsi-12]
            mov         dword ptr[rdi-12], r9d
            mov         r9,   qword ptr[rsi-8]
            mov         qword ptr[rdi-8], r9
            jmp         aligned_now

HP7Q1:      mov         r9b, byte  ptr[rsi-15]
            mov         byte  ptr[rdi-15], r9b
HP6Q1:      mov         r9w, word  ptr[rsi-14]
            mov         word  ptr[rdi-14], r9w
            mov         r9d,  dword ptr[rsi-12]
            mov         dword ptr[rdi-12], r9d
            mov         r9,   qword ptr[rsi-8]
            mov         qword ptr[rdi-8], r9
            jmp         aligned_now

HP1Q2:      mov         r9b, byte  ptr[rsi-17]
            mov         byte  ptr[rdi-17], r9b
HP0Q2:      vloadunpackld zmm0, [rsi-16]{uint8}       # assume unaligned
            vloadunpackhd zmm0, [rsi-16+64]{uint8}
            vmovdqa32   [rdi-16], zmm0{uint8}
            jmp         aligned_now

HP3Q2:      mov         r9b, byte  ptr[rsi-19]
            mov         byte  ptr[rdi-19], r9b
HP2Q2:      mov         r9w, word  ptr[rsi-18]
            mov         word  ptr[rdi-18], r9w
            vloadunpackld zmm0, [rsi-16]{uint8}       # assume unaligned
            vloadunpackhd zmm0, [rsi-16+64]{uint8}
            vmovdqa32     [rdi-16], zmm0{uint8}
            jmp         aligned_now

HP5Q2:      mov         r9b, byte  ptr[rsi-21]
            mov         byte  ptr[rdi-21], r9b
HP4Q2:      mov         r9d,  dword ptr[rsi-20]
            mov         dword ptr[rdi-20], r9d
            vloadunpackld zmm0, [rsi-16]{uint8}       # assume unaligned
            vloadunpackhd zmm0, [rsi-16+64]{uint8}
            vmovdqa32     [rdi-16], zmm0{uint8}
            jmp         aligned_now

HP7Q2:      mov         r9b, byte  ptr[rsi-23]
            mov         byte  ptr[rdi-23], r9b
HP6Q2:      mov         r9w, word  ptr[rsi-22]
            mov         word  ptr[rdi-22], r9w
            mov         r9d,  dword ptr[rsi-20]
            mov         dword ptr[rdi-20], r9d
            vloadunpackld zmm0, [rsi-16]{uint8}       # assume unaligned
            vloadunpackhd zmm0, [rsi-16+64]{uint8}
            vmovdqa32     [rdi-16], zmm0{uint8}
            jmp         aligned_now

HP1Q3:      mov         r9b, byte  ptr[rsi-25]
            mov         byte  ptr[rdi-25], r9b
HP0Q3:      mov         r9,   qword ptr[rsi-24]
            mov         qword ptr[rdi-24], r9
            vloadunpackld zmm0, [rsi-16]{uint8}       # assume unaligned
            vloadunpackhd zmm0, [rsi-16+64]{uint8}
            vmovdqa32     [rdi-16], zmm0{uint8}
            jmp         aligned_now

HP3Q3:      mov         r9b, byte  ptr[rsi-27]
            mov         byte  ptr[rdi-27], r9b
HP2Q3:      mov         r9w, word  ptr[rsi-26]
            mov         word  ptr[rdi-26], r9w
            mov         r9,   qword ptr[rsi-24]
            mov         qword ptr[rdi-24], r9
            vloadunpackld zmm0, [rsi-16]{uint8}       # assume unaligned
            vloadunpackhd zmm0, [rsi-16+64]{uint8}
            vmovdqa32     [rdi-16], zmm0{uint8}
            jmp         aligned_now

HP5Q3:      mov         r9b, byte  ptr[rsi-29]
            mov         byte  ptr[rdi-29], r9b
HP4Q3:      mov         r9d,  dword ptr[rsi-28]
            mov         dword ptr[rdi-28], r9d
            mov         r9,   qword ptr[rsi-24]
            mov         qword ptr[rdi-24], r9
            vloadunpackld zmm0, [rsi-16]{uint8}       # assume unaligned
            vloadunpackhd zmm0, [rsi-16+64]{uint8}
            vmovdqa32     [rdi-16], zmm0{uint8}
            jmp         aligned_now

HP7Q3:      mov         r9b, byte  ptr[rsi-31]
            mov         byte  ptr[rdi-31], r9b
HP6Q3:      mov         r9w, word  ptr[rsi-30]
            mov         word  ptr[rdi-30], r9w
            mov         r9d,  dword ptr[rsi-28]
            mov         dword ptr[rdi-28], r9d
            mov         r9,   qword ptr[rsi-24]
            mov         qword ptr[rdi-24], r9
            vloadunpackld zmm0, [rsi-16]{uint8}       # assume unaligned
            vloadunpackhd zmm0, [rsi-16+64]{uint8}
            vmovdqa32     [rdi-16], zmm0{uint8}
            jmp         aligned_now

HP1Q4:      mov         r9b, byte  ptr[rsi-33]
            mov         byte  ptr[rdi-33], r9b
HP0Q4:      vloadunpackld zmm0, [rsi-32]{uint16}      # assume unaligned
            vloadunpackhd zmm0, [rsi-32+64]{uint16}
            vmovdqa32     [rdi-32], zmm0{uint16}
            jmp         aligned_now

HP3Q4:      mov         r9b, byte  ptr[rsi-35]
            mov         byte  ptr[rdi-35], r9b
HP2Q4:      mov         r9w, word  ptr[rsi-34]
            mov         word  ptr[rdi-34], r9w
            vloadunpackld zmm0, [rsi-32]{uint16}      # assume unaligned
            vloadunpackhd zmm0, [rsi-32+64]{uint16}
            vmovdqa32     [rdi-32], zmm0{uint16}
            jmp         aligned_now

HP5Q4:      mov         r9b, byte  ptr[rsi-37]
            mov         byte  ptr[rdi-37], r9b
HP4Q4:      mov         r9d,  dword ptr[rsi-36]
            mov         dword ptr[rdi-36], r9d
            vloadunpackld zmm0, [rsi-32]{uint16}      # assume unaligned
            vloadunpackhd zmm0, [rsi-32+64]{uint16}
            vmovdqa32     [rdi-32], zmm0{uint16}
            jmp         aligned_now

HP7Q4:      mov         r9b, byte  ptr[rsi-39]
            mov         byte  ptr[rdi-39], r9b
HP6Q4:      mov         r9w, word  ptr[rsi-38]
            mov         word  ptr[rdi-38], r9w
            mov         r9d,  dword ptr[rsi-36]
            mov         dword ptr[rdi-36], r9d
            vloadunpackld zmm0, [rsi-32]{uint16}      # assume unaligned
            vloadunpackhd zmm0, [rsi-32+64]{uint16}
            vmovdqa32    [rdi-32], zmm0{uint16}
            jmp         aligned_now

HP1Q5:      mov         r9b, byte  ptr[rsi-41]
            mov         byte  ptr[rdi-41], r9b
HP0Q5:      mov         r9,   qword ptr[rsi-40]
            mov         qword ptr[rdi-40], r9
            vloadunpackld zmm0, [rsi-32]{uint16}      # assume unaligned
            vloadunpackhd zmm0, [rsi-32+64]{uint16}
            vmovdqa32     [rdi-32], zmm0{uint16}
            jmp         aligned_now

HP3Q5:      mov         r9b, byte  ptr[rsi-43]
            mov         byte  ptr[rdi-43], r9b
HP2Q5:      mov         r9w, word  ptr[rsi-42]
            mov         word  ptr[rdi-42], r9w
            mov         r9,   qword ptr[rsi-40]
            mov         qword ptr[rdi-40], r9
            vloadunpackld zmm0, [rsi-32]{uint16}      # assume unaligned
            vloadunpackhd zmm0, [rsi-32+64]{uint16}
            vmovdqa32     [rdi-32], zmm0{uint16}
            jmp         aligned_now

HP5Q5:      mov         r9b, byte  ptr[rsi-45]
            mov         byte  ptr[rdi-45], r9b
HP4Q5:      mov         r9d,  dword ptr[rsi-44]
            mov         dword ptr[rdi-44], r9d
            mov         r9,   qword ptr[rsi-40]
            mov         qword ptr[rdi-40], r9
            vloadunpackld zmm0, [rsi-32]{uint16}      # assume unaligned
            vloadunpackhd zmm0, [rsi-32+64]{uint16}
            vmovdqa32     [rdi-32], zmm0{uint16}
            jmp         aligned_now

HP7Q5:      mov         r9b, byte  ptr[rsi-47]
            mov         byte  ptr[rdi-47], r9b
HP6Q5:      mov         r9w, word  ptr[rsi-46]
            mov         word  ptr[rdi-46], r9w
            mov         r9d,  dword ptr[rsi-44]
            mov         dword ptr[rdi-44], r9d
            mov         r9,   qword ptr[rsi-40]
            mov         qword ptr[rdi-40], r9
            vloadunpackld zmm0, [rsi-32]{uint16}      # assume unaligned
            vloadunpackhd zmm0, [rsi-32+64]{uint16}
            vmovdqa32     [rdi-32], zmm0{uint16}
            jmp         aligned_now

HP1Q6:      mov         r9b, byte  ptr[rsi-49]
            mov         byte  ptr[rdi-49], r9b
HP0Q6:      vloadunpackld zmm0, [rsi-48]{uint8}       # assume unaligned
            vloadunpackhd zmm0, [rsi-48+64]{uint8}
            vmovdqa32     [rdi-48], zmm0{uint8}
            vloadunpackld zmm0, [rsi-32]{uint16}      # assume unaligned
            vloadunpackhd zmm0, [rsi-32+64]{uint16}
            vmovdqa32     [rdi-32], zmm0{uint16}
            jmp         aligned_now

HP3Q6:      mov         r9b, byte  ptr[rsi-51]
            mov         byte  ptr[rdi-51], r9b
HP2Q6:      mov         r9w, word  ptr[rsi-50]
            mov         word  ptr[rdi-50], r9w
            vloadunpackld zmm0, [rsi-48]{uint8}       # assume unaligned
            vloadunpackhd zmm0, [rsi-48+64]{uint8}
            vmovdqa32     [rdi-48], zmm0{uint8}
            vloadunpackld zmm0, [rsi-32]{uint16}      # assume unaligned
            vloadunpackhd zmm0, [rsi-32+64]{uint16}
            vmovdqa32     [rdi-32], zmm0{uint16}
            jmp         aligned_now

HP5Q6:      mov         r9b, byte  ptr[rsi-53]
            mov         byte  ptr[rdi-53], r9b
HP4Q6:      mov         r9d,  dword ptr[rsi-52]
            mov         dword ptr[rdi-52], r9d
            vloadunpackld zmm0, [rsi-48]{uint8}       # assume unaligned
            vloadunpackhd zmm0, [rsi-48+64]{uint8}
            vmovdqa32     [rdi-48], zmm0{uint8}
            vloadunpackld zmm0, [rsi-32]{uint16}      # assume unaligned
            vloadunpackhd zmm0, [rsi-32+64]{uint16}
            vmovdqa32     [rdi-32], zmm0{uint16}
            jmp         aligned_now

HP7Q6:      mov         r9b, byte  ptr[rsi-55]
            mov         byte  ptr[rdi-55], r9b
HP6Q6:      mov         r9w, word  ptr[rsi-54]
            mov         word  ptr[rdi-54], r9w
            mov         r9d,  dword ptr[rsi-52]
            mov         dword ptr[rdi-52], r9d
            vloadunpackld zmm0, [rsi-48]{uint8}       # assume unaligned
            vloadunpackhd zmm0, [rsi-48+64]{uint8}
            vmovdqa32     [rdi-48], zmm0{uint8}
            vloadunpackld zmm0, [rsi-32]{uint16}      # assume unaligned
            vloadunpackhd zmm0, [rsi-32+64]{uint16}
            vmovdqa32     [rdi-32], zmm0{uint16}
            jmp         aligned_now

HP1Q7:      mov         r9b, byte  ptr[rsi-57]
            mov         byte  ptr[rdi-57], r9b
HP0Q7:      mov         r9,   qword ptr[rsi-56]
            mov         qword ptr[rdi-56], r9
            vloadunpackld zmm0, [rsi-48]{uint8}       # assume unaligned
            vloadunpackhd zmm0, [rsi-48+64]{uint8}
            vmovdqa32     [rdi-48], zmm0{uint8}
            vloadunpackld zmm0, [rsi-32]{uint16}      # assume unaligned
            vloadunpackhd zmm0, [rsi-32+64]{uint16}
            vmovdqa32     [rdi-32], zmm0{uint16}
            jmp         aligned_now

HP3Q7:      mov         r9b, byte  ptr[rsi-59]
            mov         byte  ptr[rdi-59], r9b
HP2Q7:      mov         r9w, word  ptr[rsi-58]
            mov         word  ptr[rdi-58], r9w
            mov         r9,   qword ptr[rsi-56]
            mov         qword ptr[rdi-56], r9
            vloadunpackld zmm0, [rsi-48]{uint8}       # assume unaligned
            vloadunpackhd zmm0, [rsi-48+64]{uint8}
            vmovdqa32     [rdi-48], zmm0{uint8}
            vloadunpackld zmm0, [rsi-32]{uint16}      # assume unaligned
            vloadunpackhd zmm0, [rsi-32+64]{uint16}
            vmovdqa32     [rdi-32], zmm0{uint16}
            jmp         aligned_now

HP5Q7:      mov         r9b, byte  ptr[rsi-61]
            mov         byte  ptr[rdi-61], r9b
HP4Q7:      mov         r9d,  dword ptr[rsi-60]
            mov         dword ptr[rdi-60], r9d
            mov         r9,   qword ptr[rsi-56]
            mov         qword ptr[rdi-56], r9
            vloadunpackld zmm0, [rsi-48]{uint8}       # assume unaligned
            vloadunpackhd zmm0, [rsi-48+64]{uint8}
            vmovdqa32     [rdi-48], zmm0{uint8}
            vloadunpackld zmm0, [rsi-32]{uint16}      # assume unaligned
            vloadunpackhd zmm0, [rsi-32+64]{uint16}
            vmovdqa32     [rdi-32], zmm0{uint16}
            jmp         aligned_now

HP7Q7:      mov         r9b, byte  ptr[rsi-63]
            mov         byte  ptr[rdi-63], r9b
HP6Q7:      mov         r9w, word  ptr[rsi-62]
            mov         word  ptr[rdi-62], r9w
            mov         r9d,  dword ptr[rsi-60]
            mov         dword ptr[rdi-60], r9d
            mov         r9,   qword ptr[rsi-56]
            mov         qword ptr[rdi-56], r9
            vloadunpackld zmm0, [rsi-48]{uint8}       # assume unaligned
            vloadunpackhd zmm0, [rsi-48+64]{uint8}
            vmovdqa32     [rdi-48], zmm0{uint8}
            vloadunpackld zmm0, [rsi-32]{uint16}      # assume unaligned
            vloadunpackhd zmm0, [rsi-32+64]{uint16}
            vmovdqa32     [rdi-32], zmm0{uint16}
            jmp         aligned_now

#
# dst should be 16-, 32- or 64-byte aligned here
#
            .balign     64
aligned_now:
            # If src ptr is 4-byte aligned we can take profit
            #   of 32-bit elements within vector moves.
            # Otherwise, no advantage of realigning dst ptr to 64 bytes.
            vprefetch0  [rsi+  0]                # (re)prefetch 1st src line (or prefetch 2nd line)
            vprefetche0  [rdi+  0]                # (re)prefetch 1st dst line (or prefetch 2nd line)
            cmp         rcx, 0                      # jump if src is not 4-byte aligned (element size)
            jne         lrb_unaligned_src

            # dst is here 64 byte aligned
            # src is here 4 byte aligned
            cmp         r8, 256                     # THRESHOLD_LOOP, threshold for memcpy without looping
            lea         r11, TailAxDx[rip]          # speculate tail will be aligned
            jge         short lrb64_loop            # go for looping
            jmp         short no_lrb_loop

            .balign     64
no_lrb_loop:
            # memcpy without looping
            add         rdi, r8                     # set end of write buffer
            mov         rdx, rdi
            and         rdx, 0xffffffffffffffc0     # aligned end dst pointer to 64-byte

            # check is src is 64 byte aligned
            test        rsi, 63                     # check 64-byte src alignment
            jnz         short lrb_unaligned_tail

            # both src ant dst are 64 byte aligned
            add         rsi, r8                     # set end of read buffer
            mov         rcx, rsi
            and         rcx, 0xffffffffffffffc0     # aligned end dst pointer to 64-byte
#if !defined(PIC)
            jmp         qword ptr [r11+r8*8]
#else
            mov         r10, [r11+r8*8]
            lea         r11, [r10+r11]
            jmp         r11
#endif

lrb_unaligned_tail:
            # dst is, but src is not 64-byte aligned
            lea         r11, TailUxDx[rip]
            add         rsi, r8                     # set end of read buffer
            mov         rcx, rsi
            mov         r9, rdi                     # get unaligned tail size
            sub         r9, rdx
            sub         rcx, r9                     # adjust src end
#if !defined(PIC)
            jmp         qword ptr [r11+r8*8]
#else
            mov         r10, [r11+r8*8]
            lea         r11, [r10+r11]
            jmp         r11
#endif

#
# Prepare LRB loop (64 byte moves)
#
            .balign     64
lrb64_loop:
            # cq we are here if size>=256 (r8)
            mov          r9, rax                    # save return address
            mov          r10, rbx                   # save caller value
            mov          eax, 1                     # 1H
            cpuid                                   # extract CPU stepping info
            mov          edx, eax                   # save stepping info
            mov          rax, r9                    # restore return address
            mov          rbx, r10                   # restore caller value
            mov          rcx, 128                   # speculate: rdx will contain loop threshold
                                                    # (this helps to generate less bycode)
            and          edx, 15                    # stepping info: bit 0-3
            cmp          edx, 0                     # A stepping: zero
            je           ..L_knc_no_nt_move         # A-stepping, no NGO instruction
            cmp          r8, 512
            jg           ..L_knc_nt_move

..L_knc_no_nt_move:
            # prepare for looping
            # If both the source and dest are aligned, then go to the both aligned logic.
            test        rsi, 63
            jz          short lrb64loop0A
            lea         r11, TailUxDx[rip]
            jmp         short lrb64loopXA

#
# Main LRB loop -- both src and dst are aligned
# We cannot have too many memory requests in flight (32 per core).
# Considering the high L2 miss-latency:
# - Does not make sense to unroll more than x2,
# - Prefetches going to L2 only, to make L1 misses to happen.
#   This will avoid launching too many memory requests.
# Also, prefetches are exclusive since the line will be written.
# Scalar code is scheduled in the main loop.
#
            .balign     64
lrb64loop0A:
            cmp     r8, 16320
            jge     lrb64loop0big

            .balign     64
lrb64loop0:
            # azv: we are here if size>=256 (r8)
            # rcx holds 128
            # Loop - copy 128 bytes and prefetch next 128

            # process sources first
            vmovdqa32      zmm0, [rsi+  0]
            vprefetch0  [rsi+ 0+128]
            vmovdqa32      zmm1, [rsi+ 64]
            vprefetch0  [rsi+ 64+128]

            # loop decrease indexes
            add         rsi, rcx
            sub         r8, rcx

            # process destinations
            vmovdqa32     [rdi+  0], zmm0
            vprefetche0  [rdi+ 0+128]
            vmovdqa32     [rdi+ 64], zmm1
            vprefetche0  [rdi+ 64+128]

            # check end condition
            add         rdi, rcx
            cmp         r8, 256
            jge         short lrb64loop0

            # azv: do the rest 128 bytes w/o prefetch
            vmovdqa32      zmm0, [rsi+  0]
            vmovdqa32      zmm1, [rsi+ 64]
            add         rsi, rcx
            sub         r8, rcx
            vmovdqa32     [rdi+  0], zmm0
            vmovdqa32     [rdi+ 64], zmm1
            add         rdi, rcx

            # do the tail
            add         rdi, r8                     # set end of buffers
            add         rsi, r8
            mov         rdx, rdi
            mov         rcx, rsi
            and         rdx, 0xffffffffffffffc0     # aligned end pointers to 512-bit
            and         rcx, 0xffffffffffffffc0
#if !defined(PIC)
            jmp         qword ptr [r11+r8*8]
#else
            mov         r10, [r11+r8*8]
            lea         r11, [r10+r11]
            jmp         r11
#endif

            .balign     64
lrb64loop0big:
            # azv: we are here if size >= 16K-64
            # r8 holds length
            # rcx holds 128

            # process sources first
            vmovdqa32      zmm0, [rsi+  0]
            vprefetch0  [rsi+128+0]
            vprefetch1  [rsi+1152+0]
            vmovdqa32      zmm1, [rsi+ 64]
            vprefetch0  [rsi+128+64]
            vprefetch1  [rsi+1152+64]

            # loop decrease indexes
            add         rsi, rcx
            sub         r8, rcx

            # process destinations
            vmovdqa32     [rdi+  0], zmm0
            vprefetch0  [rdi+128+0]
            vprefetch1  [rdi+1152+0]
            vmovdqa32     [rdi+ 64], zmm1
            vprefetch0  [rdi+128+64]
            vprefetch1  [rdi+1152+64]

            # check end condition
            add         rdi, rcx
            cmp         r8, 1280
            jge         short lrb64loop0big

lrb64loop0big1:
            # do the rest bytes w/o prefetch to avoid invalid addresses
            vmovdqa32      zmm0, [rsi+  0]
            vmovdqa32      zmm1, [rsi+ 64]
            add         rsi, rcx
            sub         r8, rcx
            vmovdqa32     [rdi+  0],  zmm0
            vmovdqa32     [rdi+ 64],  zmm1
            add         rdi, rcx
            cmp         r8, 128
            jge         short lrb64loop0big1

            # do the tail
            add         rdi, r8                     # set end of buffers
            add         rsi, r8
            mov         rdx, rdi
            mov         rcx, rsi
            and         rdx, 0xffffffffffffffc0     # aligned end pointers to 512-bit
            and         rcx, 0xffffffffffffffc0
#if !defined(PIC)
            jmp         qword ptr [r11+r8*8]
#else
            mov         r10, [r11+r8*8]
            lea         r11, [r10+r11]
            jmp         r11
#endif

#
# Main LRB loop -- src is element aligned, dst is vector aligned
#
            .balign     64
lrb64loopXA:
            cmp     r8, 16320
            jge     lrb64loopXbig

            .balign     64
lrb64loopX:
            # azv: we are here if size>=256 (r8)
            # rcx holds 128
            # Loop - copy 128 bytes and prefetch next 128

            # process 1st source
            vloadunpackld zmm0, [rsi+  0]
            vprefetch0  [rsi+  0+128]
            vloadunpackhd zmm0, [rsi+  0+64]
            vprefetch0  [rsi+  64+128]
            sub         r8, rcx                     # loop decrease index (mem size)

            # process 2nd source
            vloadunpackld zmm1, [rsi+ 64]
            vprefetch0  [rsi+ 64+128]
            vloadunpackhd zmm1, [rsi+ 64+64]
            vprefetch0  [rsi+ 128+128]
            add         rsi, rcx

            # process destinations
            vmovdqa32     [rdi+  0], zmm0
            vprefetche0  [rdi+  0+128]
            vmovdqa32     [rdi+ 64], zmm1
            vprefetche0  [rdi+ 64+128]

            # check end condition
            add         rdi, rcx
            cmp         r8, 256                     # check end condition
            jge         short lrb64loopX

            # azv: do the rest w/o prefetch
            vloadunpackld zmm0, [rsi+  0]
            vloadunpackhd zmm0, [rsi+  0+64]
            sub         r8, rcx
            vloadunpackld zmm1, [rsi+ 64]
            vloadunpackhd zmm1, [rsi+ 64+64]

            add         rsi, rcx
            vmovdqa32     [rdi+  0], zmm0
            vmovdqa32     [rdi+ 64], zmm1
            add         rdi, rcx

            # do the tail
            add         rdi, r8                     # set end of buffers
            add         rsi, r8
            mov         rdx, rdi
            mov         rcx, rsi
            and         rdx, 0xffffffffffffffc0     # aligned end pointers to 512-bit
            mov         r9, rdi                     # get unaligned tail size
            sub         r9, rdx
            sub         rcx, r9                     # adjust src end
#if !defined(PIC)
            jmp         qword ptr [r11+r8*8]
#else
            mov         r10, [r11+r8*8]
            lea         r11, [r10+r11]
            jmp         r11
#endif

            .balign     64
lrb64loopXbig:
            # we are here if size >= 16K-64
            # r8 holds length
            # rcx holds 128

            # process 1st source
            vloadunpackld zmm0, [rsi+  0]
            vprefetch0  [rsi+  0+256]
            vprefetch1  [rsi+  0+1280]
            vloadunpackhd zmm0, [rsi+  0+64]
            vprefetch0  [rsi+  64+256]
            vprefetch1  [rsi+  64+1280]
            sub         r8, rcx                     # loop decrease index (mem size)

            # process 2nd source
            vloadunpackld zmm1, [rsi+ 64]
            vprefetch0  [rsi+ 64+256]
            vprefetch1  [rsi+ 64+1280]
            vloadunpackhd zmm1, [rsi+ 64+64]
            vprefetch0  [rsi+ 128+256]
            vprefetch1  [rsi+ 128+1280]
            add         rsi, rcx

            # process destinations
            vmovdqa32     [rdi+  0], zmm0
            vprefetche0  [rdi+  0+256]
            vprefetche1  [rdi+  0+1280]
            vmovdqa32     [rdi+ 64], zmm1
            vprefetche0  [rdi+ 64+256]
            vprefetche1  [rdi+ 64+1280]

            # check end condition
            add         rdi, rcx
            cmp         r8, 1408                     # check end condition
            jge         short lrb64loopXbig

lrb64loopXbig1:
            # do the rest w/o prefetch to avoid invalid addresses
            vloadunpackld zmm0, [rsi+  0]
            vloadunpackhd zmm0, [rsi+  0+64]
            sub         r8, rcx
            vloadunpackld zmm1, [rsi+ 64]
            vloadunpackhd zmm1, [rsi+ 64+64]
            add         rsi, rcx
            vmovdqa32     [rdi+  0], zmm0
            vmovdqa32     [rdi+ 64], zmm1
            add         rdi, rcx
            cmp         r8, 128
            jge         short lrb64loopXbig1

            # do the tail
            add         rdi, r8                     # set end of buffers
            add         rsi, r8
            mov         rdx, rdi
            mov         rcx, rsi
            and         rdx, 0xffffffffffffffc0     # aligned end pointers to 512-bit
            mov         r9, rdi                     # get unaligned tail size
            sub         r9, rdx
            sub         rcx, r9                     # adjust src end
#if !defined(PIC)
            jmp         qword ptr [r11+r8*8]
#else
            mov         r10, [r11+r8*8]
            lea         r11, [r10+r11]
            jmp         r11
#endif

..L_knc_nt_move:
            # prepare for looping
            # If both the source and dest are aligned, then go to the both aligned logic.
            test        rsi, 63
            jnz         short ..L_knc_nt_loop_srcNA

            .balign     64
..L_knc_nt_loop_srcA:
            # r8 holds length
            # rcx holds 128

            # process sources first
            vmovdqa32   zmm0, [rsi+  0]
            vprefetch0  [rsi+128+0]
            vprefetch1  [rsi+1152+0]
            vmovdqa32   zmm1, [rsi+ 64]
            vprefetch0  [rsi+128+64]
            vprefetch1  [rsi+1152+64]

            # loop decrease indexes
            add         rsi, rcx
            sub         r8, rcx

            # process destinations using NGO stores

# The current KNC assembler (MPSS 2.1.3126-14) generates incorrect encoding
# for VMOVNRNGOAPS, so we encode it here

###         vmovnrngoaps     [rdi], zmm0
            .byte 0x62
            .byte 0xf1
            .byte 0x7b
            .byte 0x88
            .byte 0x29
            .byte 0x07

###         vmovnrngoaps     [rdi+64], zmm1
            .byte 0x62
            .byte 0xf1
            .byte 0x7b
            .byte 0x88
            .byte 0x29
            .byte 0x4f
            .byte 0x01

            # check end condition
            add         rdi, rcx
            cmp         r8, 128
            jge         short ..L_knc_nt_loop_srcA

            # do sfence
            lock addq [rsp], 0

            # do the tail
            lea         r11, TailAxDx[rip]
            add         rdi, r8                     # set end of buffers
            add         rsi, r8
            mov         rdx, rdi
            mov         rcx, rsi
            and         rdx, 0xffffffffffffffc0     # aligned end pointers to 512-bit
            mov         r9, rdi                     # get unaligned tail size
            sub         r9, rdx
            sub         rcx, r9                     # adjust src end
#if !defined(PIC)
            jmp         qword ptr [r11+r8*8]
#else
            mov         r10, [r11+r8*8]
            lea         r11, [r10+r11]
            jmp         r11
#endif

#
# Main LRB loop -- src is element aligned, dst is vector aligned
#
            .balign     64
..L_knc_nt_loop_srcNA:
            # r8 holds length
            # rcx holds 128

            # process 1st source
            vloadunpackld zmm0, [rsi+  0]
            vprefetch0  [rsi+  0+256]
            vprefetch1  [rsi+  0+1280]
            vloadunpackhd zmm0, [rsi+  0+64]
            vprefetch0  [rsi+  64+256]
            vprefetch1  [rsi+  64+1280]
            sub         r8, rcx                     # loop decrease index (mem size)

            # process 2nd source
            vloadunpackld zmm1, [rsi+ 64]
            vprefetch0  [rsi+ 64+256]
            vprefetch1  [rsi+ 64+1280]
            vloadunpackhd zmm1, [rsi+ 64+64]
            vprefetch0  [rsi+ 128+256]
            vprefetch1  [rsi+ 128+1280]
            add         rsi, rcx

            # process destinations using NGO stores

# The current KNC assembler (MPSS 2.1.3126-14) generates incorrect encoding
# for VMOVNRNGOAPS, so we encode it here

###         vmovnrngoaps     [rdi], zmm0
            .byte 0x62
            .byte 0xf1
            .byte 0x7b
            .byte 0x88
            .byte 0x29
            .byte 0x07

###         vmovnrngoaps     [rdi+64], zmm1
            .byte 0x62
            .byte 0xf1
            .byte 0x7b
            .byte 0x88
            .byte 0x29
            .byte 0x4f
            .byte 0x01

            # check end condition
            add         rdi, rcx
            cmp         r8, 128                     # check end condition
            jge         short ..L_knc_nt_loop_srcNA

            # do sfence
            lock addq [rsp], 0

            # do the tail
            lea         r11, TailUxDx[rip]
            add         rdi, r8                     # set end of buffers
            add         rsi, r8
            mov         rdx, rdi
            mov         rcx, rsi
            and         rdx, 0xffffffffffffffc0     # aligned end pointers to 512-bit
            mov         r9, rdi                     # get unaligned tail size
            sub         r9, rdx
            sub         rcx, r9                     # adjust src end
#if !defined(PIC)
            jmp         qword ptr [r11+r8*8]
#else
            mov         r10, [r11+r8*8]
            lea         r11, [r10+r11]
            jmp         r11
#endif

#
# src is not 4-byte aligned
# no advantage of realigning dst ptr to 64 bytes.
#
            .balign     16
lrb_unaligned_src:
            # src is not 4 byte (element) aligned
            # anyway, short arrays do not go for lrb version
            lea         r11, fwdPxQx[rip]           # tail table

            # check against THRESHOLD_BIG(64) + 48. Adding 48 here in order to
            # avoid accessing invalid page by vloadunpackhd when loading
            # last 16 bytes - see comments in 'lrb16_loop' entry.
            cmp         r8, 112
            jle         short byte8_tail

            # Go to 16 byte or 32 byte moves (64 byte moves are not possible).
            # If src is not 2-byte aligned then go to 16 byte moves;
            # otherwise, go to 32 byte moves.
            cmp         rcx, 2
            jne         short lrb16_loop

            # go for 32 byte moves only if array is long enough.
            # check against THRESHOLD_BIG(128) + 32. Adding 32 here in order to
            # avoid accessing invalid page by vloadunpackhd when loading
            # last 32 bytes - see comments in 'lrb32_loop' entry.
            cmp         r8, 160
            jg          short lrb32_loop

byte8_tail:
            # use table to copy tail with GPRs
            add         rdi, r8
            add         rsi, r8
#if !defined(PIC)
            jmp         qword ptr [r11+r8*8]
#else
            mov         r10, [r11+r8*8]
            lea         r11, [r10+r11]
            jmp         r11
#endif

#
# Main LRB loop -- 32 bytes moves
#
            .balign     64
lrb32_loop:
            vloadunpackld zmm0, [rsi+ 0]{uint16}
            vloadunpackhd zmm0, [rsi+ 0+64]{uint16}
            vloadunpackld zmm1, [rsi+32]{uint16}
            vloadunpackhd zmm1, [rsi+32+64]{uint16}
            vloadunpackld zmm2, [rsi+64]{uint16}
            vloadunpackhd zmm2, [rsi+64+64]{uint16}
            vloadunpackld zmm3, [rsi+96]{uint16}
            vloadunpackhd zmm3, [rsi+96+64]{uint16}

            # store + loop control
            vmovdqa32   [rdi+ 0], zmm0{uint16}
            vmovdqa32   [rdi+32], zmm1{uint16}
            lea         rsi, [rsi+128]
            vmovdqa32   [rdi+64], zmm2{uint16}
            vmovdqa32   [rdi+96], zmm3{uint16}
            lea         rdi, [rdi+128]

            # loop decrease index (mem size)
            sub         r8, 128

            # Though we copy 128 bytes at each iteration, we stop iterations
            # when the mem size is less than 160. This is because the last
            # load (vloadunpackhd, see above) is accessing src + 96 + 64,
            # and this address must be valid.
            cmp         r8, 160
            jge         short lrb32_loop

            # use table to copy tail with GPRs
            add         rdi, r8
            add         rsi, r8
#if !defined(PIC)
            jmp         qword ptr [r11+r8*8]
#else
            mov         r10, [r11+r8*8]
            lea         r11, [r10+r11]
            jmp         r11
#endif

#
# Main LRB loop -- 16 bytes moves
#
            .balign     64
lrb16_loop:
            vloadunpackld zmm0, [rsi+ 0]{uint8}
            vloadunpackhd zmm0, [rsi+ 0+64]{uint8}
            vloadunpackld zmm1, [rsi+16]{uint8}
            vloadunpackhd zmm1, [rsi+16+64]{uint8}
            vloadunpackld zmm2, [rsi+32]{uint8}
            vloadunpackhd zmm2, [rsi+32+64]{uint8}
            vloadunpackld zmm3, [rsi+48]{uint8}
            vloadunpackhd zmm3, [rsi+48+64]{uint8}
            lea         rsi, [rsi+64]

            # store + loop control
            vmovdqa32     [rdi+ 0], zmm0{uint8}
            vmovdqa32     [rdi+16], zmm1{uint8}
            vmovdqa32     [rdi+32], zmm2{uint8}
            vmovdqa32     [rdi+48], zmm3{uint8}
            lea           rdi, [rdi+64]

            # loop decrease index (mem size)
            sub         r8, 64

            # Though we copy 64 bytes at each iteration, we stop iterations
            # when the mem size is less than 112. This is because the last
            # load (vloadunpackhd, see above) is accessing src + 48 + 64,
            # and this address must be valid.
            cmp         r8, 112
            jge         short lrb16_loop

            # use table to copy tail with GPRs
            add         rdi, r8
            add         rsi, r8
#if !defined(PIC)
            jmp         qword ptr [r11+r8*8]
#else
            mov         r10, [r11+r8*8]
            lea         r11, [r10+r11]
            jmp         r11
#endif

#
# LRB move buffer tail (src is 64-byte aligned)
#
            .balign     16
#if !defined(PIC)
TailAxDx:   .quad       TA0Q0,TA1Q0,TA2Q0,TA3Q0,TA0Q1,TA1Q1,TA2Q1,TA3Q1
            .quad       TA0Q1,TA1Q1,TA2Q1,TA3Q1,TA0Q1,TA1Q1,TA2Q1,TA3Q1
            .quad       TA0Q1,TA1Q1,TA2Q1,TA3Q1,TA0Q1,TA1Q1,TA2Q1,TA3Q1
            .quad       TA0Q1,TA1Q1,TA2Q1,TA3Q1,TA0Q1,TA1Q1,TA2Q1,TA3Q1
            .quad       TA0Q1,TA1Q1,TA2Q1,TA3Q1,TA0Q1,TA1Q1,TA2Q1,TA3Q1
            .quad       TA0Q1,TA1Q1,TA2Q1,TA3Q1,TA0Q1,TA1Q1,TA2Q1,TA3Q1
            .quad       TA0Q1,TA1Q1,TA2Q1,TA3Q1,TA0Q1,TA1Q1,TA2Q1,TA3Q1
            .quad       TA0Q1,TA1Q1,TA2Q1,TA3Q1,TA0Q1,TA1Q1,TA2Q1,TA3Q1     # up to 64 bytes
            .quad       TA0Q2,TA1Q2,TA2Q2,TA3Q2,TA0Q2,TA1Q2,TA2Q2,TA3Q2
            .quad       TA0Q2,TA1Q2,TA2Q2,TA3Q2,TA0Q2,TA1Q2,TA2Q2,TA3Q2
            .quad       TA0Q2,TA1Q2,TA2Q2,TA3Q2,TA0Q2,TA1Q2,TA2Q2,TA3Q2
            .quad       TA0Q2,TA1Q2,TA2Q2,TA3Q2,TA0Q2,TA1Q2,TA2Q2,TA3Q2
            .quad       TA0Q2,TA1Q2,TA2Q2,TA3Q2,TA0Q2,TA1Q2,TA2Q2,TA3Q2
            .quad       TA0Q2,TA1Q2,TA2Q2,TA3Q2,TA0Q2,TA1Q2,TA2Q2,TA3Q2
            .quad       TA0Q2,TA1Q2,TA2Q2,TA3Q2,TA0Q2,TA1Q2,TA2Q2,TA3Q2
            .quad       TA0Q2,TA1Q2,TA2Q2,TA3Q2,TA0Q2,TA1Q2,TA2Q2,TA3Q2     # up to 128 bytes
            .quad       TA0Q3,TA1Q3,TA2Q3,TA3Q3,TA0Q3,TA1Q3,TA2Q3,TA3Q3
            .quad       TA0Q3,TA1Q3,TA2Q3,TA3Q3,TA0Q3,TA1Q3,TA2Q3,TA3Q3
            .quad       TA0Q3,TA1Q3,TA2Q3,TA3Q3,TA0Q3,TA1Q3,TA2Q3,TA3Q3
            .quad       TA0Q3,TA1Q3,TA2Q3,TA3Q3,TA0Q3,TA1Q3,TA2Q3,TA3Q3
            .quad       TA0Q3,TA1Q3,TA2Q3,TA3Q3,TA0Q3,TA1Q3,TA2Q3,TA3Q3
            .quad       TA0Q3,TA1Q3,TA2Q3,TA3Q3,TA0Q3,TA1Q3,TA2Q3,TA3Q3
            .quad       TA0Q3,TA1Q3,TA2Q3,TA3Q3,TA0Q3,TA1Q3,TA2Q3,TA3Q3
            .quad       TA0Q3,TA1Q3,TA2Q3,TA3Q3,TA0Q3,TA1Q3,TA2Q3,TA3Q3     # up to 192 bytes
            .quad       TA0Q4,TA1Q4,TA2Q4,TA3Q4,TA0Q4,TA1Q4,TA2Q4,TA3Q4
            .quad       TA0Q4,TA1Q4,TA2Q4,TA3Q4,TA0Q4,TA1Q4,TA2Q4,TA3Q4
            .quad       TA0Q4,TA1Q4,TA2Q4,TA3Q4,TA0Q4,TA1Q4,TA2Q4,TA3Q4
            .quad       TA0Q4,TA1Q4,TA2Q4,TA3Q4,TA0Q4,TA1Q4,TA2Q4,TA3Q4
            .quad       TA0Q4,TA1Q4,TA2Q4,TA3Q4,TA0Q4,TA1Q4,TA2Q4,TA3Q4
            .quad       TA0Q4,TA1Q4,TA2Q4,TA3Q4,TA0Q4,TA1Q4,TA2Q4,TA3Q4
            .quad       TA0Q4,TA1Q4,TA2Q4,TA3Q4,TA0Q4,TA1Q4,TA2Q4,TA3Q4
            .quad       TA0Q4,TA1Q4,TA2Q4,TA3Q4,TA0Q4,TA1Q4,TA2Q4,TA3Q4     # up to 256 bytes
            .quad       TA0Q5,TA1Q5,TA2Q5,TA3Q5,TA0Q5,TA1Q5,TA2Q5,TA3Q5
            .quad       TA0Q5,TA1Q5,TA2Q5,TA3Q5,TA0Q5,TA1Q5,TA2Q5,TA3Q5
            .quad       TA0Q5,TA1Q5,TA2Q5,TA3Q5,TA0Q5,TA1Q5,TA2Q5,TA3Q5
            .quad       TA0Q5,TA1Q5,TA2Q5,TA3Q5,TA0Q5,TA1Q5,TA2Q5,TA3Q5
            .quad       TA0Q5,TA1Q5,TA2Q5,TA3Q5,TA0Q5,TA1Q5,TA2Q5,TA3Q5
            .quad       TA0Q5,TA1Q5,TA2Q5,TA3Q5,TA0Q5,TA1Q5,TA2Q5,TA3Q5
            .quad       TA0Q5,TA1Q5,TA2Q5,TA3Q5,TA0Q5,TA1Q5,TA2Q5,TA3Q5
            .quad       TA0Q5,TA1Q5,TA2Q5,TA3Q5,TA0Q5,TA1Q5,TA2Q5,TA3Q5     # up to 320 bytes
#else
TailAxDx:   .quad       TA0Q0-TailAxDx
            .quad       TA1Q0-TailAxDx
            .quad       TA2Q0-TailAxDx
            .quad       TA3Q0-TailAxDx
            .quad       TA0Q1-TailAxDx
            .quad       TA1Q1-TailAxDx
            .quad       TA2Q1-TailAxDx
            .quad       TA3Q1-TailAxDx

            .quad       TA0Q1-TailAxDx
            .quad       TA1Q1-TailAxDx
            .quad       TA2Q1-TailAxDx
            .quad       TA3Q1-TailAxDx
            .quad       TA0Q1-TailAxDx
            .quad       TA1Q1-TailAxDx
            .quad       TA2Q1-TailAxDx
            .quad       TA3Q1-TailAxDx
            .quad       TA0Q1-TailAxDx
            .quad       TA1Q1-TailAxDx
            .quad       TA2Q1-TailAxDx
            .quad       TA3Q1-TailAxDx
            .quad       TA0Q1-TailAxDx
            .quad       TA1Q1-TailAxDx
            .quad       TA2Q1-TailAxDx
            .quad       TA3Q1-TailAxDx

            .quad       TA0Q1-TailAxDx
            .quad       TA1Q1-TailAxDx
            .quad       TA2Q1-TailAxDx
            .quad       TA3Q1-TailAxDx
            .quad       TA0Q1-TailAxDx
            .quad       TA1Q1-TailAxDx
            .quad       TA2Q1-TailAxDx
            .quad       TA3Q1-TailAxDx

            .quad       TA0Q1-TailAxDx
            .quad       TA1Q1-TailAxDx
            .quad       TA2Q1-TailAxDx
            .quad       TA3Q1-TailAxDx
            .quad       TA0Q1-TailAxDx
            .quad       TA1Q1-TailAxDx
            .quad       TA2Q1-TailAxDx
            .quad       TA3Q1-TailAxDx

            .quad       TA0Q1-TailAxDx
            .quad       TA1Q1-TailAxDx
            .quad       TA2Q1-TailAxDx
            .quad       TA3Q1-TailAxDx
            .quad       TA0Q1-TailAxDx
            .quad       TA1Q1-TailAxDx
            .quad       TA2Q1-TailAxDx
            .quad       TA3Q1-TailAxDx

            .quad       TA0Q1-TailAxDx
            .quad       TA1Q1-TailAxDx
            .quad       TA2Q1-TailAxDx
            .quad       TA3Q1-TailAxDx
            .quad       TA0Q1-TailAxDx
            .quad       TA1Q1-TailAxDx
            .quad       TA2Q1-TailAxDx
            .quad       TA3Q1-TailAxDx

      # up to 64 bytes
            .quad       TA0Q1-TailAxDx
            .quad       TA1Q1-TailAxDx
            .quad       TA2Q1-TailAxDx
            .quad       TA3Q1-TailAxDx
            .quad       TA0Q1-TailAxDx
            .quad       TA1Q1-TailAxDx
            .quad       TA2Q1-TailAxDx
            .quad       TA3Q1-TailAxDx     # up to 64 bytes

            .quad       TA0Q2-TailAxDx
            .quad       TA1Q2-TailAxDx
            .quad       TA2Q2-TailAxDx
            .quad       TA3Q2-TailAxDx
            .quad       TA0Q2-TailAxDx
            .quad       TA1Q2-TailAxDx
            .quad       TA2Q2-TailAxDx
            .quad       TA3Q2-TailAxDx

            .quad       TA0Q2-TailAxDx
            .quad       TA1Q2-TailAxDx
            .quad       TA2Q2-TailAxDx
            .quad       TA3Q2-TailAxDx
            .quad       TA0Q2-TailAxDx
            .quad       TA1Q2-TailAxDx
            .quad       TA2Q2-TailAxDx
            .quad       TA3Q2-TailAxDx

            .quad       TA0Q2-TailAxDx
            .quad       TA1Q2-TailAxDx
            .quad       TA2Q2-TailAxDx
            .quad       TA3Q2-TailAxDx
            .quad       TA0Q2-TailAxDx
            .quad       TA1Q2-TailAxDx
            .quad       TA2Q2-TailAxDx
            .quad       TA3Q2-TailAxDx

            .quad       TA0Q2-TailAxDx
            .quad       TA1Q2-TailAxDx
            .quad       TA2Q2-TailAxDx
            .quad       TA3Q2-TailAxDx
            .quad       TA0Q2-TailAxDx
            .quad       TA1Q2-TailAxDx
            .quad       TA2Q2-TailAxDx
            .quad       TA3Q2-TailAxDx

            .quad       TA0Q2-TailAxDx
            .quad       TA1Q2-TailAxDx
            .quad       TA2Q2-TailAxDx
            .quad       TA3Q2-TailAxDx
            .quad       TA0Q2-TailAxDx
            .quad       TA1Q2-TailAxDx
            .quad       TA2Q2-TailAxDx
            .quad       TA3Q2-TailAxDx

            .quad       TA0Q2-TailAxDx
            .quad       TA1Q2-TailAxDx
            .quad       TA2Q2-TailAxDx
            .quad       TA3Q2-TailAxDx
            .quad       TA0Q2-TailAxDx
            .quad       TA1Q2-TailAxDx
            .quad       TA2Q2-TailAxDx
            .quad       TA3Q2-TailAxDx

            .quad       TA0Q2-TailAxDx
            .quad       TA1Q2-TailAxDx
            .quad       TA2Q2-TailAxDx
            .quad       TA3Q2-TailAxDx
            .quad       TA0Q2-TailAxDx
            .quad       TA1Q2-TailAxDx
            .quad       TA2Q2-TailAxDx
            .quad       TA3Q2-TailAxDx

            .quad       TA0Q2-TailAxDx
            .quad       TA1Q2-TailAxDx
            .quad       TA2Q2-TailAxDx
            .quad       TA3Q2-TailAxDx
            .quad       TA0Q2-TailAxDx
            .quad       TA1Q2-TailAxDx
            .quad       TA2Q2-TailAxDx
            .quad       TA3Q2-TailAxDx     # up to 128 bytes

            .quad       TA0Q3-TailAxDx
            .quad       TA1Q3-TailAxDx
            .quad       TA2Q3-TailAxDx
            .quad       TA3Q3-TailAxDx
            .quad       TA0Q3-TailAxDx
            .quad       TA1Q3-TailAxDx
            .quad       TA2Q3-TailAxDx
            .quad       TA3Q3-TailAxDx

            .quad       TA0Q3-TailAxDx
            .quad       TA1Q3-TailAxDx
            .quad       TA2Q3-TailAxDx
            .quad       TA3Q3-TailAxDx
            .quad       TA0Q3-TailAxDx
            .quad       TA1Q3-TailAxDx
            .quad       TA2Q3-TailAxDx
            .quad       TA3Q3-TailAxDx

            .quad       TA0Q3-TailAxDx
            .quad       TA1Q3-TailAxDx
            .quad       TA2Q3-TailAxDx
            .quad       TA3Q3-TailAxDx
            .quad       TA0Q3-TailAxDx
            .quad       TA1Q3-TailAxDx
            .quad       TA2Q3-TailAxDx
            .quad       TA3Q3-TailAxDx

            .quad       TA0Q3-TailAxDx
            .quad       TA1Q3-TailAxDx
            .quad       TA2Q3-TailAxDx
            .quad       TA3Q3-TailAxDx
            .quad       TA0Q3-TailAxDx
            .quad       TA1Q3-TailAxDx
            .quad       TA2Q3-TailAxDx
            .quad       TA3Q3-TailAxDx

            .quad       TA0Q3-TailAxDx
            .quad       TA1Q3-TailAxDx
            .quad       TA2Q3-TailAxDx
            .quad       TA3Q3-TailAxDx
            .quad       TA0Q3-TailAxDx
            .quad       TA1Q3-TailAxDx
            .quad       TA2Q3-TailAxDx
            .quad       TA3Q3-TailAxDx

            .quad       TA0Q3-TailAxDx
            .quad       TA1Q3-TailAxDx
            .quad       TA2Q3-TailAxDx
            .quad       TA3Q3-TailAxDx
            .quad       TA0Q3-TailAxDx
            .quad       TA1Q3-TailAxDx
            .quad       TA2Q3-TailAxDx
            .quad       TA3Q3-TailAxDx

            .quad       TA0Q3-TailAxDx
            .quad       TA1Q3-TailAxDx
            .quad       TA2Q3-TailAxDx
            .quad       TA3Q3-TailAxDx
            .quad       TA0Q3-TailAxDx
            .quad       TA1Q3-TailAxDx
            .quad       TA2Q3-TailAxDx
            .quad       TA3Q3-TailAxDx

            .quad       TA0Q3-TailAxDx
            .quad       TA1Q3-TailAxDx
            .quad       TA2Q3-TailAxDx
            .quad       TA3Q3-TailAxDx
            .quad       TA0Q3-TailAxDx
            .quad       TA1Q3-TailAxDx
            .quad       TA2Q3-TailAxDx
            .quad       TA3Q3-TailAxDx     # up to 192 bytes

            .quad       TA0Q4-TailAxDx
            .quad       TA1Q4-TailAxDx
            .quad       TA2Q4-TailAxDx
            .quad       TA3Q4-TailAxDx
            .quad       TA0Q4-TailAxDx
            .quad       TA1Q4-TailAxDx
            .quad       TA2Q4-TailAxDx
            .quad       TA3Q4-TailAxDx

            .quad       TA0Q4-TailAxDx
            .quad       TA1Q4-TailAxDx
            .quad       TA2Q4-TailAxDx
            .quad       TA3Q4-TailAxDx
            .quad       TA0Q4-TailAxDx
            .quad       TA1Q4-TailAxDx
            .quad       TA2Q4-TailAxDx
            .quad       TA3Q4-TailAxDx

            .quad       TA0Q4-TailAxDx
            .quad       TA1Q4-TailAxDx
            .quad       TA2Q4-TailAxDx
            .quad       TA3Q4-TailAxDx
            .quad       TA0Q4-TailAxDx
            .quad       TA1Q4-TailAxDx
            .quad       TA2Q4-TailAxDx
            .quad       TA3Q4-TailAxDx

            .quad       TA0Q4-TailAxDx
            .quad       TA1Q4-TailAxDx
            .quad       TA2Q4-TailAxDx
            .quad       TA3Q4-TailAxDx
            .quad       TA0Q4-TailAxDx
            .quad       TA1Q4-TailAxDx
            .quad       TA2Q4-TailAxDx
            .quad       TA3Q4-TailAxDx

            .quad       TA0Q4-TailAxDx
            .quad       TA1Q4-TailAxDx
            .quad       TA2Q4-TailAxDx
            .quad       TA3Q4-TailAxDx
            .quad       TA0Q4-TailAxDx
            .quad       TA1Q4-TailAxDx
            .quad       TA2Q4-TailAxDx
            .quad       TA3Q4-TailAxDx

            .quad       TA0Q4-TailAxDx
            .quad       TA1Q4-TailAxDx
            .quad       TA2Q4-TailAxDx
            .quad       TA3Q4-TailAxDx
            .quad       TA0Q4-TailAxDx
            .quad       TA1Q4-TailAxDx
            .quad       TA2Q4-TailAxDx
            .quad       TA3Q4-TailAxDx

            .quad       TA0Q4-TailAxDx
            .quad       TA1Q4-TailAxDx
            .quad       TA2Q4-TailAxDx
            .quad       TA3Q4-TailAxDx
            .quad       TA0Q4-TailAxDx
            .quad       TA1Q4-TailAxDx
            .quad       TA2Q4-TailAxDx
            .quad       TA3Q4-TailAxDx

            .quad       TA0Q4-TailAxDx
            .quad       TA1Q4-TailAxDx
            .quad       TA2Q4-TailAxDx
            .quad       TA3Q4-TailAxDx
            .quad       TA0Q4-TailAxDx
            .quad       TA1Q4-TailAxDx
            .quad       TA2Q4-TailAxDx
            .quad       TA3Q4-TailAxDx     # up to 256 bytes

            .quad       TA0Q5-TailAxDx
            .quad       TA1Q5-TailAxDx
            .quad       TA2Q5-TailAxDx
            .quad       TA3Q5-TailAxDx
            .quad       TA0Q5-TailAxDx
            .quad       TA1Q5-TailAxDx
            .quad       TA2Q5-TailAxDx
            .quad       TA3Q5-TailAxDx

            .quad       TA0Q5-TailAxDx
            .quad       TA1Q5-TailAxDx
            .quad       TA2Q5-TailAxDx
            .quad       TA3Q5-TailAxDx
            .quad       TA0Q5-TailAxDx
            .quad       TA1Q5-TailAxDx
            .quad       TA2Q5-TailAxDx
            .quad       TA3Q5-TailAxDx

            .quad       TA0Q5-TailAxDx
            .quad       TA1Q5-TailAxDx
            .quad       TA2Q5-TailAxDx
            .quad       TA3Q5-TailAxDx
            .quad       TA0Q5-TailAxDx
            .quad       TA1Q5-TailAxDx
            .quad       TA2Q5-TailAxDx
            .quad       TA3Q5-TailAxDx

            .quad       TA0Q5-TailAxDx
            .quad       TA1Q5-TailAxDx
            .quad       TA2Q5-TailAxDx
            .quad       TA3Q5-TailAxDx
            .quad       TA0Q5-TailAxDx
            .quad       TA1Q5-TailAxDx
            .quad       TA2Q5-TailAxDx
            .quad       TA3Q5-TailAxDx

            .quad       TA0Q5-TailAxDx
            .quad       TA1Q5-TailAxDx
            .quad       TA2Q5-TailAxDx
            .quad       TA3Q5-TailAxDx
            .quad       TA0Q5-TailAxDx
            .quad       TA1Q5-TailAxDx
            .quad       TA2Q5-TailAxDx
            .quad       TA3Q5-TailAxDx

            .quad       TA0Q5-TailAxDx
            .quad       TA1Q5-TailAxDx
            .quad       TA2Q5-TailAxDx
            .quad       TA3Q5-TailAxDx
            .quad       TA0Q5-TailAxDx
            .quad       TA1Q5-TailAxDx
            .quad       TA2Q5-TailAxDx
            .quad       TA3Q5-TailAxDx

            .quad       TA0Q5-TailAxDx
            .quad       TA1Q5-TailAxDx
            .quad       TA2Q5-TailAxDx
            .quad       TA3Q5-TailAxDx
            .quad       TA0Q5-TailAxDx
            .quad       TA1Q5-TailAxDx
            .quad       TA2Q5-TailAxDx
            .quad       TA3Q5-TailAxDx

            .quad       TA0Q5-TailAxDx
            .quad       TA1Q5-TailAxDx
            .quad       TA2Q5-TailAxDx
            .quad       TA3Q5-TailAxDx
            .quad       TA0Q5-TailAxDx
            .quad       TA1Q5-TailAxDx
            .quad       TA2Q5-TailAxDx
            .quad       TA3Q5-TailAxDx     # up to 320 bytes
#endif

# rsi = end of src buffer
# rcx = 64-byte aligned end of src buffer (rcx <= rsi)
# rdi = end of dst buffer
# rdx = 64-byte aligned end of dst buffer (rdx <= rdi)

            .balign     16
TA0Q5:      vmovdqa32      zmm0, [rcx-256]
            vmovdqa32     [rdx-256], zmm0
TA0Q4:      vmovdqa32      zmm0, [rcx-192]
            vmovdqa32     [rdx-192], zmm0
TA0Q3:      vmovdqa32      zmm0, [rcx-128]
            vmovdqa32     [rdx-128], zmm0
TA0Q2:      vmovdqa32      zmm0, [rcx- 64]
            vmovdqa32     [rdx- 64], zmm0
TA0Q1:      vloadunpackhd zmm0, [rsi-4]
            vpackstorehd [rdi-4], zmm0
            mov         r9w, word  ptr[rsi-4]
            mov         word  ptr[rdi-4], r9w
            mov         r9w, word  ptr[rsi-2]
            mov         word  ptr[rdi-2], r9w
TA0Q0:      ret

TA1Q5:      vmovdqa32      zmm0, [rcx-256]
            vmovdqa32     [rdx-256], zmm0
TA1Q4:      vmovdqa32      zmm0, [rcx-192]
            vmovdqa32     [rdx-192], zmm0
TA1Q3:      vmovdqa32      zmm0, [rcx-128]
            vmovdqa32     [rdx-128], zmm0
TA1Q2:      vmovdqa32      zmm0, [rcx- 64]
            vmovdqa32     [rdx- 64], zmm0
TA1Q1:      vloadunpackhd zmm0, [rsi-1]
            vpackstorehd [rdi-1], zmm0
TA1Q0:      mov         r9b, byte  ptr[rsi-1]
            mov         byte  ptr[rdi-1], r9b
            ret

TA2Q5:      vmovdqa32      zmm0, [rcx-256]
            vmovdqa32     [rdx-256], zmm0
TA2Q4:      vmovdqa32      zmm0, [rcx-192]
            vmovdqa32     [rdx-192], zmm0
TA2Q3:      vmovdqa32      zmm0, [rcx-128]
            vmovdqa32     [rdx-128], zmm0
TA2Q2:      vmovdqa32      zmm0, [rcx- 64]
            vmovdqa32     [rdx- 64], zmm0
TA2Q1:      vloadunpackhd zmm0, [rsi-2]
            vpackstorehd [rdi-2], zmm0
TA2Q0:      mov         r9w, word  ptr[rsi-2]
            mov         word  ptr[rdi-2], r9w
            ret

TA3Q5:      vmovdqa32      zmm0, [rcx-256]
            vmovdqa32     [rdx-256], zmm0
TA3Q4:      vmovdqa32      zmm0, [rcx-192]
            vmovdqa32     [rdx-192], zmm0
TA3Q3:      vmovdqa32      zmm0, [rcx-128]
            vmovdqa32     [rdx-128], zmm0
TA3Q2:      vmovdqa32      zmm0, [rcx- 64]
            vmovdqa32     [rdx- 64], zmm0
TA3Q1:      vloadunpackhd zmm0, [rsi-3]
            vpackstorehd [rdi-3], zmm0
TA3Q0:      mov         r9w, word  ptr[rsi-3]
            mov         word  ptr[rdi-3], r9w
            mov         r9b, byte  ptr[rsi-1]
            mov         byte  ptr[rdi-1], r9b
            ret

#
# LRB move buffer tail (src is NOT 64-byte aligned)
#
            .balign     16
#if !defined(PIC)
TailUxDx:   .quad       TU0Q0,TU1Q0,TU2Q0,TU3Q0,TU0Q1,TU1Q1,TU2Q1,TU3Q1
            .quad       TU0Q1,TU1Q1,TU2Q1,TU3Q1,TU0Q1,TU1Q1,TU2Q1,TU3Q1
            .quad       TU0Q1,TU1Q1,TU2Q1,TU3Q1,TU0Q1,TU1Q1,TU2Q1,TU3Q1
            .quad       TU0Q1,TU1Q1,TU2Q1,TU3Q1,TU0Q1,TU1Q1,TU2Q1,TU3Q1
            .quad       TU0Q1,TU1Q1,TU2Q1,TU3Q1,TU0Q1,TU1Q1,TU2Q1,TU3Q1
            .quad       TU0Q1,TU1Q1,TU2Q1,TU3Q1,TU0Q1,TU1Q1,TU2Q1,TU3Q1
            .quad       TU0Q1,TU1Q1,TU2Q1,TU3Q1,TU0Q1,TU1Q1,TU2Q1,TU3Q1
            .quad       TU0Q1,TU1Q1,TU2Q1,TU3Q1,TU0Q1,TU1Q1,TU2Q1,TU3Q1     # up to 64 bytes
            .quad       TU0Q2,TU1Q2,TU2Q2,TU3Q2,TU0Q2,TU1Q2,TU2Q2,TU3Q2
            .quad       TU0Q2,TU1Q2,TU2Q2,TU3Q2,TU0Q2,TU1Q2,TU2Q2,TU3Q2
            .quad       TU0Q2,TU1Q2,TU2Q2,TU3Q2,TU0Q2,TU1Q2,TU2Q2,TU3Q2
            .quad       TU0Q2,TU1Q2,TU2Q2,TU3Q2,TU0Q2,TU1Q2,TU2Q2,TU3Q2
            .quad       TU0Q2,TU1Q2,TU2Q2,TU3Q2,TU0Q2,TU1Q2,TU2Q2,TU3Q2
            .quad       TU0Q2,TU1Q2,TU2Q2,TU3Q2,TU0Q2,TU1Q2,TU2Q2,TU3Q2
            .quad       TU0Q2,TU1Q2,TU2Q2,TU3Q2,TU0Q2,TU1Q2,TU2Q2,TU3Q2
            .quad       TU0Q2,TU1Q2,TU2Q2,TU3Q2,TU0Q2,TU1Q2,TU2Q2,TU3Q2     # up to 128 bytes
            .quad       TU0Q3,TU1Q3,TU2Q3,TU3Q3,TU0Q3,TU1Q3,TU2Q3,TU3Q3
            .quad       TU0Q3,TU1Q3,TU2Q3,TU3Q3,TU0Q3,TU1Q3,TU2Q3,TU3Q3
            .quad       TU0Q3,TU1Q3,TU2Q3,TU3Q3,TU0Q3,TU1Q3,TU2Q3,TU3Q3
            .quad       TU0Q3,TU1Q3,TU2Q3,TU3Q3,TU0Q3,TU1Q3,TU2Q3,TU3Q3
            .quad       TU0Q3,TU1Q3,TU2Q3,TU3Q3,TU0Q3,TU1Q3,TU2Q3,TU3Q3
            .quad       TU0Q3,TU1Q3,TU2Q3,TU3Q3,TU0Q3,TU1Q3,TU2Q3,TU3Q3
            .quad       TU0Q3,TU1Q3,TU2Q3,TU3Q3,TU0Q3,TU1Q3,TU2Q3,TU3Q3
            .quad       TU0Q3,TU1Q3,TU2Q3,TU3Q3,TU0Q3,TU1Q3,TU2Q3,TU3Q3     # up to 192 bytes
            .quad       TU0Q4,TU1Q4,TU2Q4,TU3Q4,TU0Q4,TU1Q4,TU2Q4,TU3Q4
            .quad       TU0Q4,TU1Q4,TU2Q4,TU3Q4,TU0Q4,TU1Q4,TU2Q4,TU3Q4
            .quad       TU0Q4,TU1Q4,TU2Q4,TU3Q4,TU0Q4,TU1Q4,TU2Q4,TU3Q4
            .quad       TU0Q4,TU1Q4,TU2Q4,TU3Q4,TU0Q4,TU1Q4,TU2Q4,TU3Q4
            .quad       TU0Q4,TU1Q4,TU2Q4,TU3Q4,TU0Q4,TU1Q4,TU2Q4,TU3Q4
            .quad       TU0Q4,TU1Q4,TU2Q4,TU3Q4,TU0Q4,TU1Q4,TU2Q4,TU3Q4
            .quad       TU0Q4,TU1Q4,TU2Q4,TU3Q4,TU0Q4,TU1Q4,TU2Q4,TU3Q4
            .quad       TU0Q4,TU1Q4,TU2Q4,TU3Q4,TU0Q4,TU1Q4,TU2Q4,TU3Q4     # up to 256 bytes
            .quad       TU0Q5,TU1Q5,TU2Q5,TU3Q5,TU0Q5,TU1Q5,TU2Q5,TU3Q5
            .quad       TU0Q5,TU1Q5,TU2Q5,TU3Q5,TU0Q5,TU1Q5,TU2Q5,TU3Q5
            .quad       TU0Q5,TU1Q5,TU2Q5,TU3Q5,TU0Q5,TU1Q5,TU2Q5,TU3Q5
            .quad       TU0Q5,TU1Q5,TU2Q5,TU3Q5,TU0Q5,TU1Q5,TU2Q5,TU3Q5
            .quad       TU0Q5,TU1Q5,TU2Q5,TU3Q5,TU0Q5,TU1Q5,TU2Q5,TU3Q5
            .quad       TU0Q5,TU1Q5,TU2Q5,TU3Q5,TU0Q5,TU1Q5,TU2Q5,TU3Q5
            .quad       TU0Q5,TU1Q5,TU2Q5,TU3Q5,TU0Q5,TU1Q5,TU2Q5,TU3Q5
            .quad       TU0Q5,TU1Q5,TU2Q5,TU3Q5,TU0Q5,TU1Q5,TU2Q5,TU3Q5     # up to 320 bytes
#else
TailUxDx:
            .quad       TU0Q0-TailUxDx
            .quad       TU1Q0-TailUxDx
            .quad       TU2Q0-TailUxDx
            .quad       TU3Q0-TailUxDx
            .quad       TU0Q1-TailUxDx
            .quad       TU1Q1-TailUxDx
            .quad       TU2Q1-TailUxDx
            .quad       TU3Q1-TailUxDx
            .quad       TU0Q1-TailUxDx
            .quad       TU1Q1-TailUxDx
            .quad       TU2Q1-TailUxDx
            .quad       TU3Q1-TailUxDx
            .quad       TU0Q1-TailUxDx
            .quad       TU1Q1-TailUxDx
            .quad       TU2Q1-TailUxDx
            .quad       TU3Q1-TailUxDx
            .quad       TU0Q1-TailUxDx
            .quad       TU1Q1-TailUxDx
            .quad       TU2Q1-TailUxDx
            .quad       TU3Q1-TailUxDx
            .quad       TU0Q1-TailUxDx
            .quad       TU1Q1-TailUxDx
            .quad       TU2Q1-TailUxDx
            .quad       TU3Q1-TailUxDx
            .quad       TU0Q1-TailUxDx
            .quad       TU1Q1-TailUxDx
            .quad       TU2Q1-TailUxDx
            .quad       TU3Q1-TailUxDx
            .quad       TU0Q1-TailUxDx
            .quad       TU1Q1-TailUxDx
            .quad       TU2Q1-TailUxDx
            .quad       TU3Q1-TailUxDx
            .quad       TU0Q1-TailUxDx
            .quad       TU1Q1-TailUxDx
            .quad       TU2Q1-TailUxDx
            .quad       TU3Q1-TailUxDx
            .quad       TU0Q1-TailUxDx
            .quad       TU1Q1-TailUxDx
            .quad       TU2Q1-TailUxDx
            .quad       TU3Q1-TailUxDx
            .quad       TU0Q1-TailUxDx
            .quad       TU1Q1-TailUxDx
            .quad       TU2Q1-TailUxDx
            .quad       TU3Q1-TailUxDx
            .quad       TU0Q1-TailUxDx
            .quad       TU1Q1-TailUxDx
            .quad       TU2Q1-TailUxDx
            .quad       TU3Q1-TailUxDx
            .quad       TU0Q1-TailUxDx
            .quad       TU1Q1-TailUxDx
            .quad       TU2Q1-TailUxDx
            .quad       TU3Q1-TailUxDx
            .quad       TU0Q1-TailUxDx
            .quad       TU1Q1-TailUxDx
            .quad       TU2Q1-TailUxDx
            .quad       TU3Q1-TailUxDx
            .quad       TU0Q1-TailUxDx
            .quad       TU1Q1-TailUxDx
            .quad       TU2Q1-TailUxDx
            .quad       TU3Q1-TailUxDx
            .quad       TU0Q1-TailUxDx
            .quad       TU1Q1-TailUxDx
            .quad       TU2Q1-TailUxDx
            .quad       TU3Q1-TailUxDx
            .quad       TU0Q2-TailUxDx
            .quad       TU1Q2-TailUxDx
            .quad       TU2Q2-TailUxDx
            .quad       TU3Q2-TailUxDx
            .quad       TU0Q2-TailUxDx
            .quad       TU1Q2-TailUxDx
            .quad       TU2Q2-TailUxDx
            .quad       TU3Q2-TailUxDx
            .quad       TU0Q2-TailUxDx
            .quad       TU1Q2-TailUxDx
            .quad       TU2Q2-TailUxDx
            .quad       TU3Q2-TailUxDx
            .quad       TU0Q2-TailUxDx
            .quad       TU1Q2-TailUxDx
            .quad       TU2Q2-TailUxDx
            .quad       TU3Q2-TailUxDx
            .quad       TU0Q2-TailUxDx
            .quad       TU1Q2-TailUxDx
            .quad       TU2Q2-TailUxDx
            .quad       TU3Q2-TailUxDx
            .quad       TU0Q2-TailUxDx
            .quad       TU1Q2-TailUxDx
            .quad       TU2Q2-TailUxDx
            .quad       TU3Q2-TailUxDx
            .quad       TU0Q2-TailUxDx
            .quad       TU1Q2-TailUxDx
            .quad       TU2Q2-TailUxDx
            .quad       TU3Q2-TailUxDx
            .quad       TU0Q2-TailUxDx
            .quad       TU1Q2-TailUxDx
            .quad       TU2Q2-TailUxDx
            .quad       TU3Q2-TailUxDx
            .quad       TU0Q2-TailUxDx
            .quad       TU1Q2-TailUxDx
            .quad       TU2Q2-TailUxDx
            .quad       TU3Q2-TailUxDx
            .quad       TU0Q2-TailUxDx
            .quad       TU1Q2-TailUxDx
            .quad       TU2Q2-TailUxDx
            .quad       TU3Q2-TailUxDx
            .quad       TU0Q2-TailUxDx
            .quad       TU1Q2-TailUxDx
            .quad       TU2Q2-TailUxDx
            .quad       TU3Q2-TailUxDx
            .quad       TU0Q2-TailUxDx
            .quad       TU1Q2-TailUxDx
            .quad       TU2Q2-TailUxDx
            .quad       TU3Q2-TailUxDx
            .quad       TU0Q2-TailUxDx
            .quad       TU1Q2-TailUxDx
            .quad       TU2Q2-TailUxDx
            .quad       TU3Q2-TailUxDx
            .quad       TU0Q2-TailUxDx
            .quad       TU1Q2-TailUxDx
            .quad       TU2Q2-TailUxDx
            .quad       TU3Q2-TailUxDx
            .quad       TU0Q2-TailUxDx
            .quad       TU1Q2-TailUxDx
            .quad       TU2Q2-TailUxDx
            .quad       TU3Q2-TailUxDx
            .quad       TU0Q2-TailUxDx
            .quad       TU1Q2-TailUxDx
            .quad       TU2Q2-TailUxDx
            .quad       TU3Q2-TailUxDx
            .quad       TU0Q3-TailUxDx
            .quad       TU1Q3-TailUxDx
            .quad       TU2Q3-TailUxDx
            .quad       TU3Q3-TailUxDx
            .quad       TU0Q3-TailUxDx
            .quad       TU1Q3-TailUxDx
            .quad       TU2Q3-TailUxDx
            .quad       TU3Q3-TailUxDx
            .quad       TU0Q3-TailUxDx
            .quad       TU1Q3-TailUxDx
            .quad       TU2Q3-TailUxDx
            .quad       TU3Q3-TailUxDx
            .quad       TU0Q3-TailUxDx
            .quad       TU1Q3-TailUxDx
            .quad       TU2Q3-TailUxDx
            .quad       TU3Q3-TailUxDx
            .quad       TU0Q3-TailUxDx
            .quad       TU1Q3-TailUxDx
            .quad       TU2Q3-TailUxDx
            .quad       TU3Q3-TailUxDx
            .quad       TU0Q3-TailUxDx
            .quad       TU1Q3-TailUxDx
            .quad       TU2Q3-TailUxDx
            .quad       TU3Q3-TailUxDx
            .quad       TU0Q3-TailUxDx
            .quad       TU1Q3-TailUxDx
            .quad       TU2Q3-TailUxDx
            .quad       TU3Q3-TailUxDx
            .quad       TU0Q3-TailUxDx
            .quad       TU1Q3-TailUxDx
            .quad       TU2Q3-TailUxDx
            .quad       TU3Q3-TailUxDx
            .quad       TU0Q3-TailUxDx
            .quad       TU1Q3-TailUxDx
            .quad       TU2Q3-TailUxDx
            .quad       TU3Q3-TailUxDx
            .quad       TU0Q3-TailUxDx
            .quad       TU1Q3-TailUxDx
            .quad       TU2Q3-TailUxDx
            .quad       TU3Q3-TailUxDx
            .quad       TU0Q3-TailUxDx
            .quad       TU1Q3-TailUxDx
            .quad       TU2Q3-TailUxDx
            .quad       TU3Q3-TailUxDx
            .quad       TU0Q3-TailUxDx
            .quad       TU1Q3-TailUxDx
            .quad       TU2Q3-TailUxDx
            .quad       TU3Q3-TailUxDx
            .quad       TU0Q3-TailUxDx
            .quad       TU1Q3-TailUxDx
            .quad       TU2Q3-TailUxDx
            .quad       TU3Q3-TailUxDx
            .quad       TU0Q3-TailUxDx
            .quad       TU1Q3-TailUxDx
            .quad       TU2Q3-TailUxDx
            .quad       TU3Q3-TailUxDx
            .quad       TU0Q3-TailUxDx
            .quad       TU1Q3-TailUxDx
            .quad       TU2Q3-TailUxDx
            .quad       TU3Q3-TailUxDx
            .quad       TU0Q3-TailUxDx
            .quad       TU1Q3-TailUxDx
            .quad       TU2Q3-TailUxDx
            .quad       TU3Q3-TailUxDx
            .quad       TU0Q4-TailUxDx
            .quad       TU1Q4-TailUxDx
            .quad       TU2Q4-TailUxDx
            .quad       TU3Q4-TailUxDx
            .quad       TU0Q4-TailUxDx
            .quad       TU1Q4-TailUxDx
            .quad       TU2Q4-TailUxDx
            .quad       TU3Q4-TailUxDx
            .quad       TU0Q4-TailUxDx
            .quad       TU1Q4-TailUxDx
            .quad       TU2Q4-TailUxDx
            .quad       TU3Q4-TailUxDx
            .quad       TU0Q4-TailUxDx
            .quad       TU1Q4-TailUxDx
            .quad       TU2Q4-TailUxDx
            .quad       TU3Q4-TailUxDx
            .quad       TU0Q4-TailUxDx
            .quad       TU1Q4-TailUxDx
            .quad       TU2Q4-TailUxDx
            .quad       TU3Q4-TailUxDx
            .quad       TU0Q4-TailUxDx
            .quad       TU1Q4-TailUxDx
            .quad       TU2Q4-TailUxDx
            .quad       TU3Q4-TailUxDx
            .quad       TU0Q4-TailUxDx
            .quad       TU1Q4-TailUxDx
            .quad       TU2Q4-TailUxDx
            .quad       TU3Q4-TailUxDx
            .quad       TU0Q4-TailUxDx
            .quad       TU1Q4-TailUxDx
            .quad       TU2Q4-TailUxDx
            .quad       TU3Q4-TailUxDx
            .quad       TU0Q4-TailUxDx
            .quad       TU1Q4-TailUxDx
            .quad       TU2Q4-TailUxDx
            .quad       TU3Q4-TailUxDx
            .quad       TU0Q4-TailUxDx
            .quad       TU1Q4-TailUxDx
            .quad       TU2Q4-TailUxDx
            .quad       TU3Q4-TailUxDx
            .quad       TU0Q4-TailUxDx
            .quad       TU1Q4-TailUxDx
            .quad       TU2Q4-TailUxDx
            .quad       TU3Q4-TailUxDx
            .quad       TU0Q4-TailUxDx
            .quad       TU1Q4-TailUxDx
            .quad       TU2Q4-TailUxDx
            .quad       TU3Q4-TailUxDx
            .quad       TU0Q4-TailUxDx
            .quad       TU1Q4-TailUxDx
            .quad       TU2Q4-TailUxDx
            .quad       TU3Q4-TailUxDx
            .quad       TU0Q4-TailUxDx
            .quad       TU1Q4-TailUxDx
            .quad       TU2Q4-TailUxDx
            .quad       TU3Q4-TailUxDx
            .quad       TU0Q4-TailUxDx
            .quad       TU1Q4-TailUxDx
            .quad       TU2Q4-TailUxDx
            .quad       TU3Q4-TailUxDx
            .quad       TU0Q4-TailUxDx
            .quad       TU1Q4-TailUxDx
            .quad       TU2Q4-TailUxDx
            .quad       TU3Q4-TailUxDx
            .quad       TU0Q5-TailUxDx
            .quad       TU1Q5-TailUxDx
            .quad       TU2Q5-TailUxDx
            .quad       TU3Q5-TailUxDx
            .quad       TU0Q5-TailUxDx
            .quad       TU1Q5-TailUxDx
            .quad       TU2Q5-TailUxDx
            .quad       TU3Q5-TailUxDx
            .quad       TU0Q5-TailUxDx
            .quad       TU1Q5-TailUxDx
            .quad       TU2Q5-TailUxDx
            .quad       TU3Q5-TailUxDx
            .quad       TU0Q5-TailUxDx
            .quad       TU1Q5-TailUxDx
            .quad       TU2Q5-TailUxDx
            .quad       TU3Q5-TailUxDx
            .quad       TU0Q5-TailUxDx
            .quad       TU1Q5-TailUxDx
            .quad       TU2Q5-TailUxDx
            .quad       TU3Q5-TailUxDx
            .quad       TU0Q5-TailUxDx
            .quad       TU1Q5-TailUxDx
            .quad       TU2Q5-TailUxDx
            .quad       TU3Q5-TailUxDx
            .quad       TU0Q5-TailUxDx
            .quad       TU1Q5-TailUxDx
            .quad       TU2Q5-TailUxDx
            .quad       TU3Q5-TailUxDx
            .quad       TU0Q5-TailUxDx
            .quad       TU1Q5-TailUxDx
            .quad       TU2Q5-TailUxDx
            .quad       TU3Q5-TailUxDx
            .quad       TU0Q5-TailUxDx
            .quad       TU1Q5-TailUxDx
            .quad       TU2Q5-TailUxDx
            .quad       TU3Q5-TailUxDx
            .quad       TU0Q5-TailUxDx
            .quad       TU1Q5-TailUxDx
            .quad       TU2Q5-TailUxDx
            .quad       TU3Q5-TailUxDx
            .quad       TU0Q5-TailUxDx
            .quad       TU1Q5-TailUxDx
            .quad       TU2Q5-TailUxDx
            .quad       TU3Q5-TailUxDx
            .quad       TU0Q5-TailUxDx
            .quad       TU1Q5-TailUxDx
            .quad       TU2Q5-TailUxDx
            .quad       TU3Q5-TailUxDx
            .quad       TU0Q5-TailUxDx
            .quad       TU1Q5-TailUxDx
            .quad       TU2Q5-TailUxDx
            .quad       TU3Q5-TailUxDx
            .quad       TU0Q5-TailUxDx
            .quad       TU1Q5-TailUxDx
            .quad       TU2Q5-TailUxDx
            .quad       TU3Q5-TailUxDx
            .quad       TU0Q5-TailUxDx
            .quad       TU1Q5-TailUxDx
            .quad       TU2Q5-TailUxDx
            .quad       TU3Q5-TailUxDx
            .quad       TU0Q5-TailUxDx
            .quad       TU1Q5-TailUxDx
            .quad       TU2Q5-TailUxDx
            .quad       TU3Q5-TailUxDx
#endif

# rsi = end of src buffer
# rcx = rsi - (rdi - rdx)
# rdi = end of dst buffer
# rdx = 64-byte aligned end of dst buffer (rdx <= rdi)

            .balign     16
TU0Q5:      vloadunpackld zmm0, [rcx-256]
            vloadunpackhd zmm0, [rcx-256+64]
            vmovdqa32     [rdx-256], zmm0
TU0Q4:      vloadunpackld zmm0, [rcx-192]
            vloadunpackhd zmm0, [rcx-192+64]
            vmovdqa32     [rdx-192], zmm0
TU0Q3:      vloadunpackld zmm0, [rcx-128]
            vloadunpackhd zmm0, [rcx-128+64]
            vmovdqa32     [rdx-128], zmm0
TU0Q2:      vloadunpackld zmm0, [rcx- 64]
            vloadunpackhd zmm0, [rcx- 64+64]
            vmovdqa32     [rdx- 64], zmm0
TU0Q1:      vloadunpackld zmm0, [rsi-4-64]
            vloadunpackhd zmm0, [rsi-4]
            vpackstorehd [rdi-4], zmm0
            mov         r9w, word  ptr[rsi-4]
            mov         word  ptr[rdi-4], r9w
            mov         r9w, word  ptr[rsi-2]
            mov         word  ptr[rdi-2], r9w
TU0Q0:      ret

TU1Q5:      vloadunpackld zmm0, [rcx-256]
            vloadunpackhd zmm0, [rcx-256+64]
            vmovdqa32     [rdx-256], zmm0
TU1Q4:      vloadunpackld zmm0, [rcx-192]
            vloadunpackhd zmm0, [rcx-192+64]
            vmovdqa32     [rdx-192], zmm0
TU1Q3:      vloadunpackld zmm0, [rcx-128]
            vloadunpackhd zmm0, [rcx-128+64]
            vmovdqa32     [rdx-128], zmm0
TU1Q2:      vloadunpackld zmm0, [rcx- 64]
            vloadunpackhd zmm0, [rcx- 64+64]
            vmovdqa32     [rdx- 64], zmm0
TU1Q1:      vloadunpackld zmm0, [rsi-1-64]
            vloadunpackhd zmm0, [rsi-1]
            vpackstorehd [rdi-1], zmm0
TU1Q0:      mov         r9b, byte  ptr[rsi-1]
            mov         byte  ptr[rdi-1], r9b
            ret

TU2Q5:      vloadunpackld zmm0, [rcx-256]
            vloadunpackhd zmm0, [rcx-256+64]
            vmovdqa32     [rdx-256], zmm0
TU2Q4:      vloadunpackld zmm0, [rcx-192]
            vloadunpackhd zmm0, [rcx-192+64]
            vmovdqa32     [rdx-192], zmm0
TU2Q3:      vloadunpackld zmm0, [rcx-128]
            vloadunpackhd zmm0, [rcx-128+64]
            vmovdqa32     [rdx-128], zmm0
TU2Q2:      vloadunpackld zmm0, [rcx- 64]
            vloadunpackhd zmm0, [rcx- 64+64]
            vmovdqa32     [rdx- 64], zmm0
TU2Q1:      vloadunpackld zmm0, [rsi-2-64]
            vloadunpackhd zmm0, [rsi-2]
            vpackstorehd [rdi-2], zmm0
TU2Q0:      mov         r9w, word  ptr[rsi-2]
            mov         word  ptr[rdi-2], r9w
            ret

TU3Q5:      vloadunpackld zmm0, [rcx-256]
            vloadunpackhd zmm0, [rcx-256+64]
            vmovdqa32     [rdx-256], zmm0
TU3Q4:      vloadunpackld zmm0, [rcx-192]
            vloadunpackhd zmm0, [rcx-192+64]
            vmovdqa32     [rdx-192], zmm0
TU3Q3:      vloadunpackld zmm0, [rcx-128]
            vloadunpackhd zmm0, [rcx-128+64]
            vmovdqa32     [rdx-128], zmm0
TU3Q2:      vloadunpackld zmm0, [rcx- 64]
            vloadunpackhd zmm0, [rcx- 64+64]
            vmovdqa32     [rdx- 64], zmm0
TU3Q1:      vloadunpackld zmm0, [rsi-3-64]
            vloadunpackhd zmm0, [rsi-3]
            vpackstorehd [rdi-3], zmm0
TU3Q0:      mov         r9w, word  ptr[rsi-3]
            mov         word  ptr[rdi-3], r9w
            mov         r9b, byte  ptr[rsi-1]
            mov         byte  ptr[rdi-1], r9b
            ret

#
# Small array (shorter than a threshold)
#
            .balign     16
#if !defined(PIC)
fwdPxQx:    .quad       P0Q0,P1Q0,P2Q0,P3Q0,P4Q0,P5Q0,P6Q0,P7Q0
            .quad       P0Q1,P1Q1,P2Q1,P3Q1,P4Q1,P5Q1,P6Q1,P7Q1
            .quad       P0Q2,P1Q2,P2Q2,P3Q2,P4Q2,P5Q2,P6Q2,P7Q2
            .quad       P0Q3,P1Q3,P2Q3,P3Q3,P4Q3,P5Q3,P6Q3,P7Q3
            .quad       P0Q4,P1Q4,P2Q4,P3Q4,P4Q4,P5Q4,P6Q4,P7Q4
            .quad       P0Q5,P1Q5,P2Q5,P3Q5,P4Q5,P5Q5,P6Q5,P7Q5
            .quad       P0Q6,P1Q6,P2Q6,P3Q6,P4Q6,P5Q6,P6Q6,P7Q6
            .quad       P0Q7,P1Q7,P2Q7,P3Q7,P4Q7,P5Q7,P6Q7,P7Q7     # up to 64 bytes
            .quad       P0Q8,P1Q8,P2Q8,P3Q8,P4Q8,P5Q8,P6Q8,P7Q8
            .quad       P0Q9,P1Q9,P2Q9,P3Q9,P4Q9,P5Q9,P6Q9,P7Q9
            .quad       P0QA,P1QA,P2QA,P3QA,P4QA,P5QA,P6QA,P7QA
            .quad       P0QB,P1QB,P2QB,P3QB,P4QB,P5QB,P6QB,P7QB
            .quad       P0QC,P1QC,P2QC,P3QC,P4QC,P5QC,P6QC,P7QC
            .quad       P0QD,P1QD,P2QD,P3QD,P4QD,P5QD,P6QD,P7QD
            .quad       P0QE,P1QE,P2QE,P3QE,P4QE,P5QE,P6QE,P7QE
            .quad       P0QF,P1QF,P2QF,P3QF,P4QF,P5QF,P6QF,P7QF     # up to 128 bytes
            .quad       P0QG,P1QG,P2QG,P3QG,P4QG,P5QG,P6QG,P7QG
            .quad       P0QH,P1QH,P2QH,P3QH,P4QH,P5QH,P6QH,P7QH
            .quad       P0QI,P1QI,P2QI,P3QI,P4QI,P5QI,P6QI,P7QI
            .quad       P0QJ,P1QJ,P2QJ,P3QJ,P4QJ,P5QJ,P6QJ,P7QJ
            .quad       P0QK,P1QK,P2QK,P3QK,P4QK,P5QK,P6QK,P7QK
            .quad       P0QL,P1QL,P2QL,P3QL,P4QL,P5QL,P6QL,P7QL
            .quad       P0QM,P1QM,P2QM,P3QM,P4QM,P5QM,P6QM,P7QM
#else
fwdPxQx:    .quad       P0Q0-fwdPxQx
            .quad       P1Q0-fwdPxQx
            .quad       P2Q0-fwdPxQx
            .quad       P3Q0-fwdPxQx
            .quad       P4Q0-fwdPxQx
            .quad       P5Q0-fwdPxQx
            .quad       P6Q0-fwdPxQx
            .quad       P7Q0-fwdPxQx

            .quad       P0Q1-fwdPxQx
            .quad       P1Q1-fwdPxQx
            .quad       P2Q1-fwdPxQx
            .quad       P3Q1-fwdPxQx
            .quad       P4Q1-fwdPxQx
            .quad       P5Q1-fwdPxQx
            .quad       P6Q1-fwdPxQx
            .quad       P7Q1-fwdPxQx

            .quad       P0Q2-fwdPxQx
            .quad       P1Q2-fwdPxQx
            .quad       P2Q2-fwdPxQx
            .quad       P3Q2-fwdPxQx
            .quad       P4Q2-fwdPxQx
            .quad       P5Q2-fwdPxQx
            .quad       P6Q2-fwdPxQx
            .quad       P7Q2-fwdPxQx

            .quad       P0Q3-fwdPxQx
            .quad       P1Q3-fwdPxQx
            .quad       P2Q3-fwdPxQx
            .quad       P3Q3-fwdPxQx
            .quad       P4Q3-fwdPxQx
            .quad       P5Q3-fwdPxQx
            .quad       P6Q3-fwdPxQx
            .quad       P7Q3-fwdPxQx

            .quad       P0Q4-fwdPxQx
            .quad       P1Q4-fwdPxQx
            .quad       P2Q4-fwdPxQx
            .quad       P3Q4-fwdPxQx
            .quad       P4Q4-fwdPxQx
            .quad       P5Q4-fwdPxQx
            .quad       P6Q4-fwdPxQx
            .quad       P7Q4-fwdPxQx

            .quad       P0Q5-fwdPxQx
            .quad       P1Q5-fwdPxQx
            .quad       P2Q5-fwdPxQx
            .quad       P3Q5-fwdPxQx
            .quad       P4Q5-fwdPxQx
            .quad       P5Q5-fwdPxQx
            .quad       P6Q5-fwdPxQx
            .quad       P7Q5-fwdPxQx

            .quad       P0Q6-fwdPxQx
            .quad       P1Q6-fwdPxQx
            .quad       P2Q6-fwdPxQx
            .quad       P3Q6-fwdPxQx
            .quad       P4Q6-fwdPxQx
            .quad       P5Q6-fwdPxQx
            .quad       P6Q6-fwdPxQx
            .quad       P7Q6-fwdPxQx

            .quad       P0Q7-fwdPxQx
            .quad       P1Q7-fwdPxQx
            .quad       P2Q7-fwdPxQx
            .quad       P3Q7-fwdPxQx
            .quad       P4Q7-fwdPxQx
            .quad       P5Q7-fwdPxQx
            .quad       P6Q7-fwdPxQx
            .quad       P7Q7-fwdPxQx

            .quad       P0Q8-fwdPxQx
            .quad       P1Q8-fwdPxQx
            .quad       P2Q8-fwdPxQx
            .quad       P3Q8-fwdPxQx
            .quad       P4Q8-fwdPxQx
            .quad       P5Q8-fwdPxQx
            .quad       P6Q8-fwdPxQx
            .quad       P7Q8-fwdPxQx

            .quad       P0Q9-fwdPxQx
            .quad       P1Q9-fwdPxQx
            .quad       P2Q9-fwdPxQx
            .quad       P3Q9-fwdPxQx
            .quad       P4Q9-fwdPxQx
            .quad       P5Q9-fwdPxQx
            .quad       P6Q9-fwdPxQx
            .quad       P7Q9-fwdPxQx

            .quad       P0QA-fwdPxQx
            .quad       P1QA-fwdPxQx
            .quad       P2QA-fwdPxQx
            .quad       P3QA-fwdPxQx
            .quad       P4QA-fwdPxQx
            .quad       P5QA-fwdPxQx
            .quad       P6QA-fwdPxQx
            .quad       P7QA-fwdPxQx

            .quad       P0QB-fwdPxQx
            .quad       P1QB-fwdPxQx
            .quad       P2QB-fwdPxQx
            .quad       P3QB-fwdPxQx
            .quad       P4QB-fwdPxQx
            .quad       P5QB-fwdPxQx
            .quad       P6QB-fwdPxQx
            .quad       P7QB-fwdPxQx

            .quad       P0QC-fwdPxQx
            .quad       P1QC-fwdPxQx
            .quad       P2QC-fwdPxQx
            .quad       P3QC-fwdPxQx
            .quad       P4QC-fwdPxQx
            .quad       P5QC-fwdPxQx
            .quad       P6QC-fwdPxQx
            .quad       P7QC-fwdPxQx

            .quad       P0QD-fwdPxQx
            .quad       P1QD-fwdPxQx
            .quad       P2QD-fwdPxQx
            .quad       P3QD-fwdPxQx
            .quad       P4QD-fwdPxQx
            .quad       P5QD-fwdPxQx
            .quad       P6QD-fwdPxQx
            .quad       P7QD-fwdPxQx

            .quad       P0QE-fwdPxQx
            .quad       P1QE-fwdPxQx
            .quad       P2QE-fwdPxQx
            .quad       P3QE-fwdPxQx
            .quad       P4QE-fwdPxQx
            .quad       P5QE-fwdPxQx
            .quad       P6QE-fwdPxQx
            .quad       P7QE-fwdPxQx

            .quad       P0QF-fwdPxQx
            .quad       P1QF-fwdPxQx
            .quad       P2QF-fwdPxQx
            .quad       P3QF-fwdPxQx
            .quad       P4QF-fwdPxQx
            .quad       P5QF-fwdPxQx
            .quad       P6QF-fwdPxQx
            .quad       P7QF-fwdPxQx

            .quad       P0QG-fwdPxQx
            .quad       P1QG-fwdPxQx
            .quad       P2QG-fwdPxQx
            .quad       P3QG-fwdPxQx
            .quad       P4QG-fwdPxQx
            .quad       P5QG-fwdPxQx
            .quad       P6QG-fwdPxQx
            .quad       P7QG-fwdPxQx

            .quad       P0QH-fwdPxQx
            .quad       P1QH-fwdPxQx
            .quad       P2QH-fwdPxQx
            .quad       P3QH-fwdPxQx
            .quad       P4QH-fwdPxQx
            .quad       P5QH-fwdPxQx
            .quad       P6QH-fwdPxQx
            .quad       P7QH-fwdPxQx

            .quad       P0QI-fwdPxQx
            .quad       P1QI-fwdPxQx
            .quad       P2QI-fwdPxQx
            .quad       P3QI-fwdPxQx
            .quad       P4QI-fwdPxQx
            .quad       P5QI-fwdPxQx
            .quad       P6QI-fwdPxQx
            .quad       P7QI-fwdPxQx

            .quad       P0QJ-fwdPxQx
            .quad       P1QJ-fwdPxQx
            .quad       P2QJ-fwdPxQx
            .quad       P3QJ-fwdPxQx
            .quad       P4QJ-fwdPxQx
            .quad       P5QJ-fwdPxQx
            .quad       P6QJ-fwdPxQx
            .quad       P7QJ-fwdPxQx

            .quad       P0QK-fwdPxQx
            .quad       P1QK-fwdPxQx
            .quad       P2QK-fwdPxQx
            .quad       P3QK-fwdPxQx
            .quad       P4QK-fwdPxQx
            .quad       P5QK-fwdPxQx
            .quad       P6QK-fwdPxQx
            .quad       P7QK-fwdPxQx

            .quad       P0QL-fwdPxQx
            .quad       P1QL-fwdPxQx
            .quad       P2QL-fwdPxQx
            .quad       P3QL-fwdPxQx
            .quad       P4QL-fwdPxQx
            .quad       P5QL-fwdPxQx
            .quad       P6QL-fwdPxQx
            .quad       P7QL-fwdPxQx

            .quad       P0QM-fwdPxQx
            .quad       P1QM-fwdPxQx
            .quad       P2QM-fwdPxQx
            .quad       P3QM-fwdPxQx
            .quad       P4QM-fwdPxQx
            .quad       P5QM-fwdPxQx
            .quad       P6QM-fwdPxQx
            .quad       P7QM-fwdPxQx
#endif

P0QM:       mov         r9, qword ptr[rsi-(22*8)-0]
            mov         qword ptr[rdi-(22*8)-0], r9
P0QL:       mov         r11, qword ptr[rsi-(21*8)-0]
            mov         qword ptr[rdi-(21*8)-0], r11
P0QK:       mov         r9, qword ptr[rsi-(20*8)-0]
            mov         qword ptr[rdi-(20*8)-0], r9
P0QJ:       mov         r10, qword ptr[rsi-(19*8)-0]
            mov         qword ptr[rdi-(19*8)-0], r10
P0QI:       mov         r9, qword ptr[rsi-(18*8)-0]
            mov         qword ptr[rdi-(18*8)-0], r9
P0QH:       mov         r10, qword ptr[rsi-(17*8)-0]
            mov         qword ptr[rdi-(17*8)-0], r10
P0QG:       mov         r9, qword ptr[rsi-(16*8)-0]
            mov         qword ptr[rdi-(16*8)-0], r9
P0QF:       mov         r10, qword ptr[rsi-(15*8)-0]
            mov         qword ptr[rdi-(15*8)-0], r10
P0QE:       mov         r9, qword ptr[rsi-(14*8)-0]
            mov         qword ptr[rdi-(14*8)-0], r9
P0QD:       mov         r10, qword ptr[rsi-(13*8)-0]
            mov         qword ptr[rdi-(13*8)-0], r10
P0QC:       mov         r9, qword ptr[rsi-(12*8)-0]
            mov         qword ptr[rdi-(12*8)-0], r9
P0QB:       mov         r10, qword ptr[rsi-(11*8)-0]
            mov         qword ptr[rdi-(11*8)-0], r10
P0QA:       mov         r9, qword ptr[rsi-(10*8)-0]
            mov         qword ptr[rdi-(10*8)-0], r9
P0Q9:       mov         r10, qword ptr[rsi-(9*8)-0]
            mov         qword ptr[rdi-(9*8)-0], r10
P0Q8:       mov         r9, qword ptr[rsi-(8*8)-0]
            mov         qword ptr[rdi-(8*8)-0], r9
P0Q7:       mov         r10, qword ptr[rsi-(7*8)-0]
            mov         qword ptr[rdi-(7*8)-0], r10
P0Q6:       mov         r9, qword ptr[rsi-(6*8)-0]
            mov         qword ptr[rdi-(6*8)-0], r9
P0Q5:       mov         r10, qword ptr[rsi-(5*8)-0]
            mov         qword ptr[rdi-(5*8)-0], r10
P0Q4:       mov         r9, qword ptr[rsi-(4*8)-0]
            mov         qword ptr[rdi-(4*8)-0], r9
P0Q3:       mov         r10, qword ptr[rsi-(3*8)-0]
            mov         qword ptr[rdi-(3*8)-0], r10
P0Q2:       mov         r9, qword ptr[rsi-(2*8)-0]
            mov         qword ptr[rdi-(2*8)-0], r9
P0Q1:       mov         r10, qword ptr[rsi-(1*8)-0]
            mov         qword ptr[rdi-(1*8)-0], r10
P0Q0:       ret

P1QM:       mov         r9, qword ptr[rsi-(22*8)-1]
            mov         qword ptr[rdi-(22*8)-1], r9
P1QL:       mov         r9, qword ptr[rsi-(21*8)-1]
            mov         qword ptr[rdi-(21*8)-1], r9
P1QK:       mov         r9, qword ptr[rsi-(20*8)-1]
            mov         qword ptr[rdi-(20*8)-1], r9
P1QJ:       mov         r9, qword ptr[rsi-(19*8)-1]
            mov         qword ptr[rdi-(19*8)-1], r9
P1QI:       mov         r9, qword ptr[rsi-(18*8)-1]
            mov         qword ptr[rdi-(18*8)-1], r9
P1QH:       mov         r9, qword ptr[rsi-(17*8)-1]
            mov         qword ptr[rdi-(17*8)-1], r9
P1QG:       mov         r9, qword ptr[rsi-(16*8)-1]
            mov         qword ptr[rdi-(16*8)-1], r9
P1QF:       mov         r9, qword ptr[rsi-(15*8)-1]
            mov         qword ptr[rdi-(15*8)-1], r9
P1QE:       mov         r9, qword ptr[rsi-(14*8)-1]
            mov         qword ptr[rdi-(14*8)-1], r9
P1QD:       mov         r9, qword ptr[rsi-(13*8)-1]
            mov         qword ptr[rdi-(13*8)-1], r9
P1QC:       mov         r9, qword ptr[rsi-(12*8)-1]
            mov         qword ptr[rdi-(12*8)-1], r9
P1QB:       mov         r11, qword ptr[rsi-(11*8)-1]
            mov         qword ptr[rdi-(11*8)-1], r11
P1QA:       mov         r10, qword ptr[rsi-(10*8)-1]
            mov         qword ptr[rdi-(10*8)-1], r10
P1Q9:       mov         r9,  qword ptr[rsi-(9*8)-1]
            mov         qword ptr[rdi-(9*8)-1], r9
P1Q8:       mov         r11, qword ptr[rsi-(8*8)-1]
            mov         qword ptr[rdi-(8*8)-1], r11
P1Q7:       mov         r10, qword ptr[rsi-(7*8)-1]
            mov         qword ptr[rdi-(7*8)-1], r10
P1Q6:       mov         r9,  qword ptr[rsi-(6*8)-1]
            mov         qword ptr[rdi-(6*8)-1], r9
P1Q5:       mov         r11, qword ptr[rsi-(5*8)-1]
            mov         qword ptr[rdi-(5*8)-1], r11
P1Q4:       mov         r10, qword ptr[rsi-(4*8)-1]
            mov         qword ptr[rdi-(4*8)-1], r10
P1Q3:       mov         r9, qword ptr[rsi-(3*8)-1]
            mov         qword ptr[rdi-(3*8)-1], r9
P1Q2:       mov         r11, qword ptr[rsi-(2*8)-1]
            mov         qword ptr[rdi-(2*8)-1], r11
P1Q1:       mov         r10, qword ptr[rsi-(1*8)-1]
            mov         qword ptr[rdi-(1*8)-1], r10
P1Q0:       # These trailing loads/stores have to do all their loads 1st, then do the stores
            mov         r9b, byte ptr[rsi-(0*8)-1]
            mov         byte ptr[rdi-(0*8)-1], r9b
            ret

P2QM:       mov         r9, qword ptr[rsi-(22*8)-2]
            mov         qword ptr[rdi-(22*8)-2], r9
P2QL:       mov         r9, qword ptr[rsi-(21*8)-2]
            mov         qword ptr[rdi-(21*8)-2], r9
P2QK:       mov         r9, qword ptr[rsi-(20*8)-2]
            mov         qword ptr[rdi-(20*8)-2], r9
P2QJ:       mov         r9, qword ptr[rsi-(19*8)-2]
            mov         qword ptr[rdi-(19*8)-2], r9
P2QI:       mov         r9, qword ptr[rsi-(18*8)-2]
            mov         qword ptr[rdi-(18*8)-2], r9
P2QH:       mov         r9, qword ptr[rsi-(17*8)-2]
            mov         qword ptr[rdi-(17*8)-2], r9
P2QG:       mov         r9, qword ptr[rsi-(16*8)-2]
            mov         qword ptr[rdi-(16*8)-2], r9
P2QF:       mov         r9, qword ptr[rsi-(15*8)-2]
            mov         qword ptr[rdi-(15*8)-2], r9
P2QE:       mov         r9, qword ptr[rsi-(14*8)-2]
            mov         qword ptr[rdi-(14*8)-2], r9
P2QD:       mov         r9, qword ptr[rsi-(13*8)-2]
            mov         qword ptr[rdi-(13*8)-2], r9
P2QC:       mov         r9, qword ptr[rsi-(12*8)-2]
            mov         qword ptr[rdi-(12*8)-2], r9
P2QB:       mov         r9, qword ptr[rsi-(11*8)-2]
            mov         qword ptr[rdi-(11*8)-2], r9
P2QA:       mov         r9, qword ptr[rsi-(10*8)-2]
            mov         qword ptr[rdi-(10*8)-2], r9
P2Q9:       mov         r9, qword ptr[rsi-(9*8)-2]
            mov         qword ptr[rdi-(9*8)-2], r9
P2Q8:       mov         r9, qword ptr[rsi-(8*8)-2]
            mov         qword ptr[rdi-(8*8)-2], r9
P2Q7:       mov         r9, qword ptr[rsi-(7*8)-2]
            mov         qword ptr[rdi-(7*8)-2], r9
P2Q6:       mov         r9, qword ptr[rsi-(6*8)-2]
            mov         qword ptr[rdi-(6*8)-2], r9
P2Q5:       mov         r9, qword ptr[rsi-(5*8)-2]
            mov         qword ptr[rdi-(5*8)-2], r9
P2Q4:       mov         r9, qword ptr[rsi-(4*8)-2]
            mov         qword ptr[rdi-(4*8)-2], r9
P2Q3:       mov         r9, qword ptr[rsi-(3*8)-2]
            mov         qword ptr[rdi-(3*8)-2], r9
P2Q2:       mov         r9, qword ptr[rsi-(2*8)-2]
            mov         qword ptr[rdi-(2*8)-2], r9
P2Q1:       mov         r9, qword ptr[rsi-(1*8)-2]
            mov         qword ptr[rdi-(1*8)-2], r9
P2Q0:       # These trailing loads/stores have to do all their loads 1st, then do the stores
            mov         r9w, word ptr[rsi-(0*8)-2]
            mov         word ptr[rdi-(0*8)-2], r9w
            ret

P3QM:       mov         r9, qword ptr[rsi-(22*8)-3]
            mov         qword ptr[rdi-(22*8)-3], r9
P3QL:       mov         r9, qword ptr[rsi-(21*8)-3]
            mov         qword ptr[rdi-(21*8)-3], r9
P3QK:       mov         r9, qword ptr[rsi-(20*8)-3]
            mov         qword ptr[rdi-(20*8)-3], r9
P3QJ:       mov         r9, qword ptr[rsi-(19*8)-3]
            mov         qword ptr[rdi-(19*8)-3], r9
P3QI:       mov         r9, qword ptr[rsi-(18*8)-3]
            mov         qword ptr[rdi-(18*8)-3], r9
P3QH:       mov         r9, qword ptr[rsi-(17*8)-3]
            mov         qword ptr[rdi-(17*8)-3], r9
P3QG:       mov         r9, qword ptr[rsi-(16*8)-3]
            mov         qword ptr[rdi-(16*8)-3], r9
P3QF:       mov         r9, qword ptr[rsi-(15*8)-3]
            mov         qword ptr[rdi-(15*8)-3], r9
P3QE:       mov         r9, qword ptr[rsi-(14*8)-3]
            mov         qword ptr[rdi-(14*8)-3], r9
P3QD:       mov         r9, qword ptr[rsi-(13*8)-3]
            mov         qword ptr[rdi-(13*8)-3], r9
P3QC:       mov         r9, qword ptr[rsi-(12*8)-3]
            mov         qword ptr[rdi-(12*8)-3], r9
P3QB:       mov         r9, qword ptr[rsi-(11*8)-3]
            mov         qword ptr[rdi-(11*8)-3], r9
P3QA:       mov         r9, qword ptr[rsi-(10*8)-3]
            mov         qword ptr[rdi-(10*8)-3], r9
P3Q9:       mov         r9, qword ptr[rsi-(9*8)-3]
            mov         qword ptr[rdi-(9*8)-3], r9
P3Q8:       mov         r9, qword ptr[rsi-(8*8)-3]
            mov         qword ptr[rdi-(8*8)-3], r9
P3Q7:       mov         r9, qword ptr[rsi-(7*8)-3]
            mov         qword ptr[rdi-(7*8)-3], r9
P3Q6:       mov         r9, qword ptr[rsi-(6*8)-3]
            mov         qword ptr[rdi-(6*8)-3], r9
P3Q5:       mov         r9, qword ptr[rsi-(5*8)-3]
            mov         qword ptr[rdi-(5*8)-3], r9
P3Q4:       mov         r9, qword ptr[rsi-(4*8)-3]
            mov         qword ptr[rdi-(4*8)-3], r9
P3Q3:       mov         r9, qword ptr[rsi-(3*8)-3]
            mov         qword ptr[rdi-(3*8)-3], r9
P3Q2:       mov         r9, qword ptr[rsi-(2*8)-3]
            mov         qword ptr[rdi-(2*8)-3], r9
P3Q1:       mov         r9, qword ptr[rsi-(1*8)-3]
            mov         qword ptr[rdi-(1*8)-3], r9
P3Q0:       # These trailing loads/stores have to do all their loads 1st, then do the stores
            mov         r9w, word ptr[rsi-(0*8)-3]
            mov         r10b, byte ptr[rsi-(0*8)-1]
            mov         word ptr[rdi-(0*8)-3], r9w
            mov         byte ptr[rdi-(0*8)-1], r10b
            ret

P4QM:       mov         r9, qword ptr[rsi-(22*8)-4]
            mov         qword ptr[rdi-(22*8)-4], r9
P4QL:       mov         r9, qword ptr[rsi-(21*8)-4]
            mov         qword ptr[rdi-(21*8)-4], r9
P4QK:       mov         r9, qword ptr[rsi-(20*8)-4]
            mov         qword ptr[rdi-(20*8)-4], r9
P4QJ:       mov         r9, qword ptr[rsi-(19*8)-4]
            mov         qword ptr[rdi-(19*8)-4], r9
P4QI:       mov         r9, qword ptr[rsi-(18*8)-4]
            mov         qword ptr[rdi-(18*8)-4], r9
P4QH:       mov         r9, qword ptr[rsi-(17*8)-4]
            mov         qword ptr[rdi-(17*8)-4], r9
P4QG:       mov         r9, qword ptr[rsi-(16*8)-4]
            mov         qword ptr[rdi-(16*8)-4], r9
P4QF:       mov         r9, qword ptr[rsi-(15*8)-4]
            mov         qword ptr[rdi-(15*8)-4], r9
P4QE:       mov         r9, qword ptr[rsi-(14*8)-4]
            mov         qword ptr[rdi-(14*8)-4], r9
P4QD:       mov         r9, qword ptr[rsi-(13*8)-4]
            mov         qword ptr[rdi-(13*8)-4], r9
P4QC:       mov         r9, qword ptr[rsi-(12*8)-4]
            mov         qword ptr[rdi-(12*8)-4], r9
P4QB:       mov         r9, qword ptr[rsi-(11*8)-4]
            mov         qword ptr[rdi-(11*8)-4], r9
P4QA:       mov         r9, qword ptr[rsi-(10*8)-4]
            mov         qword ptr[rdi-(10*8)-4], r9
P4Q9:       mov         r9, qword ptr[rsi-(9*8)-4]
            mov         qword ptr[rdi-(9*8)-4], r9
P4Q8:       mov         r9, qword ptr[rsi-(8*8)-4]
            mov         qword ptr[rdi-(8*8)-4], r9
P4Q7:       mov         r9, qword ptr[rsi-(7*8)-4]
            mov         qword ptr[rdi-(7*8)-4], r9
P4Q6:       mov         r9, qword ptr[rsi-(6*8)-4]
            mov         qword ptr[rdi-(6*8)-4], r9
P4Q5:       mov         r9, qword ptr[rsi-(5*8)-4]
            mov         qword ptr[rdi-(5*8)-4], r9
P4Q4:       mov         r9, qword ptr[rsi-(4*8)-4]
            mov         qword ptr[rdi-(4*8)-4], r9
P4Q3:       mov         r9, qword ptr[rsi-(3*8)-4]
            mov         qword ptr[rdi-(3*8)-4], r9
P4Q2:       mov         r9, qword ptr[rsi-(2*8)-4]
            mov         qword ptr[rdi-(2*8)-4], r9
P4Q1:       mov         r9, qword ptr[rsi-(1*8)-4]
            mov         qword ptr[rdi-(1*8)-4], r9
P4Q0:       # These trailing loads/stores have to do all their loads 1st, then do the stores
            mov         r9d, dword ptr[rsi-(0*8)-4]
            mov         dword ptr[rdi-(0*8)-4], r9d
            ret

P5QM:       mov         r9, qword ptr[rsi-(22*8)-5]
            mov         qword ptr[rdi-(22*8)-5], r9
P5QL:       mov         r9, qword ptr[rsi-(21*8)-5]
            mov         qword ptr[rdi-(21*8)-5], r9
P5QK:       mov         r9, qword ptr[rsi-(20*8)-5]
            mov         qword ptr[rdi-(20*8)-5], r9
P5QJ:       mov         r9, qword ptr[rsi-(19*8)-5]
            mov         qword ptr[rdi-(19*8)-5], r9
P5QI:       mov         r9, qword ptr[rsi-(18*8)-5]
            mov         qword ptr[rdi-(18*8)-5], r9
P5QH:       mov         r9, qword ptr[rsi-(17*8)-5]
            mov         qword ptr[rdi-(17*8)-5], r9
P5QG:       mov         r9, qword ptr[rsi-(16*8)-5]
            mov         qword ptr[rdi-(16*8)-5], r9
P5QF:       mov         r9, qword ptr[rsi-(15*8)-5]
            mov         qword ptr[rdi-(15*8)-5], r9
P5QE:       mov         r9, qword ptr[rsi-(14*8)-5]
            mov         qword ptr[rdi-(14*8)-5], r9
P5QD:       mov         r9, qword ptr[rsi-(13*8)-5]
            mov         qword ptr[rdi-(13*8)-5], r9
P5QC:       mov         r9, qword ptr[rsi-(12*8)-5]
            mov         qword ptr[rdi-(12*8)-5], r9
P5QB:       mov         r9, qword ptr[rsi-(11*8)-5]
            mov         qword ptr[rdi-(11*8)-5], r9
P5QA:       mov         r9, qword ptr[rsi-(10*8)-5]
            mov         qword ptr[rdi-(10*8)-5], r9
P5Q9:       mov         r9, qword ptr[rsi-(9*8)-5]
            mov         qword ptr[rdi-(9*8)-5], r9
P5Q8:       mov         r9, qword ptr[rsi-(8*8)-5]
            mov         qword ptr[rdi-(8*8)-5], r9
P5Q7:       mov         r9, qword ptr[rsi-(7*8)-5]
            mov         qword ptr[rdi-(7*8)-5], r9
P5Q6:       mov         r9, qword ptr[rsi-(6*8)-5]
            mov         qword ptr[rdi-(6*8)-5], r9
P5Q5:       mov         r9, qword ptr[rsi-(5*8)-5]
            mov         qword ptr[rdi-(5*8)-5], r9
P5Q4:       mov         r9, qword ptr[rsi-(4*8)-5]
            mov         qword ptr[rdi-(4*8)-5], r9
P5Q3:       mov         r9, qword ptr[rsi-(3*8)-5]
            mov         qword ptr[rdi-(3*8)-5], r9
P5Q2:       mov         r9, qword ptr[rsi-(2*8)-5]
            mov         qword ptr[rdi-(2*8)-5], r9
P5Q1:       mov         r9, qword ptr[rsi-(1*8)-5]
            mov         qword ptr[rdi-(1*8)-5], r9
P5Q0:       # These trailing loads/stores have to do all their loads 1st, then do the stores
            mov         r9d, dword ptr[rsi-(0*8)-5]
            mov         r10b, byte ptr[rsi-(0*8)-1]
            mov         dword ptr[rdi-(0*8)-5], r9d
            mov         byte ptr[rdi-(0*8)-1], r10b
            ret

P6QM:       mov         r9, qword ptr[rsi-(22*8)-6]
            mov         qword ptr[rdi-(22*8)-6], r9
P6QL:       mov         r9, qword ptr[rsi-(21*8)-6]
            mov         qword ptr[rdi-(21*8)-6], r9
P6QK:       mov         r9, qword ptr[rsi-(20*8)-6]
            mov         qword ptr[rdi-(20*8)-6], r9
P6QJ:       mov         r9, qword ptr[rsi-(19*8)-6]
            mov         qword ptr[rdi-(19*8)-6], r9
P6QI:       mov         r9, qword ptr[rsi-(18*8)-6]
            mov         qword ptr[rdi-(18*8)-6], r9
P6QH:       mov         r9, qword ptr[rsi-(17*8)-6]
            mov         qword ptr[rdi-(17*8)-6], r9
P6QG:       mov         r9, qword ptr[rsi-(16*8)-6]
            mov         qword ptr[rdi-(16*8)-6], r9
P6QF:       mov         r9, qword ptr[rsi-(15*8)-6]
            mov         qword ptr[rdi-(15*8)-6], r9
P6QE:       mov         r9, qword ptr[rsi-(14*8)-6]
            mov         qword ptr[rdi-(14*8)-6], r9
P6QD:       mov         r9, qword ptr[rsi-(13*8)-6]
            mov         qword ptr[rdi-(13*8)-6], r9
P6QC:       mov         r9, qword ptr[rsi-(12*8)-6]
            mov         qword ptr[rdi-(12*8)-6], r9
P6QB:       mov         r9, qword ptr[rsi-(11*8)-6]
            mov         qword ptr[rdi-(11*8)-6], r9
P6QA:       mov         r9, qword ptr[rsi-(10*8)-6]
            mov         qword ptr[rdi-(10*8)-6], r9
P6Q9:       mov         r9, qword ptr[rsi-(9*8)-6]
            mov         qword ptr[rdi-(9*8)-6], r9
P6Q8:       mov         r9, qword ptr[rsi-(8*8)-6]
            mov         qword ptr[rdi-(8*8)-6], r9
P6Q7:       mov         r9, qword ptr[rsi-(7*8)-6]
            mov         qword ptr[rdi-(7*8)-6], r9
P6Q6:       mov         r9, qword ptr[rsi-(6*8)-6]
            mov         qword ptr[rdi-(6*8)-6], r9
P6Q5:       mov         r9, qword ptr[rsi-(5*8)-6]
            mov         qword ptr[rdi-(5*8)-6], r9
P6Q4:       mov         r9, qword ptr[rsi-(4*8)-6]
            mov         qword ptr[rdi-(4*8)-6], r9
P6Q3:       mov         r9, qword ptr[rsi-(3*8)-6]
            mov         qword ptr[rdi-(3*8)-6], r9
P6Q2:       mov         r9, qword ptr[rsi-(2*8)-6]
            mov         qword ptr[rdi-(2*8)-6], r9
P6Q1:       mov         r9, qword ptr[rsi-(1*8)-6]
            mov         qword ptr[rdi-(1*8)-6], r9
P6Q0:       # These trailing loads/stores have to do all their loads 1st, then do the stores
            mov         r9d, dword ptr[rsi-(0*8)-6]
            mov         r10w, word ptr[rsi-(0*8)-2]
            mov         dword ptr[rdi-(0*8)-6], r9d
            mov         word ptr[rdi-(0*8)-2], r10w
            ret

P7QM:       mov         r9, qword ptr[rsi-(22*8)-7]
            mov         qword ptr[rdi-(22*8)-7], r9
P7QL:       mov         r9, qword ptr[rsi-(21*8)-7]
            mov         qword ptr[rdi-(21*8)-7], r9
P7QK:       mov         r9, qword ptr[rsi-(20*8)-7]
            mov         qword ptr[rdi-(20*8)-7], r9
P7QJ:       mov         r9, qword ptr[rsi-(19*8)-7]
            mov         qword ptr[rdi-(19*8)-7], r9
P7QI:       mov         r9, qword ptr[rsi-(18*8)-7]
            mov         qword ptr[rdi-(18*8)-7], r9
P7QH:       mov         r9, qword ptr[rsi-(17*8)-7]
            mov         qword ptr[rdi-(17*8)-7], r9
P7QG:       mov         r9, qword ptr[rsi-(16*8)-7]
            mov         qword ptr[rdi-(16*8)-7], r9
P7QF:       mov         r9, qword ptr[rsi-(15*8)-7]
            mov         qword ptr[rdi-(15*8)-7], r9
P7QE:       mov         r9, qword ptr[rsi-(14*8)-7]
            mov         qword ptr[rdi-(14*8)-7], r9
P7QD:       mov         r9, qword ptr[rsi-(13*8)-7]
            mov         qword ptr[rdi-(13*8)-7], r9
P7QC:       mov         r9, qword ptr[rsi-(12*8)-7]
            mov         qword ptr[rdi-(12*8)-7], r9
P7QB:       mov         r9, qword ptr[rsi-(11*8)-7]
            mov         qword ptr[rdi-(11*8)-7], r9
P7QA:       mov         r9, qword ptr[rsi-(10*8)-7]
            mov         qword ptr[rdi-(10*8)-7], r9
P7Q9:       mov         r9, qword ptr[rsi-(9*8)-7]
            mov         qword ptr[rdi-(9*8)-7], r9
P7Q8:       mov         r9, qword ptr[rsi-(8*8)-7]
            mov         qword ptr[rdi-(8*8)-7], r9
P7Q7:       mov         r9, qword ptr[rsi-(7*8)-7]
            mov         qword ptr[rdi-(7*8)-7], r9
P7Q6:       mov         r9, qword ptr[rsi-(6*8)-7]
            mov         qword ptr[rdi-(6*8)-7], r9
P7Q5:       mov         r9, qword ptr[rsi-(5*8)-7]
            mov         qword ptr[rdi-(5*8)-7], r9
P7Q4:       mov         r9, qword ptr[rsi-(4*8)-7]
            mov         qword ptr[rdi-(4*8)-7], r9
P7Q3:       mov         r9, qword ptr[rsi-(3*8)-7]
            mov         qword ptr[rdi-(3*8)-7], r9
P7Q2:       mov         r9, qword ptr[rsi-(2*8)-7]
            mov         qword ptr[rdi-(2*8)-7], r9
P7Q1:       mov         r9, qword ptr[rsi-(1*8)-7]
            mov         qword ptr[rdi-(1*8)-7], r9
P7Q0:       # These trailing loads/stores have to do all their loads 1st, then do the stores
            mov         r9d, dword ptr[rsi-(0*8)-7]
            mov         r10w, word ptr[rsi-(0*8)-3]
            mov         r11b, byte ptr[rsi-(0*8)-1]
            mov         dword ptr[rdi-(0*8)-7], r9d
            mov         word ptr[rdi-(0*8)-3], r10w
            mov         byte ptr[rdi-(0*8)-1], r11b
            ret

    .balign 16
    .type ipath_mic_vectorcpy,@function
    .size ipath_mic_vectorcpy,.-ipath_mic_vectorcpy
    .section .note.GNU-stack,"",@progbits

#endif
