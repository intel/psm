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
# On Oct. 2012
# modified by CQ Tang from __intel_fast_memcpy() for MIC:fastmemcpy-lrb2.S
#
##############################################################################

#
# REGISTER RULES (KNC)
# parameter registers   RDI, RSI, RDX, RCX, R8, R9, ZMM0-ZMM7
# scratch registers     RAX, RCX, RDX, RSI, RDI, R8-R11, ST(0)-ST(7), ZMM0-ZMM31
# callee-save registers RBX, RBP, R12-R15
# registers for return  RAX, RDX, ZMM0, ZMM1, st(0), st(1)
#

#ifdef __MIC__

#
# Since ngo instruction has no performance differentce for PIO,
# we don't use it for now in order to run code on A0 board. In
# future we can re-visit ngo instruction again if necessary.
# #define NGO
#

.intel_syntax noprefix

            .text

            .balign     64
            .global     ipath_mic_vectorpio

#
# Function entry point (tgt = rdi, src = rsi, len = rdx)
# !!!!!!
# this assembly code is only used for 64byte aligned tgt(rdi)!!!
# !!!!!!
#
ipath_mic_vectorpio:
            mov         r8, rdx                 # reassign input arguments
            mov         rax, rdi                # memcpy return the dest address
            test        rsi, 63
            jz          short src_64_aligned

            mov         rcx, rsi
            and         rcx, 3
            jz          short src_4_aligned

            mov         rdx, rsp                 # stack top
            sub         rdx, 256                 # get stack space, big of 160 or 112
            and         rdx, 0xffffffffffffffc0  # aligned end pointers to 64-byte
            lea         r11, fwdPxQx[rip]
            cmp         rcx, 2
            je          short src_2_aligned
            jmp         short src_1_aligned

src_bounce_aligned:
            lea         r11, TailAxDx[rip]
            mov         rsi, rdx
            mov         rdx, rdi
            mov         rcx, rsi
            and         rdx, 0xffffffffffffffc0  # aligned end pointers to 64-byte
            and         rcx, 0xffffffffffffffc0
#if !defined(PIC)
            jmp         qword ptr [r11+r8*8]
#else
            mov         r10, [r11+r8*8]
            lea         r11, [r10+r11]
            jmp         r11
#endif

#
# 1-byte aligned src.
#
            .balign     64
src_1_aligned:
            cmp         r8, 112
            jl          src_1_tail
src_1_loop:
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
            vmovdqa32     [rdx+ 0], zmm0{uint8}
            vmovdqa32     [rdx+16], zmm1{uint8}
            vmovdqa32     [rdx+32], zmm2{uint8}
            vmovdqa32     [rdx+48], zmm3{uint8}

            # loop decrease index (mem size)
            sub         r8, 64

            vmovdqa32   zmm3, [rdx]
            vmovdqa32   [rdi], zmm3
            lea         rdi, [rdi+64]

            # Though we copy 64 bytes at each iteration, we stop iterations
            # when the mem size is less than 112. This is because the last
            # load (vloadunpackhd, see above) is accessing src + 48 + 64,
            # and this address must be valid.
            cmp         r8, 112
            jge         short src_1_loop

src_1_tail:
            # use table to copy tail with GPRs
            add         rdx, r8
            add         rsi, r8
            add         rdi, r8
#if !defined(PIC)
            jmp         qword ptr [r11+r8*8]
#else
            mov         r10, [r11+r8*8]
            lea         r11, [r10+r11]
            jmp         r11
#endif

#
# 2-byte aligned src.
#
            .balign     64
src_2_aligned:
            cmp         r8, 160
            jl          short src_2_tail
src_2_loop:
            vloadunpackld zmm0, [rsi+ 0]{uint16}
            vloadunpackhd zmm0, [rsi+ 0+64]{uint16}
            vloadunpackld zmm1, [rsi+32]{uint16}
            vloadunpackhd zmm1, [rsi+32+64]{uint16}
            vloadunpackld zmm2, [rsi+64]{uint16}
            vloadunpackhd zmm2, [rsi+64+64]{uint16}
            vloadunpackld zmm3, [rsi+96]{uint16}
            vloadunpackhd zmm3, [rsi+96+64]{uint16}
            lea         rsi, [rsi+128]

            # store + loop control
            vmovdqa32   [rdx+ 0], zmm0{uint16}
            vmovdqa32   [rdx+32], zmm1{uint16}
            vmovdqa32   [rdx+64], zmm2{uint16}
            vmovdqa32   [rdx+96], zmm3{uint16}
            
            # loop decrease index (mem size)
            sub         r8, 128

            vmovdqa32   zmm2, [rdx]
            vmovdqa32   zmm3, [rdx+64]
            vmovdqa32   [rdi+ 0], zmm2
            vmovdqa32   [rdi+64], zmm3
            lea         rdi, [rdi+128]

            # Though we copy 128 bytes at each iteration, we stop iterations
            # when the mem size is less than 160. This is because the last
            # load (vloadunpackhd, see above) is accessing src + 96 + 64,
            # and this address must be valid.
            cmp         r8, 160
            jge         short src_2_loop

src_2_tail:
            # use table to copy tail with GPRs
            add         rdx, r8
            add         rsi, r8
            add         rdi, r8
#if !defined(PIC)
            jmp         qword ptr [r11+r8*8]
#else
            mov         r10, [r11+r8*8]
            lea         r11, [r10+r11]
            jmp         r11
#endif

#
# 4-byte aligned src.
#
            .balign     64
src_4_aligned:
            mov         rcx, 128
            cmp         r8, rcx
            jl          short src_4_tail

            mov         r10, 64
            vprefetch0  [rsi]                   # prefetch 1st src line
            vprefetch0  [rsi+ r10]

            mov         rdx, 256
            cmp         r8, rdx
            jl          short src_4_small
            mov         r11, 192

src_4_loop:
            # azv: we are here if size>=256 (r8)
            # rcx holds 128
            # Loop - copy 128 bytes and prefetch next 128

            # process 1st source
            vloadunpackld zmm0, [rsi]
            vloadunpackhd zmm0, [rsi+ r10]
            vprefetch0  [rsi+ rcx]

            # process 2nd source
            vloadunpackld zmm1, [rsi+ r10]
            vloadunpackhd zmm1, [rsi+ rcx]
            vprefetch0  [rsi+ r11]

            add         rsi, rcx
            sub         r8, rcx

#if !defined(NGO)
            # process destinations
            vmovdqa32     [rdi], zmm0
            vmovdqa32     [rdi+ r10], zmm1

            # check end condition
            add         rdi, rcx
            cmp         r8, rdx
            jge         short src_4_loop
#else
            # process destinations using NGO stores

# The current KNC assembler (MPSS 2.1.3126-14) generates incorrect encoding
# for VMOVNRNGOAPS, so we encode it here

#if 1
###         vmovnrngoaps     [rdi], zmm0
            .byte 0x62
            .byte 0xf1
            .byte 0x7b
            .byte 0x88
            .byte 0x29
            .byte 0x07

###         vmovnrngoaps     [rdi+ r10], zmm1
            .byte 0x62
            .byte 0xf1
            .byte 0x7b
            .byte 0x88
            .byte 0x29
            .byte 0x4f
            .byte 0x01
#else
            vmovnrngoaps     [rdi], zmm0
            vmovnrngoaps     [rdi+ r10], zmm1
#endif

            # check end condition
            add         rdi, rcx
            cmp         r8, rdx
            jge         short src_4_loop

            # do sfence
            lock addq [rsp], 0
#endif

src_4_small:
            # azv: we are here if size>=128 (r8) but<256
            # azv: do the rest 128 bytes w/o prefetch

            vloadunpackld zmm0, [rsi]
            vloadunpackhd zmm0, [rsi+ r10]
            vloadunpackld zmm1, [rsi+ r10]
            vloadunpackhd zmm1, [rsi+ rcx]
            add         rsi, rcx
            sub         r8, rcx
            vmovdqa32     [rdi], zmm0
            vmovdqa32     [rdi+ r10], zmm1
            add         rdi, rcx
            cmp         r8, 0
            jg          short src_4_tail
            ret

src_4_tail:
            # azv: we are here if size<128 (r8)

            lea         r11, TailUxDx[rip]
            add         rdi, r8                     # set end of buffers
            add         rsi, r8
            mov         rdx, rdi
            mov         rcx, rsi
            and         rdx, 0xffffffffffffffc0     # aligned end pointers to 64-byte
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
# 64-byte aligned src.
#
            .balign     64
src_64_aligned:
            mov         rcx, 128
            cmp         r8, rcx
            jl          short src_64_tail

            mov         r10, 64
            vprefetch0  [rsi]                   # prefetch 1st src line
            vprefetch0  [rsi+ r10]

            mov         rdx, 256
            cmp         r8, rdx
            jl          short src_64_small
            mov         r11, 192

src_64_loop:
            # azv: we are here if size>=256 (r8)
            # rcx holds 128
            # Loop - copy 128 bytes and prefetch next 128

            # process sources first
            vmovdqa32      zmm0, [rsi]
            vprefetch0  [rsi+ rcx]
            vmovdqa32      zmm1, [rsi+ r10]
            vprefetch0  [rsi+ r11]

            # loop decrease indexes
            add         rsi, rcx
            sub         r8, rcx

#if !defined(NGO)
            # process destinations
            vmovdqa32     [rdi], zmm0
            vmovdqa32     [rdi+ r10], zmm1

            # check end condition
            add         rdi, rcx
            cmp         r8, rdx
            jge         short src_64_loop
#else
            # process destinations using NGO stores

# The current KNC assembler (MPSS 2.1.3126-14) generates incorrect encoding
# for VMOVNRNGOAPS, so we encode it here

#if 1
###         vmovnrngoaps     [rdi], zmm0
            .byte 0x62
            .byte 0xf1
            .byte 0x7b
            .byte 0x88
            .byte 0x29
            .byte 0x07

###         vmovnrngoaps     [rdi+ r10], zmm1
            .byte 0x62
            .byte 0xf1
            .byte 0x7b
            .byte 0x88
            .byte 0x29
            .byte 0x4f
            .byte 0x01
#else
            vmovnrngoaps     [rdi], zmm0
            vmovnrngoaps     [rdi+ r10], zmm1
#endif

            # check end condition
            add         rdi, rcx
            cmp         r8, rdx
            jge         short src_64_loop

            # do sfence
            lock addq [rsp], 0
#endif

src_64_small:
            # azv: we are here if size>=128 (r8) but<256
            # azv: do the rest 128 bytes w/o prefetch

            vmovdqa32      zmm0, [rsi]
            vmovdqa32      zmm1, [rsi+ r10]
            add         rsi, rcx
            sub         r8, rcx
            vmovdqa32     [rdi], zmm0
            vmovdqa32     [rdi+ r10], zmm1
            add         rdi, rcx
            cmp         r8, 0
            jg          short src_64_tail
            ret

src_64_tail:
            # azv: we are here if size<128 (r8)

            lea         r11, TailAxDx[rip]
            add         rdi, r8                     # set end of buffers
            add         rsi, r8
            mov         rdx, rdi
            mov         rcx, rsi
            and         rdx, 0xffffffffffffffc0     # aligned end pointers to 64-byte
            and         rcx, 0xffffffffffffffc0

#if !defined(PIC)
            jmp         qword ptr [r11+r8*8]
#else
            mov         r10, [r11+r8*8]
            lea         r11, [r10+r11]
            jmp         r11
#endif

#
# LRB move buffer tail (src and dst are 64-byte aligned)
#
            .balign     16
#if !defined(PIC)
TailAxDx:   .quad       TAxQ0,TA1Q0,TA2Q0,TA3Q0,TA0Q1,TA1Q1,TA2Q1,TA3Q1
            .quad       TA0Q1,TA1Q1,TA2Q1,TA3Q1,TA0Q1,TA1Q1,TA2Q1,TA3Q1
            .quad       TA0Q1,TA1Q1,TA2Q1,TA3Q1,TA0Q1,TA1Q1,TA2Q1,TA3Q1
            .quad       TA0Q1,TA1Q1,TA2Q1,TA3Q1,TA0Q1,TA1Q1,TA2Q1,TA3Q1
            .quad       TA0Q1,TA1Q1,TA2Q1,TA3Q1,TA0Q1,TA1Q1,TA2Q1,TA3Q1
            .quad       TA0Q1,TA1Q1,TA2Q1,TA3Q1,TA0Q1,TA1Q1,TA2Q1,TA3Q1
            .quad       TA0Q1,TA1Q1,TA2Q1,TA3Q1,TA0Q1,TA1Q1,TA2Q1,TA3Q1
            .quad       TA0Q1,TA1Q1,TA2Q1,TA3Q1,TA0Q1,TA1Q1,TA2Q1,TA3Q1     # up to 64 bytes
            .quad       TAxQ2,TA1Q2,TA2Q2,TA3Q2,TA0Q2,TA1Q2,TA2Q2,TA3Q2
            .quad       TA0Q2,TA1Q2,TA2Q2,TA3Q2,TA0Q2,TA1Q2,TA2Q2,TA3Q2
            .quad       TA0Q2,TA1Q2,TA2Q2,TA3Q2,TA0Q2,TA1Q2,TA2Q2,TA3Q2
            .quad       TA0Q2,TA1Q2,TA2Q2,TA3Q2,TA0Q2,TA1Q2,TA2Q2,TA3Q2
            .quad       TA0Q2,TA1Q2,TA2Q2,TA3Q2,TA0Q2,TA1Q2,TA2Q2,TA3Q2
            .quad       TA0Q2,TA1Q2,TA2Q2,TA3Q2,TA0Q2,TA1Q2,TA2Q2,TA3Q2
            .quad       TA0Q2,TA1Q2,TA2Q2,TA3Q2,TA0Q2,TA1Q2,TA2Q2,TA3Q2
            .quad       TA0Q2,TA1Q2,TA2Q2,TA3Q2,TA0Q2,TA1Q2,TA2Q2,TA3Q2     # up to 128 bytes
            .quad       TAxQ3,TA1Q3,TA2Q3,TA3Q3,TA0Q3,TA1Q3,TA2Q3,TA3Q3
            .quad       TA0Q3,TA1Q3,TA2Q3,TA3Q3,TA0Q3,TA1Q3,TA2Q3,TA3Q3
            .quad       TA0Q3,TA1Q3,TA2Q3,TA3Q3,TA0Q3,TA1Q3,TA2Q3,TA3Q3
            .quad       TA0Q3,TA1Q3,TA2Q3,TA3Q3,TA0Q3,TA1Q3,TA2Q3,TA3Q3
            .quad       TA0Q3,TA1Q3,TA2Q3,TA3Q3,TA0Q3,TA1Q3,TA2Q3,TA3Q3
            .quad       TA0Q3,TA1Q3,TA2Q3,TA3Q3,TA0Q3,TA1Q3,TA2Q3,TA3Q3
            .quad       TA0Q3,TA1Q3,TA2Q3,TA3Q3,TA0Q3,TA1Q3,TA2Q3,TA3Q3
            .quad       TA0Q3,TA1Q3,TA2Q3,TA3Q3,TA0Q3,TA1Q3,TA2Q3,TA3Q3     # up to 192 bytes
            .quad       TAxQ4,TA1Q4,TA2Q4,TA3Q4,TA0Q4,TA1Q4,TA2Q4,TA3Q4
            .quad       TA0Q4,TA1Q4,TA2Q4,TA3Q4,TA0Q4,TA1Q4,TA2Q4,TA3Q4
            .quad       TA0Q4,TA1Q4,TA2Q4,TA3Q4,TA0Q4,TA1Q4,TA2Q4,TA3Q4
            .quad       TA0Q4,TA1Q4,TA2Q4,TA3Q4,TA0Q4,TA1Q4,TA2Q4,TA3Q4
            .quad       TA0Q4,TA1Q4,TA2Q4,TA3Q4,TA0Q4,TA1Q4,TA2Q4,TA3Q4
            .quad       TA0Q4,TA1Q4,TA2Q4,TA3Q4,TA0Q4,TA1Q4,TA2Q4,TA3Q4
            .quad       TA0Q4,TA1Q4,TA2Q4,TA3Q4,TA0Q4,TA1Q4,TA2Q4,TA3Q4
            .quad       TA0Q4,TA1Q4,TA2Q4,TA3Q4,TA0Q4,TA1Q4,TA2Q4,TA3Q4     # up to 256 bytes
            .quad       TAxQ5,TA1Q5,TA2Q5,TA3Q5,TA0Q5,TA1Q5,TA2Q5,TA3Q5
            .quad       TA0Q5,TA1Q5,TA2Q5,TA3Q5,TA0Q5,TA1Q5,TA2Q5,TA3Q5
            .quad       TA0Q5,TA1Q5,TA2Q5,TA3Q5,TA0Q5,TA1Q5,TA2Q5,TA3Q5
            .quad       TA0Q5,TA1Q5,TA2Q5,TA3Q5,TA0Q5,TA1Q5,TA2Q5,TA3Q5
            .quad       TA0Q5,TA1Q5,TA2Q5,TA3Q5,TA0Q5,TA1Q5,TA2Q5,TA3Q5
            .quad       TA0Q5,TA1Q5,TA2Q5,TA3Q5,TA0Q5,TA1Q5,TA2Q5,TA3Q5
            .quad       TA0Q5,TA1Q5,TA2Q5,TA3Q5,TA0Q5,TA1Q5,TA2Q5,TA3Q5
            .quad       TA0Q5,TA1Q5,TA2Q5,TA3Q5,TA0Q5,TA1Q5,TA2Q5,TA3Q5     # up to 320 bytes
#else
TailAxDx:   .quad       TAxQ0-TailAxDx
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

            .quad       TA0Q1-TailAxDx
            .quad       TA1Q1-TailAxDx
            .quad       TA2Q1-TailAxDx
            .quad       TA3Q1-TailAxDx
            .quad       TA0Q1-TailAxDx
            .quad       TA1Q1-TailAxDx
            .quad       TA2Q1-TailAxDx
            .quad       TA3Q1-TailAxDx     # up to 64 bytes

            .quad       TAxQ2-TailAxDx
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

            .quad       TAxQ3-TailAxDx
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

            .quad       TAxQ4-TailAxDx
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

            .quad       TAxQ5-TailAxDx
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
#
# multiple 64bytes(including 0), r8%64==0
#
TAxQ5:      vmovdqa32      zmm0, [rcx-256]
            vmovdqa32     [rdx-256], zmm0
TAxQ4:      vmovdqa32      zmm0, [rcx-192]
            vmovdqa32     [rdx-192], zmm0
TAxQ3:      vmovdqa32      zmm0, [rcx-128]
            vmovdqa32     [rdx-128], zmm0
TAxQ2:      vmovdqa32      zmm0, [rcx- 64]
            vmovdqa32     [rdx- 64], zmm0
TAxQ0:      ret

#
# multiple 4bytes, r8%4==0
#
TA0Q5:      vmovdqa32      zmm0, [rcx-256]
            vmovdqa32     [rdx-256], zmm0
TA0Q4:      vmovdqa32      zmm0, [rcx-192]
            vmovdqa32     [rdx-192], zmm0
TA0Q3:      vmovdqa32      zmm0, [rcx-128]
            vmovdqa32     [rdx-128], zmm0
TA0Q2:      vmovdqa32      zmm0, [rcx- 64]
            vmovdqa32     [rdx- 64], zmm0
TA0Q1:      vloadunpackhd zmm0, [rsi-0]
            vpackstorehd [rdi-0], zmm0
            ret

#
# multiple 4bytes + 1, r8%4==1
#
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

#
# multiple 4bytes + 2, r8%4==2
#
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

#
# multiple 4bytes + 3, r8%4==3
#
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
# LRB move buffer tail (dst is 64-byte aligned, src is 4-byte aligned)
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
TU0Q1:      vloadunpackld zmm0, [rsi-64]
            vloadunpackhd zmm0, [rsi]
            vpackstorehd [rdi], zmm0
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
# LRB move buffer tail (dst is 64-byte aligned, src is 2-byte/1-byte aligned)
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
            mov         qword ptr[rdx-(22*8)-0], r9
P0QL:       mov         r9, qword ptr[rsi-(21*8)-0]
            mov         qword ptr[rdx-(21*8)-0], r9
P0QK:       mov         r9, qword ptr[rsi-(20*8)-0]
            mov         qword ptr[rdx-(20*8)-0], r9
P0QJ:       mov         r9, qword ptr[rsi-(19*8)-0]
            mov         qword ptr[rdx-(19*8)-0], r9
P0QI:       mov         r9, qword ptr[rsi-(18*8)-0]
            mov         qword ptr[rdx-(18*8)-0], r9
P0QH:       mov         r9, qword ptr[rsi-(17*8)-0]
            mov         qword ptr[rdx-(17*8)-0], r9
P0QG:       mov         r9, qword ptr[rsi-(16*8)-0]
            mov         qword ptr[rdx-(16*8)-0], r9
P0QF:       mov         r9, qword ptr[rsi-(15*8)-0]
            mov         qword ptr[rdx-(15*8)-0], r9
P0QE:       mov         r9, qword ptr[rsi-(14*8)-0]
            mov         qword ptr[rdx-(14*8)-0], r9
P0QD:       mov         r9, qword ptr[rsi-(13*8)-0]
            mov         qword ptr[rdx-(13*8)-0], r9
P0QC:       mov         r9, qword ptr[rsi-(12*8)-0]
            mov         qword ptr[rdx-(12*8)-0], r9
P0QB:       mov         r9, qword ptr[rsi-(11*8)-0]
            mov         qword ptr[rdx-(11*8)-0], r9
P0QA:       mov         r9, qword ptr[rsi-(10*8)-0]
            mov         qword ptr[rdx-(10*8)-0], r9
P0Q9:       mov         r9, qword ptr[rsi-(9*8)-0]
            mov         qword ptr[rdx-(9*8)-0], r9
P0Q8:       mov         r9, qword ptr[rsi-(8*8)-0]
            mov         qword ptr[rdx-(8*8)-0], r9
P0Q7:       mov         r9, qword ptr[rsi-(7*8)-0]
            mov         qword ptr[rdx-(7*8)-0], r9
P0Q6:       mov         r9, qword ptr[rsi-(6*8)-0]
            mov         qword ptr[rdx-(6*8)-0], r9
P0Q5:       mov         r9, qword ptr[rsi-(5*8)-0]
            mov         qword ptr[rdx-(5*8)-0], r9
P0Q4:       mov         r9, qword ptr[rsi-(4*8)-0]
            mov         qword ptr[rdx-(4*8)-0], r9
P0Q3:       mov         r9, qword ptr[rsi-(3*8)-0]
            mov         qword ptr[rdx-(3*8)-0], r9
P0Q2:       mov         r9, qword ptr[rsi-(2*8)-0]
            mov         qword ptr[rdx-(2*8)-0], r9
P0Q1:       mov         r9, qword ptr[rsi-(1*8)-0]
            mov         qword ptr[rdx-(1*8)-0], r9
            jmp         src_bounce_aligned
P0Q0:       ret

P1QM:       mov         r9, qword ptr[rsi-(22*8)-1]
            mov         qword ptr[rdx-(22*8)-1], r9
P1QL:       mov         r9, qword ptr[rsi-(21*8)-1]
            mov         qword ptr[rdx-(21*8)-1], r9
P1QK:       mov         r9, qword ptr[rsi-(20*8)-1]
            mov         qword ptr[rdx-(20*8)-1], r9
P1QJ:       mov         r9, qword ptr[rsi-(19*8)-1]
            mov         qword ptr[rdx-(19*8)-1], r9
P1QI:       mov         r9, qword ptr[rsi-(18*8)-1]
            mov         qword ptr[rdx-(18*8)-1], r9
P1QH:       mov         r9, qword ptr[rsi-(17*8)-1]
            mov         qword ptr[rdx-(17*8)-1], r9
P1QG:       mov         r9, qword ptr[rsi-(16*8)-1]
            mov         qword ptr[rdx-(16*8)-1], r9
P1QF:       mov         r9, qword ptr[rsi-(15*8)-1]
            mov         qword ptr[rdx-(15*8)-1], r9
P1QE:       mov         r9, qword ptr[rsi-(14*8)-1]
            mov         qword ptr[rdx-(14*8)-1], r9
P1QD:       mov         r9, qword ptr[rsi-(13*8)-1]
            mov         qword ptr[rdx-(13*8)-1], r9
P1QC:       mov         r9, qword ptr[rsi-(12*8)-1]
            mov         qword ptr[rdx-(12*8)-1], r9
P1QB:       mov         r9, qword ptr[rsi-(11*8)-1]
            mov         qword ptr[rdx-(11*8)-1], r9
P1QA:       mov         r9, qword ptr[rsi-(10*8)-1]
            mov         qword ptr[rdx-(10*8)-1], r9
P1Q9:       mov         r9,  qword ptr[rsi-(9*8)-1]
            mov         qword ptr[rdx-(9*8)-1], r9
P1Q8:       mov         r9, qword ptr[rsi-(8*8)-1]
            mov         qword ptr[rdx-(8*8)-1], r9
P1Q7:       mov         r9, qword ptr[rsi-(7*8)-1]
            mov         qword ptr[rdx-(7*8)-1], r9
P1Q6:       mov         r9,  qword ptr[rsi-(6*8)-1]
            mov         qword ptr[rdx-(6*8)-1], r9
P1Q5:       mov         r9, qword ptr[rsi-(5*8)-1]
            mov         qword ptr[rdx-(5*8)-1], r9
P1Q4:       mov         r9, qword ptr[rsi-(4*8)-1]
            mov         qword ptr[rdx-(4*8)-1], r9
P1Q3:       mov         r9, qword ptr[rsi-(3*8)-1]
            mov         qword ptr[rdx-(3*8)-1], r9
P1Q2:       mov         r9, qword ptr[rsi-(2*8)-1]
            mov         qword ptr[rdx-(2*8)-1], r9
P1Q1:       mov         r9, qword ptr[rsi-(1*8)-1]
            mov         qword ptr[rdx-(1*8)-1], r9
            # These trailing loads/stores have to do all their loads 1st, then do the stores
            mov         r9b, byte ptr[rsi-(0*8)-1]
            mov         byte ptr[rdx-(0*8)-1], r9b
            jmp         src_bounce_aligned
P1Q0:       # These trailing loads/stores have to do all their loads 1st, then do the stores
            mov         r9b, byte ptr[rsi-(0*8)-1]
            mov         byte ptr[rdi-(0*8)-1], r9b
            ret

P2QM:       mov         r9, qword ptr[rsi-(22*8)-2]
            mov         qword ptr[rdx-(22*8)-2], r9
P2QL:       mov         r9, qword ptr[rsi-(21*8)-2]
            mov         qword ptr[rdx-(21*8)-2], r9
P2QK:       mov         r9, qword ptr[rsi-(20*8)-2]
            mov         qword ptr[rdx-(20*8)-2], r9
P2QJ:       mov         r9, qword ptr[rsi-(19*8)-2]
            mov         qword ptr[rdx-(19*8)-2], r9
P2QI:       mov         r9, qword ptr[rsi-(18*8)-2]
            mov         qword ptr[rdx-(18*8)-2], r9
P2QH:       mov         r9, qword ptr[rsi-(17*8)-2]
            mov         qword ptr[rdx-(17*8)-2], r9
P2QG:       mov         r9, qword ptr[rsi-(16*8)-2]
            mov         qword ptr[rdx-(16*8)-2], r9
P2QF:       mov         r9, qword ptr[rsi-(15*8)-2]
            mov         qword ptr[rdx-(15*8)-2], r9
P2QE:       mov         r9, qword ptr[rsi-(14*8)-2]
            mov         qword ptr[rdx-(14*8)-2], r9
P2QD:       mov         r9, qword ptr[rsi-(13*8)-2]
            mov         qword ptr[rdx-(13*8)-2], r9
P2QC:       mov         r9, qword ptr[rsi-(12*8)-2]
            mov         qword ptr[rdx-(12*8)-2], r9
P2QB:       mov         r9, qword ptr[rsi-(11*8)-2]
            mov         qword ptr[rdx-(11*8)-2], r9
P2QA:       mov         r9, qword ptr[rsi-(10*8)-2]
            mov         qword ptr[rdx-(10*8)-2], r9
P2Q9:       mov         r9, qword ptr[rsi-(9*8)-2]
            mov         qword ptr[rdx-(9*8)-2], r9
P2Q8:       mov         r9, qword ptr[rsi-(8*8)-2]
            mov         qword ptr[rdx-(8*8)-2], r9
P2Q7:       mov         r9, qword ptr[rsi-(7*8)-2]
            mov         qword ptr[rdx-(7*8)-2], r9
P2Q6:       mov         r9, qword ptr[rsi-(6*8)-2]
            mov         qword ptr[rdx-(6*8)-2], r9
P2Q5:       mov         r9, qword ptr[rsi-(5*8)-2]
            mov         qword ptr[rdx-(5*8)-2], r9
P2Q4:       mov         r9, qword ptr[rsi-(4*8)-2]
            mov         qword ptr[rdx-(4*8)-2], r9
P2Q3:       mov         r9, qword ptr[rsi-(3*8)-2]
            mov         qword ptr[rdx-(3*8)-2], r9
P2Q2:       mov         r9, qword ptr[rsi-(2*8)-2]
            mov         qword ptr[rdx-(2*8)-2], r9
P2Q1:       mov         r9, qword ptr[rsi-(1*8)-2]
            mov         qword ptr[rdx-(1*8)-2], r9
            # These trailing loads/stores have to do all their loads 1st, then do the stores
            mov         r9w, word ptr[rsi-(0*8)-2]
            mov         word ptr[rdx-(0*8)-2], r9w
            jmp         src_bounce_aligned
P2Q0:       # These trailing loads/stores have to do all their loads 1st, then do the stores
            mov         r9w, word ptr[rsi-(0*8)-2]
            mov         word ptr[rdi-(0*8)-2], r9w
            ret

P3QM:       mov         r9, qword ptr[rsi-(22*8)-3]
            mov         qword ptr[rdx-(22*8)-3], r9
P3QL:       mov         r9, qword ptr[rsi-(21*8)-3]
            mov         qword ptr[rdx-(21*8)-3], r9
P3QK:       mov         r9, qword ptr[rsi-(20*8)-3]
            mov         qword ptr[rdx-(20*8)-3], r9
P3QJ:       mov         r9, qword ptr[rsi-(19*8)-3]
            mov         qword ptr[rdx-(19*8)-3], r9
P3QI:       mov         r9, qword ptr[rsi-(18*8)-3]
            mov         qword ptr[rdx-(18*8)-3], r9
P3QH:       mov         r9, qword ptr[rsi-(17*8)-3]
            mov         qword ptr[rdx-(17*8)-3], r9
P3QG:       mov         r9, qword ptr[rsi-(16*8)-3]
            mov         qword ptr[rdx-(16*8)-3], r9
P3QF:       mov         r9, qword ptr[rsi-(15*8)-3]
            mov         qword ptr[rdx-(15*8)-3], r9
P3QE:       mov         r9, qword ptr[rsi-(14*8)-3]
            mov         qword ptr[rdx-(14*8)-3], r9
P3QD:       mov         r9, qword ptr[rsi-(13*8)-3]
            mov         qword ptr[rdx-(13*8)-3], r9
P3QC:       mov         r9, qword ptr[rsi-(12*8)-3]
            mov         qword ptr[rdx-(12*8)-3], r9
P3QB:       mov         r9, qword ptr[rsi-(11*8)-3]
            mov         qword ptr[rdx-(11*8)-3], r9
P3QA:       mov         r9, qword ptr[rsi-(10*8)-3]
            mov         qword ptr[rdx-(10*8)-3], r9
P3Q9:       mov         r9, qword ptr[rsi-(9*8)-3]
            mov         qword ptr[rdx-(9*8)-3], r9
P3Q8:       mov         r9, qword ptr[rsi-(8*8)-3]
            mov         qword ptr[rdx-(8*8)-3], r9
P3Q7:       mov         r9, qword ptr[rsi-(7*8)-3]
            mov         qword ptr[rdx-(7*8)-3], r9
P3Q6:       mov         r9, qword ptr[rsi-(6*8)-3]
            mov         qword ptr[rdx-(6*8)-3], r9
P3Q5:       mov         r9, qword ptr[rsi-(5*8)-3]
            mov         qword ptr[rdx-(5*8)-3], r9
P3Q4:       mov         r9, qword ptr[rsi-(4*8)-3]
            mov         qword ptr[rdx-(4*8)-3], r9
P3Q3:       mov         r9, qword ptr[rsi-(3*8)-3]
            mov         qword ptr[rdx-(3*8)-3], r9
P3Q2:       mov         r9, qword ptr[rsi-(2*8)-3]
            mov         qword ptr[rdx-(2*8)-3], r9
P3Q1:       mov         r9, qword ptr[rsi-(1*8)-3]
            mov         qword ptr[rdx-(1*8)-3], r9
            # These trailing loads/stores have to do all their loads 1st, then do the stores
            mov         r9w, word ptr[rsi-(0*8)-3]
            mov         r10b, byte ptr[rsi-(0*8)-1]
            mov         word ptr[rdx-(0*8)-3], r9w
            mov         byte ptr[rdx-(0*8)-1], r10b
            jmp         src_bounce_aligned
P3Q0:       # These trailing loads/stores have to do all their loads 1st, then do the stores
            mov         r9w, word ptr[rsi-(0*8)-3]
            mov         r10b, byte ptr[rsi-(0*8)-1]
            mov         word ptr[rdi-(0*8)-3], r9w
            mov         byte ptr[rdi-(0*8)-1], r10b
            ret

P4QM:       mov         r9, qword ptr[rsi-(22*8)-4]
            mov         qword ptr[rdx-(22*8)-4], r9
P4QL:       mov         r9, qword ptr[rsi-(21*8)-4]
            mov         qword ptr[rdx-(21*8)-4], r9
P4QK:       mov         r9, qword ptr[rsi-(20*8)-4]
            mov         qword ptr[rdx-(20*8)-4], r9
P4QJ:       mov         r9, qword ptr[rsi-(19*8)-4]
            mov         qword ptr[rdx-(19*8)-4], r9
P4QI:       mov         r9, qword ptr[rsi-(18*8)-4]
            mov         qword ptr[rdx-(18*8)-4], r9
P4QH:       mov         r9, qword ptr[rsi-(17*8)-4]
            mov         qword ptr[rdx-(17*8)-4], r9
P4QG:       mov         r9, qword ptr[rsi-(16*8)-4]
            mov         qword ptr[rdx-(16*8)-4], r9
P4QF:       mov         r9, qword ptr[rsi-(15*8)-4]
            mov         qword ptr[rdx-(15*8)-4], r9
P4QE:       mov         r9, qword ptr[rsi-(14*8)-4]
            mov         qword ptr[rdx-(14*8)-4], r9
P4QD:       mov         r9, qword ptr[rsi-(13*8)-4]
            mov         qword ptr[rdx-(13*8)-4], r9
P4QC:       mov         r9, qword ptr[rsi-(12*8)-4]
            mov         qword ptr[rdx-(12*8)-4], r9
P4QB:       mov         r9, qword ptr[rsi-(11*8)-4]
            mov         qword ptr[rdx-(11*8)-4], r9
P4QA:       mov         r9, qword ptr[rsi-(10*8)-4]
            mov         qword ptr[rdx-(10*8)-4], r9
P4Q9:       mov         r9, qword ptr[rsi-(9*8)-4]
            mov         qword ptr[rdx-(9*8)-4], r9
P4Q8:       mov         r9, qword ptr[rsi-(8*8)-4]
            mov         qword ptr[rdx-(8*8)-4], r9
P4Q7:       mov         r9, qword ptr[rsi-(7*8)-4]
            mov         qword ptr[rdx-(7*8)-4], r9
P4Q6:       mov         r9, qword ptr[rsi-(6*8)-4]
            mov         qword ptr[rdx-(6*8)-4], r9
P4Q5:       mov         r9, qword ptr[rsi-(5*8)-4]
            mov         qword ptr[rdx-(5*8)-4], r9
P4Q4:       mov         r9, qword ptr[rsi-(4*8)-4]
            mov         qword ptr[rdx-(4*8)-4], r9
P4Q3:       mov         r9, qword ptr[rsi-(3*8)-4]
            mov         qword ptr[rdx-(3*8)-4], r9
P4Q2:       mov         r9, qword ptr[rsi-(2*8)-4]
            mov         qword ptr[rdx-(2*8)-4], r9
P4Q1:       mov         r9, qword ptr[rsi-(1*8)-4]
            mov         qword ptr[rdx-(1*8)-4], r9
            # These trailing loads/stores have to do all their loads 1st, then do the stores
            mov         r9d, dword ptr[rsi-(0*8)-4]
            mov         dword ptr[rdx-(0*8)-4], r9d
            jmp         src_bounce_aligned
P4Q0:       # These trailing loads/stores have to do all their loads 1st, then do the stores
            mov         r9d, dword ptr[rsi-(0*8)-4]
            mov         dword ptr[rdi-(0*8)-4], r9d
            ret

P5QM:       mov         r9, qword ptr[rsi-(22*8)-5]
            mov         qword ptr[rdx-(22*8)-5], r9
P5QL:       mov         r9, qword ptr[rsi-(21*8)-5]
            mov         qword ptr[rdx-(21*8)-5], r9
P5QK:       mov         r9, qword ptr[rsi-(20*8)-5]
            mov         qword ptr[rdx-(20*8)-5], r9
P5QJ:       mov         r9, qword ptr[rsi-(19*8)-5]
            mov         qword ptr[rdx-(19*8)-5], r9
P5QI:       mov         r9, qword ptr[rsi-(18*8)-5]
            mov         qword ptr[rdx-(18*8)-5], r9
P5QH:       mov         r9, qword ptr[rsi-(17*8)-5]
            mov         qword ptr[rdx-(17*8)-5], r9
P5QG:       mov         r9, qword ptr[rsi-(16*8)-5]
            mov         qword ptr[rdx-(16*8)-5], r9
P5QF:       mov         r9, qword ptr[rsi-(15*8)-5]
            mov         qword ptr[rdx-(15*8)-5], r9
P5QE:       mov         r9, qword ptr[rsi-(14*8)-5]
            mov         qword ptr[rdx-(14*8)-5], r9
P5QD:       mov         r9, qword ptr[rsi-(13*8)-5]
            mov         qword ptr[rdx-(13*8)-5], r9
P5QC:       mov         r9, qword ptr[rsi-(12*8)-5]
            mov         qword ptr[rdx-(12*8)-5], r9
P5QB:       mov         r9, qword ptr[rsi-(11*8)-5]
            mov         qword ptr[rdx-(11*8)-5], r9
P5QA:       mov         r9, qword ptr[rsi-(10*8)-5]
            mov         qword ptr[rdx-(10*8)-5], r9
P5Q9:       mov         r9, qword ptr[rsi-(9*8)-5]
            mov         qword ptr[rdx-(9*8)-5], r9
P5Q8:       mov         r9, qword ptr[rsi-(8*8)-5]
            mov         qword ptr[rdx-(8*8)-5], r9
P5Q7:       mov         r9, qword ptr[rsi-(7*8)-5]
            mov         qword ptr[rdx-(7*8)-5], r9
P5Q6:       mov         r9, qword ptr[rsi-(6*8)-5]
            mov         qword ptr[rdx-(6*8)-5], r9
P5Q5:       mov         r9, qword ptr[rsi-(5*8)-5]
            mov         qword ptr[rdx-(5*8)-5], r9
P5Q4:       mov         r9, qword ptr[rsi-(4*8)-5]
            mov         qword ptr[rdx-(4*8)-5], r9
P5Q3:       mov         r9, qword ptr[rsi-(3*8)-5]
            mov         qword ptr[rdx-(3*8)-5], r9
P5Q2:       mov         r9, qword ptr[rsi-(2*8)-5]
            mov         qword ptr[rdx-(2*8)-5], r9
P5Q1:       mov         r9, qword ptr[rsi-(1*8)-5]
            mov         qword ptr[rdx-(1*8)-5], r9
            # These trailing loads/stores have to do all their loads 1st, then do the stores
            mov         r9d, dword ptr[rsi-(0*8)-5]
            mov         r10b, byte ptr[rsi-(0*8)-1]
            mov         dword ptr[rdx-(0*8)-5], r9d
            mov         byte ptr[rdx-(0*8)-1], r10b
            jmp         src_bounce_aligned
P5Q0:       # These trailing loads/stores have to do all their loads 1st, then do the stores
            mov         r9d, dword ptr[rsi-(0*8)-5]
            mov         r10b, byte ptr[rsi-(0*8)-1]
            mov         dword ptr[rdi-(0*8)-5], r9d
            mov         byte ptr[rdi-(0*8)-1], r10b
            ret

P6QM:       mov         r9, qword ptr[rsi-(22*8)-6]
            mov         qword ptr[rdx-(22*8)-6], r9
P6QL:       mov         r9, qword ptr[rsi-(21*8)-6]
            mov         qword ptr[rdx-(21*8)-6], r9
P6QK:       mov         r9, qword ptr[rsi-(20*8)-6]
            mov         qword ptr[rdx-(20*8)-6], r9
P6QJ:       mov         r9, qword ptr[rsi-(19*8)-6]
            mov         qword ptr[rdx-(19*8)-6], r9
P6QI:       mov         r9, qword ptr[rsi-(18*8)-6]
            mov         qword ptr[rdx-(18*8)-6], r9
P6QH:       mov         r9, qword ptr[rsi-(17*8)-6]
            mov         qword ptr[rdx-(17*8)-6], r9
P6QG:       mov         r9, qword ptr[rsi-(16*8)-6]
            mov         qword ptr[rdx-(16*8)-6], r9
P6QF:       mov         r9, qword ptr[rsi-(15*8)-6]
            mov         qword ptr[rdx-(15*8)-6], r9
P6QE:       mov         r9, qword ptr[rsi-(14*8)-6]
            mov         qword ptr[rdx-(14*8)-6], r9
P6QD:       mov         r9, qword ptr[rsi-(13*8)-6]
            mov         qword ptr[rdx-(13*8)-6], r9
P6QC:       mov         r9, qword ptr[rsi-(12*8)-6]
            mov         qword ptr[rdx-(12*8)-6], r9
P6QB:       mov         r9, qword ptr[rsi-(11*8)-6]
            mov         qword ptr[rdx-(11*8)-6], r9
P6QA:       mov         r9, qword ptr[rsi-(10*8)-6]
            mov         qword ptr[rdx-(10*8)-6], r9
P6Q9:       mov         r9, qword ptr[rsi-(9*8)-6]
            mov         qword ptr[rdx-(9*8)-6], r9
P6Q8:       mov         r9, qword ptr[rsi-(8*8)-6]
            mov         qword ptr[rdx-(8*8)-6], r9
P6Q7:       mov         r9, qword ptr[rsi-(7*8)-6]
            mov         qword ptr[rdx-(7*8)-6], r9
P6Q6:       mov         r9, qword ptr[rsi-(6*8)-6]
            mov         qword ptr[rdx-(6*8)-6], r9
P6Q5:       mov         r9, qword ptr[rsi-(5*8)-6]
            mov         qword ptr[rdx-(5*8)-6], r9
P6Q4:       mov         r9, qword ptr[rsi-(4*8)-6]
            mov         qword ptr[rdx-(4*8)-6], r9
P6Q3:       mov         r9, qword ptr[rsi-(3*8)-6]
            mov         qword ptr[rdx-(3*8)-6], r9
P6Q2:       mov         r9, qword ptr[rsi-(2*8)-6]
            mov         qword ptr[rdx-(2*8)-6], r9
P6Q1:       mov         r9, qword ptr[rsi-(1*8)-6]
            mov         qword ptr[rdx-(1*8)-6], r9
            # These trailing loads/stores have to do all their loads 1st, then do the stores
            mov         r9d, dword ptr[rsi-(0*8)-6]
            mov         r10w, word ptr[rsi-(0*8)-2]
            mov         dword ptr[rdx-(0*8)-6], r9d
            mov         word ptr[rdx-(0*8)-2], r10w
            jmp         src_bounce_aligned
P6Q0:       # These trailing loads/stores have to do all their loads 1st, then do the stores
            mov         r9d, dword ptr[rsi-(0*8)-6]
            mov         r10w, word ptr[rsi-(0*8)-2]
            mov         dword ptr[rdi-(0*8)-6], r9d
            mov         word ptr[rdi-(0*8)-2], r10w
            ret

P7QM:       mov         r9, qword ptr[rsi-(22*8)-7]
            mov         qword ptr[rdx-(22*8)-7], r9
P7QL:       mov         r9, qword ptr[rsi-(21*8)-7]
            mov         qword ptr[rdx-(21*8)-7], r9
P7QK:       mov         r9, qword ptr[rsi-(20*8)-7]
            mov         qword ptr[rdx-(20*8)-7], r9
P7QJ:       mov         r9, qword ptr[rsi-(19*8)-7]
            mov         qword ptr[rdx-(19*8)-7], r9
P7QI:       mov         r9, qword ptr[rsi-(18*8)-7]
            mov         qword ptr[rdx-(18*8)-7], r9
P7QH:       mov         r9, qword ptr[rsi-(17*8)-7]
            mov         qword ptr[rdx-(17*8)-7], r9
P7QG:       mov         r9, qword ptr[rsi-(16*8)-7]
            mov         qword ptr[rdx-(16*8)-7], r9
P7QF:       mov         r9, qword ptr[rsi-(15*8)-7]
            mov         qword ptr[rdx-(15*8)-7], r9
P7QE:       mov         r9, qword ptr[rsi-(14*8)-7]
            mov         qword ptr[rdx-(14*8)-7], r9
P7QD:       mov         r9, qword ptr[rsi-(13*8)-7]
            mov         qword ptr[rdx-(13*8)-7], r9
P7QC:       mov         r9, qword ptr[rsi-(12*8)-7]
            mov         qword ptr[rdx-(12*8)-7], r9
P7QB:       mov         r9, qword ptr[rsi-(11*8)-7]
            mov         qword ptr[rdx-(11*8)-7], r9
P7QA:       mov         r9, qword ptr[rsi-(10*8)-7]
            mov         qword ptr[rdx-(10*8)-7], r9
P7Q9:       mov         r9, qword ptr[rsi-(9*8)-7]
            mov         qword ptr[rdx-(9*8)-7], r9
P7Q8:       mov         r9, qword ptr[rsi-(8*8)-7]
            mov         qword ptr[rdx-(8*8)-7], r9
P7Q7:       mov         r9, qword ptr[rsi-(7*8)-7]
            mov         qword ptr[rdx-(7*8)-7], r9
P7Q6:       mov         r9, qword ptr[rsi-(6*8)-7]
            mov         qword ptr[rdx-(6*8)-7], r9
P7Q5:       mov         r9, qword ptr[rsi-(5*8)-7]
            mov         qword ptr[rdx-(5*8)-7], r9
P7Q4:       mov         r9, qword ptr[rsi-(4*8)-7]
            mov         qword ptr[rdx-(4*8)-7], r9
P7Q3:       mov         r9, qword ptr[rsi-(3*8)-7]
            mov         qword ptr[rdx-(3*8)-7], r9
P7Q2:       mov         r9, qword ptr[rsi-(2*8)-7]
            mov         qword ptr[rdx-(2*8)-7], r9
P7Q1:       mov         r9, qword ptr[rsi-(1*8)-7]
            mov         qword ptr[rdx-(1*8)-7], r9
            # These trailing loads/stores have to do all their loads 1st, then do the stores
            mov         r9d, dword ptr[rsi-(0*8)-7]
            mov         r10w, word ptr[rsi-(0*8)-3]
            mov         r11b, byte ptr[rsi-(0*8)-1]
            mov         dword ptr[rdx-(0*8)-7], r9d
            mov         word ptr[rdx-(0*8)-3], r10w
            mov         byte ptr[rdx-(0*8)-1], r11b
            jmp         src_bounce_aligned
P7Q0:       # These trailing loads/stores have to do all their loads 1st, then do the stores
            mov         r9d, dword ptr[rsi-(0*8)-7]
            mov         r10w, word ptr[rsi-(0*8)-3]
            mov         r11b, byte ptr[rsi-(0*8)-1]
            mov         dword ptr[rdi-(0*8)-7], r9d
            mov         word ptr[rdi-(0*8)-3], r10w
            mov         byte ptr[rdi-(0*8)-1], r11b
            ret

    .balign 16
    .type ipath_mic_vectorpio,@function
    .size ipath_mic_vectorpio,.-ipath_mic_vectorpio
    .section .note.GNU-stack,"",@progbits

#endif
