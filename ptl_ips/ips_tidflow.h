/*
 * Copyright (c) 2013. Intel Corporation. All rights reserved.
 * Copyright (c) 2006-2012. QLogic Corporation. All rights reserved.
 * Copyright (c) 2003-2006, PathScale, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _IPS_TIDFLOW_H
#define _IPS_TIDFLOW_H

#include "psm_user.h"

#define IPS_TF_MAX_GENERATION 256
#define IPS_TF_INVALID (~0U)
#define IPS_TF_INVALID_GENERATION 0

#define IPS_TF_PSN_PACK(flow,gen,seq) \
  ( ((((uint64_t)flow)&0x1f)<<19) | \
    ((((uint64_t)gen)&INFINIPATH_TF_GENVAL_MASK)<<INFINIPATH_TF_GENVAL_SHIFT)|\
    ((((uint64_t)seq)&INFINIPATH_TF_SEQNUM_MASK)<<INFINIPATH_TF_SEQNUM_SHIFT))

#define IPS_TF_PSN_UNPACK(tfval,flow,gen,seq) do {			\
    (flow) = ((tfval)>>19) & 0x1f;					\
    (gen) = ((tfval)>>INFINIPATH_TF_GENVAL_SHIFT) & INFINIPATH_TF_GENVAL_MASK; \
    (seq) = ((tfval)>>INFINIPATH_TF_SEQNUM_SHIFT) & INFINIPATH_TF_SEQNUM_MASK; \
  } while (0)

#define IPS_TF_INC_SEQ(tfval) \
  tfval = (tfval & ~INFINIPATH_TF_SEQNUM_MASK) | ((ipath_tidflow_get_seqnum(tfval) + 1) & INFINIPATH_TF_SEQNUM_MASK)

struct ips_tfctrl;

typedef void (*ips_tf_avail_cb_fn_t)(struct ips_tfctrl *,
				     void *context);
typedef enum {
  TF_STATE_INVALID = 0,
  TF_STATE_ALLOCATED = 1,
  TF_STATE_DEALLOCATED = 2
} tf_state_t;

struct ips_tf {
  
  SLIST_ENTRY(ips_tf)           next;

  tf_state_t			state;	

  uint32_t                      tf_idx;
				
  uint32_t                      next_gen:8;
  uint32_t                      pad:24;
};

struct ips_tfctrl {
  const psmi_context_t		*context;
  
  uint32_t                      tf_start_idx;
  uint32_t                      tf_end_idx;
  
  uint32_t                      tf_num_max;
  uint32_t                      tf_num_avail;
  
  uint32_t                      tf_num_total;

  ips_tf_avail_cb_fn_t          tf_avail_cb;
  void                         *tf_avail_context;
  
  SLIST_HEAD(tf_free, ips_tf)   tf_avail;
			   
  struct ips_tf tf[INFINIPATH_TF_NFLOWS];
};

PSMI_ALWAYS_INLINE(
int
ips_tf_available(struct ips_tfctrl *tfctrl))
{
  return tfctrl->tf_num_avail;
}

psm_error_t ips_tf_init(const psmi_context_t *context,
			struct ips_tfctrl *tfctrl, 
			int start_flowidx, 
			int end_flowidx,
			ips_tf_avail_cb_fn_t cb,
			void *cb_context);
psm_error_t ips_tf_fini(struct ips_tfctrl *tfctrl);

/* Allocate a tidflow */
psm_error_t ips_tf_allocate(struct ips_tfctrl *tfctrl, 
			    uint32_t *tf_idx,
			    uint32_t *tf_gen);

/* Deallocate a tidflow */
psm_error_t ips_tf_deallocate(struct ips_tfctrl *tfctrl, uint32_t tf_idx);

/* Allocate a generation for a flow */
psm_error_t ips_tfgen_allocate(struct ips_tfctrl *tfctrl, 
			       uint32_t tf_idx, 
			       uint32_t *tfgen);

#endif
