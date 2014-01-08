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

#include "ips_tidflow.h"

psm_error_t ips_tf_init(const psmi_context_t *context,
			struct ips_tfctrl *tfctrl, 
			int start_flowidx, 
			int end_flowidx,
			ips_tf_avail_cb_fn_t cb,
			void *cb_context)
{
  int tf_idx;
  int num_flows = end_flowidx - start_flowidx;
  
#if TF_ADD
  struct psmi_stats_entry entries[] = { 
    PSMI_STATS_DECL("tidflow update count", MPSPAWN_STATS_REDUCTION_ALL,
		    NULL, &tfctrl->tf_num_total),
  };
#endif

  psmi_assert_always(num_flows > 0);
  
  tfctrl->context	  = context;
  tfctrl->tf_start_idx    = start_flowidx;
  tfctrl->tf_end_idx      = end_flowidx;
  tfctrl->tf_num_max      = num_flows;
  tfctrl->tf_num_avail    = num_flows;
  tfctrl->tf_num_total    = 0;
  tfctrl->tf_avail_cb     = cb;
  tfctrl->tf_avail_context= cb_context;

  SLIST_INIT(&tfctrl->tf_avail);
  
  for (tf_idx = start_flowidx; tf_idx < end_flowidx; tf_idx++) {
    /* Update flow state */
    tfctrl->tf[tf_idx].state     = TF_STATE_DEALLOCATED;
    tfctrl->tf[tf_idx].tf_idx    = tf_idx;
    tfctrl->tf[tf_idx].next_gen  = IPS_TF_INVALID_GENERATION + 1;

    SLIST_NEXT(&tfctrl->tf[tf_idx], next) = NULL;
    SLIST_INSERT_HEAD(&tfctrl->tf_avail, &tfctrl->tf[tf_idx], next);

    /* Use tidflow reset as we may want to emulate hardware suppression on
     * QLE73XX and tidflow_set_entry enables the header suppression engine while
     * reset does not.
     */
    ipath_tidflow_reset(context->ctrl, tf_idx);
  }
    
#if TF_ADD
  /* TF_ADD: Add a new stats type for tid flows in psm_stats.h */
  return psmi_stats_register_type(PSMI_STATS_NO_HEADING,
				  PSMI_STATSTYPE_TIDS,
				  entries,
				  PSMI_STATS_HOWMANY(entries),
				  tidc);
#else
  return PSM_OK;
#endif
}

psm_error_t ips_tf_fini(struct ips_tfctrl *tfctrl)
{
  return PSM_OK;
}

/* Allocate a tidflow */
psm_error_t ips_tf_allocate(struct ips_tfctrl *tfctrl, 
			    uint32_t *tf_idx,
			    uint32_t *tf_gen)
{
  struct ips_tf *tf;
  
  if (!tfctrl->tf_num_avail){
    *tf_idx = IPS_TF_INVALID;
    *tf_gen = IPS_TF_INVALID_GENERATION;
    return PSM_EP_NO_RESOURCES;
  }
  
  psmi_assert(!SLIST_EMPTY(&tfctrl->tf_avail));
  
  tf = SLIST_FIRST(&tfctrl->tf_avail);
  SLIST_REMOVE_HEAD(&tfctrl->tf_avail, next);
  
  psmi_assert(tf->state == TF_STATE_DEALLOCATED);

  tf->state = TF_STATE_ALLOCATED;
  
  tfctrl->tf_num_avail--;
  tfctrl->tf_num_total++;
  
  *tf_idx = tf->tf_idx;
  *tf_gen = tf->next_gen;
  
  tf->next_gen++;
  if (tf->next_gen == IPS_TF_INVALID_GENERATION)
    tf->next_gen++;
  
  psmi_assert(*tf_gen != IPS_TF_INVALID_GENERATION);
  psmi_assert_always(*tf_gen <= IPS_TF_MAX_GENERATION);
  
  return PSM_OK;
}

/* Deallocate a tidflow */
psm_error_t ips_tf_deallocate(struct ips_tfctrl *tfctrl, uint32_t tf_idx)
{
  struct ips_tf *tf;

  psmi_assert_always(tf_idx < tfctrl->tf_end_idx);
  
  tf = &tfctrl->tf[tf_idx];
  psmi_assert(tf->state == TF_STATE_ALLOCATED);
  tf->state = TF_STATE_DEALLOCATED;
  
  /* Mark invalid generation for flow (stale packets will be dropped) */
  ipath_tidflow_set_entry(tfctrl->context->ctrl,
		tf_idx, IPS_TF_INVALID_GENERATION, 0);
  
  SLIST_NEXT(tf, next) = NULL;
  SLIST_INSERT_HEAD(&tfctrl->tf_avail, tf, next);
  
  /* If an available callback is registered invoke it */
  if ((tfctrl->tf_num_avail++ == 0) && tfctrl->tf_avail_cb)
    tfctrl->tf_avail_cb(tfctrl, tfctrl->tf_avail_context);
 
  return PSM_OK;
}

/* Allocate a generation for a flow */
psm_error_t ips_tfgen_allocate(struct ips_tfctrl *tfctrl, 
			       uint32_t tf_idx, 
			       uint32_t *tfgen)
{
  struct ips_tf *tf;
  int ret = PSM_OK;
  
  psmi_assert_always(tf_idx < tfctrl->tf_end_idx);
  
  tf = &tfctrl->tf[tf_idx];
  psmi_assert(tf->state == TF_STATE_ALLOCATED);
  
  *tfgen = tf->next_gen;
  
  tf->next_gen++;
  if (tf->next_gen == IPS_TF_INVALID_GENERATION)
    tf->next_gen++;
  
  return ret;
}

