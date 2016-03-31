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

/* included header files  */
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sched.h>

#include "ips_proto.h"
#include "ips_proto_internal.h"
#include "ips_spio.h"
#include "ipserror.h" /* ips error codes */
#include "ips_proto_params.h"
#include "ipath_byteorder.h"


#define SPIO_INUSE_MASK 0xAAAAAAAAAAAAAAAAULL
#define SPIO_CHECK_MASK 0x5555555555555555ULL

/* Report PIO stalls every 20 seconds at the least */
#define SPIO_STALL_WARNING_INTERVAL	  (nanosecs_to_cycles(20e9))
#define SPIO_MAX_CONSECUTIVE_SEND_FAIL	  (1<<20) /* 1M */
/* RESYNC_CONSECUTIVE_SEND_FAIL has to be a multiple of MAX_CONSECUTIVE */
#define SPIO_RESYNC_CONSECUTIVE_SEND_FAIL (1<<4) /* 16 */

static void spio_report_stall(struct ips_spio *ctrl, 
			      uint64_t t_cyc_now, 
			      uint64_t send_failures);

static void spio_handle_stall(struct ips_spio *ctrl,
			      uint64_t send_failures);

static inline
uint64_t
ips_spio_read_avail_index(struct ips_spio *ctrl, int index)
{
    if (ctrl->runtime_flags & IPATH_RUNTIME_PIO_REGSWAPPED && index > 3) {
	return __le64_to_cpu(ctrl->spio_avail_addr[index ^ 1]);
    }
    else
	return __le64_to_cpu(ctrl->spio_avail_addr[index]);
}

psm_error_t
ips_spio_init(const struct psmi_context *context, const struct ptl *ptl,
	      struct ips_spio *ctrl)
{
    psm_error_t err = PSM_OK;
    const struct ipath_base_info *base_info = &context->base_info;
    unsigned wc_unordered;
    char *order_str = "undefined";
    int i, last_shadow_index;
    int num_shadow_index = sizeof(ctrl->spio_avail_shadow) / 
			   sizeof(ctrl->spio_avail_shadow[0]);

    ctrl->ptl = ptl;
    ctrl->context = context;
    /* Copy runtime flags */
    ctrl->runtime_flags = ptl->runtime_flags;
    ctrl->unit_id = context->ep->unit_id;
    ctrl->portnum = context->ep->portnum;
    pthread_spin_init(&ctrl->spio_lock, 0);
    ctrl->spio_avail_addr =
        (__le64 *)(ptrdiff_t)base_info->spi_pioavailaddr;
    ctrl->spio_buffer_base =
        (uint32_t *)(ptrdiff_t)base_info->spi_piobufbase;
    ctrl->spio_sendbuf_status =
        (unsigned long *)(ptrdiff_t)base_info->spi_sendbuf_status;

    ctrl->spio_buffer_spacing = base_info->spi_pioalign >> 2;
    ctrl->spio_first_buffer = ctrl->spio_current_buffer = 
	base_info->spi_pioindex;
    ctrl->spio_last_buffer = 
	ctrl->spio_first_buffer + base_info->spi_piocnt - 1;
    ctrl->spio_num_of_buffer = base_info->spi_piocnt;

    ctrl->spio_consecutive_failures = 0;
    ctrl->spio_num_stall = 0ULL;
    ctrl->spio_next_stall_warning = 0ULL;
    ctrl->spio_last_stall_cyc = 0ULL;
    ctrl->spio_init_cyc = get_cycles();

    last_shadow_index = ctrl->spio_last_buffer / 32;
    last_shadow_index += (ctrl->spio_last_buffer % 32) ? 1 : 0;
    if (last_shadow_index > num_shadow_index) 
    {
	err = psmi_handle_error(ctrl->context->ep, PSM_EP_DEVICE_FAILURE,
		"Number of buffer avail registers is wrong; "
		"have %u, expected %u (1st %u, piocnt %u, last %u)",
		last_shadow_index, 
		(uint32_t)(sizeof(ctrl->spio_avail_shadow) / 
			   sizeof(ctrl->spio_avail_shadow[0])),
		base_info->spi_pioindex, ctrl->spio_last_buffer,
		base_info->spi_piocnt);
	goto fail;
    }

    /* update the shadow copy with the current contents of hardware
     * available registers */
    for (i = 0; i < num_shadow_index; i++)
	ctrl->spio_avail_shadow[i] = ips_spio_read_avail_index(ctrl, i);

    /* Figure out the type of ordering we require for pio writes.  Update the
     * routine we use for copies according to the type of pio write required */
    wc_unordered  = base_info->spi_runtime_flags;
    wc_unordered &= IPATH_RUNTIME_FORCE_WC_ORDER;

    if (base_info->spi_runtime_flags & IPATH_RUNTIME_SPECIAL_TRIGGER) {
      /* For now all PIO packets are < 2K and use the 2K trigger function. */
      ctrl->spio_copy_fn = ipath_write_pio_special_trigger2k;
      order_str = "natural CPU (w/ 2k special trigger)";
    }
    else {
	switch ( wc_unordered ) {
	    case 0: 
#ifdef __MIC__
		ctrl->spio_copy_fn = getenv("IPATH_MIC_DWORD_PIO")?
				ipath_write_pio:ipath_write_pio_vector;
#else
		ctrl->spio_copy_fn = ipath_write_pio;
#endif
		order_str = "natural CPU";
		break;

	    case IPATH_RUNTIME_FORCE_WC_ORDER: 
	    default:    // any other non-zero
		ctrl->spio_copy_fn = ipath_write_pio_force_order;
		order_str = "forced";
		break;
	}
    }

    _IPATH_PRDBG("PIO copy uses %s ordering\n", order_str);

fail:
    return err;
}

psm_error_t
ips_spio_fini(struct ips_spio *ctrl)
{
    spio_report_stall(ctrl, get_cycles(), 0ULL);
    return PSM_OK;
}

static
void 
spio_report_stall(struct ips_spio *ctrl, uint64_t t_cyc_now, 
		  uint64_t send_failures)
{
    int last, i;
    size_t off = 0;
    char buf[1024];
    
    if (ctrl->spio_num_stall == 0)
	return;

    last = ctrl->spio_last_buffer/32;

    if (send_failures > 0) {
	char bufctr[128];
	uint64_t tx_stat, rx_stat;
	int ret;

	off = snprintf(buf, sizeof buf - 1, 
	    "PIO Send Bufs context %d with %d bufs from %d to %d. PIO avail regs: ",
	    (int) psm_epid_context(ctrl->context->epid),
	    ctrl->spio_num_of_buffer, ctrl->spio_first_buffer, 
	    ctrl->spio_last_buffer);

	for (i = 0; i < 8; i++) {
	    uint64_t avail = ips_spio_read_avail_index(ctrl, i);
	    off += snprintf(buf+off, sizeof buf - off - 1, " <%d>=(%llx) ", 
		    i, (long long) avail);
	}
	off += snprintf(buf+off, sizeof buf - off - 1, ". PIO shadow regs: ");
	for (i = ctrl->spio_first_buffer/32; i <= last; i++) {
	    off += snprintf(buf+off, sizeof buf - off - 1, " <%d>=(%llx) ", 
		    i, (long long)ctrl->spio_avail_shadow[i]);
	}
	buf[off] = '\0';

	/* In case ipathfs isn't running */
	ret = infinipath_get_single_portctr(ctrl->unit_id, ctrl->portnum,
					    "TxPkt", &tx_stat);
	if (ret != -1) {
		ret = infinipath_get_single_portctr(ctrl->unit_id,
						    ctrl->portnum, "RxPkt",
						    &rx_stat);
		if (ret != -1) {
			snprintf(bufctr, sizeof bufctr - 1, 
				 "(TxPktCnt=%llu,RxPktCnt=%llu)",
				 (unsigned long long) tx_stat,
				 (unsigned long long) rx_stat);
			bufctr[sizeof bufctr - 1] = '\0';
		} else 
			bufctr[0] = '\0';
	} else
		bufctr[0] = '\0';
	_IPATH_DBG("PIO Send Stall after at least %.2fM failed send attempts "
	    "(elapsed=%.3fs, last=%.3fs, pio_stall_count=%lld) %s %s\n",
	    send_failures / 1e6,
	    PSMI_CYCLES_TO_SECSF(t_cyc_now - ctrl->spio_init_cyc),
	    PSMI_CYCLES_TO_SECSF(t_cyc_now - ctrl->spio_last_stall_cyc),
	    (unsigned long long) ctrl->spio_num_stall,
	    bufctr[0] != '\0' ? bufctr : "", buf);
    }
    else {
	_IPATH_DBG(
	    "PIO Send Stall Summary: count=%llu, last=%.3fs, elapsed=%.3fs",
	    (unsigned long long) ctrl->spio_num_stall,
	    PSMI_CYCLES_TO_SECSF(t_cyc_now - ctrl->spio_init_cyc),
	    PSMI_CYCLES_TO_SECSF(t_cyc_now - ctrl->spio_last_stall_cyc));
    }

    return;
}

static void 
spio_handle_stall(struct ips_spio *ctrl,
		  uint64_t send_failures)
{
    uint64_t t_cyc_now = get_cycles();
    int i, last;
    
    /* We handle the pio-stall every time but only report something every 20
     * seconds.  We print a summary at the end while closing the device */
    ctrl->spio_num_stall++;
    ctrl->spio_num_stall_total++;

    if (ctrl->spio_next_stall_warning <= t_cyc_now) {
	/* If context status is ok (i.e. no cables pulled or anything) */
	if (psmi_context_check_status(ctrl->context) == PSM_OK)
	    spio_report_stall(ctrl, t_cyc_now, send_failures);
	ctrl->spio_next_stall_warning = 
		get_cycles() + SPIO_STALL_WARNING_INTERVAL;
    }

    /* re-initialize our shadow from the real registers; by this time,
     * we know the hardware has to have done the update.
     * Also, kernel check may have changed things.
     */
    last = ctrl->spio_last_buffer/32;
    for (i = 0; i <= last; i++) {
        uint64_t mask, avail, shadow_avail;
      
        avail = ips_spio_read_avail_index(ctrl, i);
	shadow_avail = ctrl->spio_avail_shadow[i];
	mask = (~(avail ^ shadow_avail) & SPIO_CHECK_MASK) << 1;
	shadow_avail &= ~mask; /* clear all possible in-use bits */
	shadow_avail |= (avail & mask);
	ctrl->spio_avail_shadow[i] = shadow_avail;
    }

    ctrl->spio_last_stall_cyc = t_cyc_now;

    return;
}

/*
 * Update our shadow of the PIO available bitfield at index 'index'
 */
static void __sendpath 
spio_update_shadow(struct ips_spio *ctrl, int index)
{
    register uint64_t mask, avail, shadow_avail;

    if_pf (*ctrl->spio_sendbuf_status) {
      __u64 event_mask;
      struct ips_proto *proto = (struct ips_proto*) &ctrl->ptl->proto;
      
      /* Get event mask for PSM to process */
      event_mask = (uint64_t) *ctrl->spio_sendbuf_status;
      
      /* First ack the driver the receipt of the events */
      _IPATH_VDBG("Acking event(s) 0x%"PRIx64" to qib driver.\n", (uint64_t) event_mask);
      ipath_event_ack(ctrl->context->ctrl, event_mask);
      
      if (event_mask & IPATH_EVENT_DISARM_BUFS) {
	/* Just acking event has disarmed all buffers */
	_IPATH_VDBG("Disarm of send buffers completed.\n");
      }
      
      if (event_mask & IPATH_EVENT_LINKDOWN) {
	/* A link down event can clear the LMC and SL2VL change as those
	 * events are implicitly handled in the link up/down event handler.
	 */
	event_mask &= ~(IPATH_EVENT_LMC_CHANGE | IPATH_EVENT_SL2VL_CHANGE);
	ips_ibta_link_updown_event(proto);
	_IPATH_VDBG("Link down detected.\n");
      }
      
      if (event_mask & IPATH_EVENT_LID_CHANGE) {
	/* Display a warning that LID change has occurred during the run. This
	 * is not supported in the current implementation and in general is
	 * bad for the SM to re-assign LIDs during a run.
	 */
	int lid, olid;
	
	lid = 
	  ipath_get_port_lid(proto->ep->context.base_info.spi_unit,
			     proto->ep->context.base_info.spi_port);
	olid = PSMI_EPID_GET_LID(ctrl->context->epid);
	
	_IPATH_INFO("Warning! LID change detected during run. Old LID: %x, New Lid: %x\n", olid, lid);
      }
      
      if (event_mask & IPATH_EVENT_LMC_CHANGE) {
	_IPATH_INFO("Fabric LMC changed.\n");
      }
      
      if (event_mask & IPATH_EVENT_SL2VL_CHANGE) {
	_IPATH_INFO("SL2VL mapping changed for port.\n");
	ips_ibta_init_sl2vl_table(proto);
      }
    }

    index &= 0x7;	// max spio_avail_shadow[] index.
    avail = ips_spio_read_avail_index(ctrl, index);
 
    do {
	shadow_avail = ctrl->spio_avail_shadow[index];
	mask = (~(avail ^ shadow_avail) & SPIO_CHECK_MASK) << 1;
	shadow_avail &= ~mask; /* clear all possible in-use bits */
	shadow_avail |= (avail & mask);
    }
#ifndef PSMI_USE_THREADS
    while (0);
    ctrl->spio_avail_shadow[index] = shadow_avail;
#else
    while (ips_cswap(...));
#endif
}

static void
spio_handle_resync(struct ips_spio *ctrl,
		   uint64_t consecutive_send_failed)
{
  if (ctrl->runtime_flags & IPATH_RUNTIME_FORCE_PIOAVAIL)
    ipath_force_pio_avail_update(ctrl->context->ctrl);
  if (!(consecutive_send_failed & (SPIO_MAX_CONSECUTIVE_SEND_FAIL - 1)))
    spio_handle_stall(ctrl, consecutive_send_failed);
}

/* 
 * This function attempts to write a packet to a PIO.
 *
 * Recoverable errors:
 * PSM_OK: Packet triggered through PIO.
 * PSM_EP_NO_RESOURCES: No PIO bufs available or cable pulled.
 *
 * Unrecoverable errors:
 * PSM_EP_NO_NETWORK: No network, no lid, ...
 * PSM_EP_DEVICE_FAILURE: Chip failures, rxe/txe parity, etc.
 */
psm_error_t __sendpath 
ips_spio_transfer_frame(struct ips_spio *ctrl, struct ips_flow *flow,
			void *header, void *payload, int length,
			uint32_t isCtrlMsg, uint32_t cksum_valid,uint32_t cksum)
{
    uint32_t *current_pio_buffer;
    const uint64_t toggle_bits = 3ULL;
    psm_error_t err = PSM_OK;
    int tries;
    int do_lock = (ctrl->runtime_flags & PSMI_RUNTIME_RCVTHREAD);
    struct ipath_pio_params pio_params;
    struct ips_message_header *p_hdr = (struct ips_message_header*) header;

    if (do_lock)
	pthread_spin_lock(&ctrl->spio_lock);

    if_pf (PSMI_FAULTINJ_ENABLED()) {
	PSMI_FAULTINJ_STATIC_DECL(fi_lost, "piosend", 1, IPS_FAULTINJ_PIOLOST);
	PSMI_FAULTINJ_STATIC_DECL(fi_busy, "piobusy", 1, IPS_FAULTINJ_PIOBUSY);
	if (psmi_faultinj_is_fault(fi_lost)) {
	    if (do_lock)
		pthread_spin_unlock(&ctrl->spio_lock);
	    return PSM_OK;
	}
	else if (psmi_faultinj_is_fault(fi_busy))
	    goto fi_busy;
	/* else fall through normal processing path, i.e. no faults */
    }

    if (ctrl->spio_avail_shadow[ctrl->spio_current_buffer / 32] & 
        (1ULL<<(((ctrl->spio_current_buffer) % 32 * 2) + 1))) 
    {
	/* 
	 * If the bit was already set, we couldn't get the pio buf. Update our
	 * shadow copy.
	 */
        spio_update_shadow(ctrl, ctrl->spio_current_buffer / 32);

        tries = ctrl->spio_num_of_buffer;

	while (tries && (ctrl->spio_avail_shadow[ctrl->spio_current_buffer / 32] & 
			    (1ULL<<(((ctrl->spio_current_buffer % 32) * 2) + 1)))) 
	{
            /* advance spio_current_buffer to next buffer */
	    if (++ctrl->spio_current_buffer > ctrl->spio_last_buffer) {
		ctrl->spio_current_buffer = ctrl->spio_first_buffer;
                spio_update_shadow(ctrl, ctrl->spio_current_buffer / 32);
	    }
	    else if ( (ctrl->spio_current_buffer % 32) == 0 ) 
                spio_update_shadow(ctrl, ctrl->spio_current_buffer / 32);
            tries--;
        }

        if_pf ( !tries ) {
	    /* Check unit status */
fi_busy:
	    if ((err = psmi_context_check_status(ctrl->context)) == PSM_OK) {
		if (0 == (++ctrl->spio_consecutive_failures & 
			    (SPIO_RESYNC_CONSECUTIVE_SEND_FAIL-1)))
		    spio_handle_resync(ctrl, ctrl->spio_consecutive_failures);
		err = PSM_EP_NO_RESOURCES; 
	    }
	    /* If cable is pulled, we don't count it as a consecutive failure,
	     * we just make it as though no send pio was available */
	    else if (err == PSM_OK_NO_PROGRESS) 
		err = PSM_EP_NO_RESOURCES; 
	    /* else something bad happened in check_status */
	    if (do_lock)
		pthread_spin_unlock(&ctrl->spio_lock);
            return err;
        }
    }
    if (ctrl->spio_num_stall) // now able to send, so clear if set
        ctrl->spio_num_stall = 0;

    /* toggle the Generation bit and set the busy bit.
     * If we detected a flip,        toggle busy but not GenBit (0x2)
     * If we didn't detect the flip, toggle busy but not the GenBit (0x3) */
    ctrl->spio_avail_shadow[ctrl->spio_current_buffer / 32] ^= 
	    (toggle_bits<<(((ctrl->spio_current_buffer % 32) * 2)));

    current_pio_buffer = (uint32_t *) ctrl->spio_buffer_base +
        (ctrl->spio_buffer_spacing * 
	 (ctrl->spio_current_buffer - ctrl->spio_first_buffer));

    /* advance spio_current_buffer to next buffer */
    if (++ctrl->spio_current_buffer > ctrl->spio_last_buffer)
	ctrl->spio_current_buffer = ctrl->spio_first_buffer;

    ctrl->spio_consecutive_failures = 0;

    if (do_lock)
	pthread_spin_unlock(&ctrl->spio_lock);

    pio_params.length = length;
    pio_params.vl = (__be16_to_cpu(p_hdr->lrh[0]) >> LRH_VL_SHIFT) & 0xf;
    pio_params.port = ctrl->portnum;
    pio_params.cksum_is_valid = cksum_valid;
    pio_params.cksum = cksum;

    /* For matched send/receive rates and control messages IPD is not
     * required.
     */
    if_pf (!isCtrlMsg && flow->path->epr_active_ipd)
      pio_params.rate = 
      ips_proto_pbc_static_rate(flow, 
				(length + sizeof(struct ips_message_header)));
    else
      pio_params.rate = 0;
    
    /* Copy buffer using PIO */
    ctrl->spio_copy_fn(current_pio_buffer, &pio_params, header, payload);

    return PSM_OK;
} // ips_spio_transfer_frame()

