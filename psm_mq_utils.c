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

#include "psm_user.h"
#include "psm_mq_internal.h"

/*
 *
 * MQ request allocator
 *
 */

psm_mq_req_t __sendpath
psmi_mq_req_alloc(psm_mq_t mq, uint32_t type)
{
    psm_mq_req_t req;

    psmi_assert(type == MQE_TYPE_RECV || type == MQE_TYPE_SEND);

    if (type == MQE_TYPE_SEND)
	req = psmi_mpool_get(mq->sreq_pool);
    else
	req = psmi_mpool_get(mq->rreq_pool);

    if_pt (req != NULL) {
	/* A while ago there were issues about forgetting to zero-out parts of the
	 * structure, I'm leaving this as a debug-time option */
#ifdef PSM_DEBUG
	memset(req, 0, sizeof(struct psm_mq_req));
#endif
	req->type = type;
	req->state = MQ_STATE_FREE;
	req->next = NULL;
	req->pprev = NULL;
	req->error_code = PSM_OK;
	req->mq = mq;
	req->testwait_callback = NULL;
	req->rts_peer = NULL;
	req->ptl_req_ptr = NULL;
	return req;
    }
    else { /* we're out of reqs */
	int issend = (type == MQE_TYPE_SEND);
	uint32_t reqmax, reqchunk;
	psmi_mpool_get_obj_info(issend ? mq->sreq_pool : mq->rreq_pool, 
				&reqchunk, &reqmax);
	
	psmi_handle_error(PSMI_EP_NORETURN, PSM_PARAM_ERR,
	    "Exhausted %d MQ %s request descriptors, which usually indicates "
	    "a user program error or insufficient request descriptors (%s=%d)",
	    reqmax, issend ? "isend" : "irecv", 
	    issend ? "PSM_MQ_SENDREQS_MAX" : "PSM_MQ_RECVREQS_MAX", reqmax);
	return NULL;
    }
}

psm_error_t
psmi_mq_req_init(psm_mq_t mq)
{
    psm_mq_req_t warmup_req;
    psm_error_t err = PSM_OK;

    _IPATH_VDBG("mq element sizes are %d bytes\n", 
		(int) sizeof(struct psm_mq_req));

    /*
     * Send MQ requests
     */
    {
	struct psmi_rlimit_mpool rlim = MQ_SENDREQ_LIMITS;
	uint32_t maxsz, chunksz;

	if ((err = psmi_parse_mpool_env(mq, 0, &rlim, &maxsz, &chunksz)))
	    goto fail;
				    
	if ((mq->sreq_pool = psmi_mpool_create(sizeof(struct psm_mq_req), 
				chunksz, maxsz, 0, DESCRIPTORS,
				NULL, NULL)) == NULL) 
	{
	    err = PSM_NO_MEMORY;
	    goto fail;
	}
    }

    /*
     * Receive MQ requests
     */
    {
	struct psmi_rlimit_mpool rlim = MQ_RECVREQ_LIMITS;
	uint32_t maxsz, chunksz;

	if ((err = psmi_parse_mpool_env(mq, 0, &rlim, &maxsz, &chunksz)))
	    goto fail;

	if ((mq->rreq_pool = 
	    psmi_mpool_create(sizeof(struct psm_mq_req), chunksz, maxsz, 0,
			      DESCRIPTORS, NULL, NULL)) == NULL) {
	    err = PSM_NO_MEMORY;
	    goto fail;
	}
    }

    /* Warm up the allocators */
    warmup_req = psmi_mq_req_alloc(mq, MQE_TYPE_RECV);
    psmi_assert_always(warmup_req != NULL);
    psmi_mq_req_free(warmup_req);

    warmup_req = psmi_mq_req_alloc(mq, MQE_TYPE_SEND);
    psmi_assert_always(warmup_req != NULL);
    psmi_mq_req_free(warmup_req);

fail:
    return err;
}

psm_error_t
psmi_mq_req_fini(psm_mq_t mq)
{
    psmi_mpool_destroy(mq->rreq_pool);
    psmi_mpool_destroy(mq->sreq_pool);
    return PSM_OK;
}

/*
 *
 * System buffer (unexpected message) allocator
 *
 */

#if 0
/* There's a version with a basic wrapper around malloc, as a back up */
void *
psmi_mq_sysbuf_alloc(psm_mq_t mq, uint32_t nbytes)
{
    mq->stats.rx_sysbuf_num++;
    mq->stats.rx_sysbuf_bytes += nbytes;
    return malloc(nbytes);
}

void 
psmi_mq_sysbuf_free(psm_mq_t mq, void *ptr)
{
    free(ptr);
}

#else

void psmi_mq_sysbuf_init(psm_mq_t mq)
{
    int i;
    uint32_t block_sizes[] = {256, 512, 1024, 2048, 4096, 8192, (uint32_t)-1};
    uint32_t replenishing_rate[] = {128, 64, 32, 16, 8, 4, 0};

    if (mq->mem_ctrl_is_init)
	return;
    mq->mem_ctrl_is_init = 1;

    for (i=0; i < MM_NUM_OF_POOLS; i++) {
        mq->handler_index[i].block_size = block_sizes[i];
        mq->handler_index[i].current_available = 0;
        mq->handler_index[i].free_list = NULL;
        mq->handler_index[i].total_alloc = 0;
        mq->handler_index[i].replenishing_rate = replenishing_rate[i];

	if (block_sizes[i] == -1) {
	    psmi_assert_always(replenishing_rate[i] == 0);
	    mq->handler_index[i].flags = MM_FLAG_TRANSIENT;
	}
	else {
	    psmi_assert_always(replenishing_rate[i] > 0);
	    mq->handler_index[i].flags = MM_FLAG_NONE;
	}
    }

    VALGRIND_CREATE_MEMPOOL(mq, PSM_VALGRIND_REDZONE_SZ, 
				PSM_VALGRIND_MEM_UNDEFINED);

    /* Hit once on each block size so we have a pool that's allocated */
    for (i=0; i < MM_NUM_OF_POOLS; i++) {
	void *ptr;
	if (block_sizes[i] == -1)
	    continue;
	ptr = psmi_mq_sysbuf_alloc(mq, block_sizes[i]);
	psmi_mq_sysbuf_free(mq, ptr);
    }
}

void 
psmi_mq_sysbuf_fini(psm_mq_t mq)  // free all buffers that is currently not used
{ 
    mem_block_ctrl *block;
    int i;

    if (mq->mem_ctrl_is_init == 0)
	return;

    VALGRIND_DESTROY_MEMPOOL(mq);

    for (i=0; i < MM_NUM_OF_POOLS; i++) {
	while ((block = mq->handler_index[i].free_list) != NULL) {
	    mq->handler_index[i].free_list = block->next;
	    psmi_free(block);
	}
    }
    mq->mem_ctrl_is_init = 0;
}

void
psmi_mq_sysbuf_getinfo(psm_mq_t mq, char *buf, size_t len)
{
    snprintf(buf, len-1, "Sysbuf consumption: %"PRIu64" bytes\n",
	    mq->mem_ctrl_total_bytes);
    buf[len-1] = '\0';
    return;
}

void * 
psmi_mq_sysbuf_alloc(psm_mq_t mq, uint32_t alloc_size)
{
    mem_ctrl *mm_handler = mq->handler_index;
    mem_block_ctrl *new_block;
    int replenishing;

    /* There is a timing race with ips initialization, fix later.
     * XXX */
    if (!mq->mem_ctrl_is_init)
	psmi_mq_sysbuf_init(mq);

    mq->stats.rx_sysbuf_num++;
    mq->stats.rx_sysbuf_bytes += alloc_size;
    
    while (mm_handler->block_size < alloc_size) 
        mm_handler++;

    replenishing = mm_handler->replenishing_rate;
                          
    if (mm_handler->current_available == 0) { // allocate more buffers
        if (mm_handler->flags & MM_FLAG_TRANSIENT) {
	    uint32_t newsz = alloc_size + sizeof(mem_block_ctrl)
			     + PSM_VALGRIND_REDZONE_SZ;
            new_block = psmi_malloc(mq->ep, UNEXPECTED_BUFFERS, newsz);

            if (new_block) {
		new_block->mem_handler = mm_handler;
                new_block++;
                mm_handler->total_alloc++;
		mq->mem_ctrl_total_bytes += newsz;
		VALGRIND_MEMPOOL_ALLOC(mq, new_block, alloc_size);
            }
            return new_block;
        }

        do {
	    uint32_t newsz = mm_handler->block_size + sizeof(mem_block_ctrl) +
			     PSM_VALGRIND_REDZONE_SZ;

            new_block = psmi_malloc(mq->ep, UNEXPECTED_BUFFERS, newsz);
	    mq->mem_ctrl_total_bytes += newsz;

            if (new_block) {
                mm_handler->current_available++;
                mm_handler->total_alloc++;

                new_block->next = mm_handler->free_list;
                mm_handler->free_list = new_block;
            }
            
        } while (--replenishing && new_block);
    }

    if (mm_handler->current_available) {
        mm_handler->current_available--;

       new_block = mm_handler->free_list;
       mm_handler->free_list = new_block->next;

       new_block->mem_handler = mm_handler;
       new_block++;

       VALGRIND_MEMPOOL_ALLOC(mq, new_block, mm_handler->block_size);
       return new_block;
    }

    return NULL;
}       

void psmi_mq_sysbuf_free(psm_mq_t mq, void * mem_to_free)
{
    mem_block_ctrl * block_to_free;
    mem_ctrl *mm_handler;

    psmi_assert_always(mq->mem_ctrl_is_init);

    block_to_free = (mem_block_ctrl *)mem_to_free - 1;
    mm_handler = block_to_free->mem_handler;

    VALGRIND_MEMPOOL_FREE(mq, mem_to_free);

    if (mm_handler->flags & MM_FLAG_TRANSIENT) {
        psmi_free(block_to_free);
    } else {
        block_to_free->next = mm_handler->free_list;
        mm_handler->free_list = block_to_free;

        mm_handler->current_available++;
    }

    return;
}
#endif

/*
 * Hooks to plug into QLogic MPI stats
 */

static
void psmi_mq_stats_callback(struct mpspawn_stats_req_args *args)
{
    uint64_t *entry = args->stats;
    psm_mq_t mq = (psm_mq_t) args->context;
    psm_mq_stats_t mqstats;

    psm_mq_get_stats(mq, &mqstats);

    if (args->num < 8)
        return;

    entry[0] = mqstats.tx_eager_num;
    entry[1] = mqstats.tx_eager_bytes;
    entry[2] = mqstats.tx_rndv_num;
    entry[3] = mqstats.tx_rndv_bytes;

    entry[4] = mqstats.rx_user_num;
    entry[5] = mqstats.rx_user_bytes;
    entry[6] = mqstats.rx_sys_num;
    entry[7] = mqstats.rx_sys_bytes;
}

void
psmi_mq_stats_register(psm_mq_t mq, mpspawn_stats_add_fn add_fn)
{
    char *desc[8];
    uint16_t flags[8];
    int i;
    struct mpspawn_stats_add_args mp_add;
    /*
     * Hardcode flags until we correctly move mpspawn to its own repo.
     * flags[i] = MPSPAWN_REDUCTION_MAX | MPSPAWN_REDUCTION_MIN;
     */
    for (i = 0; i < 8; i++)
        flags[i] = MPSPAWN_STATS_REDUCTION_ALL;

    desc[0] = "Eager count sent";
    desc[1] = "Eager bytes sent";
    desc[2] = "Rendezvous count sent";
    desc[3] = "Rendezvous bytes sent";
    desc[4] = "Expected count received";
    desc[5] = "Expected bytes received";
    desc[6] = "Unexpect count received";
    desc[7] = "Unexpect bytes received";

    mp_add.version = MPSPAWN_STATS_VERSION;
    mp_add.num = 8;
    mp_add.header = "MPI Statistics Summary (max,min @ rank)";
    mp_add.req_fn = psmi_mq_stats_callback;
    mp_add.desc = desc;
    mp_add.flags = flags;
    mp_add.context = mq;

    add_fn(&mp_add);
}
