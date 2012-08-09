/*
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

#include "ips_recvq.h"

/* We return a table of pointer indexes.
 * 
 * From the point of view of the returned pointer, index -1 always points to
 * the address to call psmi_free on (since we force page-alignment).
 */
void **
ips_recvq_egrbuf_table_alloc(psm_ep_t ep, void *baseptr, 
			     uint32_t chunksize, 
			     uint32_t bufnum, uint32_t bufsize)
{
    unsigned i;
    uint32_t bufperchunk = chunksize / bufsize;
    void *ptr_alloc;
    uintptr_t *buft;
    uintptr_t base = (uintptr_t) baseptr;

    ptr_alloc = psmi_malloc(ep, UNDEFINED, 
		      PSMI_PAGESIZE + sizeof(uintptr_t)*(bufnum+1));
    if (ptr_alloc == NULL)
	return NULL;
    /* First pointer is to the actual allocated address, so we can free it but
     * buft[1] is first on the page boundary
     */
    buft = (uintptr_t *) PSMI_ALIGNUP(ptr_alloc+1, PSMI_PAGESIZE);
    buft[-1] = (uintptr_t) ptr_alloc;
    for (i=0; i<bufnum; i++)
	buft[i] = base + (i / bufperchunk) * chunksize +
            (i % bufperchunk) * bufsize;
    return (void **)buft;
}

void
ips_recvq_egrbuf_table_free(void **buftable)
{
    uintptr_t *buft = (uintptr_t *) buftable;
    void *ptr_alloc = (void *) buft[-1];
    psmi_free(ptr_alloc);
}

