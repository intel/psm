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

#ifndef _PSMI_IN_USER_H
#error psm_mpool.h not meant to be included directly, include psm_user.h instead
#endif

#ifndef PSM_MPOOL_H
#define PSM_MPOOL_H

/* mpool flags */
#define PSMI_MPOOL_ALIGN_CACHE	0x1
#define PSMI_MPOOL_ALIGN_PAGE   0x2
#define PSMI_MPOOL_NOGENERATION 0x4

/* Backwards compatibility */
#define PSMI_MPOOL_ALIGN	PSMI_MPOOL_ALIGN_CACHE 

typedef void (*non_empty_callback_fn_t)(void *context);
typedef struct mpool *mpool_t;

mpool_t		psmi_mpool_create(size_t obj_size, uint32_t num_obj_per_chunk,
				  uint32_t num_obj_max_total, int flags,
				  psmi_memtype_t statstype, 
				  non_empty_callback_fn_t cb, void *context);

void		psmi_mpool_destroy(mpool_t mp);
void		psmi_mpool_get_obj_info(mpool_t mp, uint32_t *num_obj_per_chunk, 
				        uint32_t *num_obj_max_total);

void *		psmi_mpool_get(mpool_t mp);
void		psmi_mpool_put(void *obj);

int		psmi_mpool_get_obj_index(void *obj);
uint32_t	psmi_mpool_get_obj_gen_count(void *obj);
int		psmi_mpool_get_obj_index_gen_count(void *obj,
						   uint32_t *index,
						   uint32_t *gen_count);

void *		psmi_mpool_find_obj_by_index(mpool_t mp, int index);

#endif
