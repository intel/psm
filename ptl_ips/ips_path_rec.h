/*
 * Copyright (c) 2013. Intel Corporation. All rights reserved.
 * 2009,2010. QLogic Corporation.  All rights reserved.
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

#ifndef _IPS_PATH_REC_H_
#define _IPS_PATH_REC_H_

#include <search.h>

/* Default size of path record hash table */
#define DF_PATH_REC_HASH_SIZE 2047

/* Default size of CCT table. Must be multiple of 64 */
#define DF_CCT_TABLE_SIZE 128

/* CCT max IPD delay. QLE73XX is limited to 32us */
#define DF_CCT_MAX_IPD_DELAY_US 21

/* CCA divisor shift */
#define CCA_DIVISOR_SHIFT 14

/* CCA ipd mask */
#define CCA_IPD_MASK 0x3FFF

/* A lot of these are IBTA specific defines that are available in other header
 * files. To minimize dependencies with PSM build process they are listed
 * here. Most of this is used to implement IBTA compliance features with PSM
 * like path record querye etc.
 */

enum ibta_mtu {
  IBTA_MTU_256  = 1,
  IBTA_MTU_512  = 2,
  IBTA_MTU_1024 = 3,
  IBTA_MTU_2048 = 4,
  IBTA_MTU_4096 = 5
};

typedef enum  {
  IBTA_RATE_PORT_CURRENT = 0,
  IBTA_RATE_2_5_GBPS = 2,
  IBTA_RATE_5_GBPS   = 5,
  IBTA_RATE_10_GBPS  = 3,
  IBTA_RATE_20_GBPS  = 6,
  IBTA_RATE_30_GBPS  = 4,
  IBTA_RATE_40_GBPS  = 7,
  IBTA_RATE_60_GBPS  = 8,
  IBTA_RATE_80_GBPS  = 9,
  IBTA_RATE_120_GBPS = 10
} ibta_rate;

static inline int ibta_mtu_enum_to_int(enum ibta_mtu mtu)
{
  switch (mtu) {
  case IBTA_MTU_256:  return  256;
  case IBTA_MTU_512:  return  512;
  case IBTA_MTU_1024: return 1024;
  case IBTA_MTU_2048: return 2048;
  case IBTA_MTU_4096: return 4096;
  default:          return -1;
  }
}

/* This is same as ob_path_rec from ib_types.h. Listed here to be self
 * contained to minimize dependencies during build etc.
 */
typedef struct _ibta_path_rec {
  uint64_t service_id;                /* net order */
  uint8_t  dgid[16];
  uint8_t  sgid[16];
  uint16_t dlid;                      /* net order */
  uint16_t slid;                      /* net order */
  uint32_t hop_flow_raw;              /* net order */
  uint8_t  tclass;
  uint8_t  num_path;
  uint16_t pkey;                      /* net order */
  uint16_t qos_class_sl;              /* net order */
  uint8_t  mtu;                       /* IBTA encoded */
  uint8_t  rate;                      /* IBTA encoded */
  uint8_t  pkt_life;                  /* IBTA encoded */
  uint8_t  preference;
  uint8_t  resv2[6];
} ibta_path_rec_t;

/*
 * PSM IPS path record components for endpoint. 
 */
struct ips_proto;
typedef struct ips_path_rec {
  uint16_t      epr_slid; /* For Torus/non zero LMC fabrics this can be diff */
  uint16_t	epr_dlid;
  uint16_t	epr_mtu;
  uint16_t      epr_pkey;
  uint8_t       epr_sl;
  uint8_t       epr_static_rate; 
  uint16_t      epr_static_ipd; /* Static rate IPD from path record */

  /* IBTA CCA parameters per path */
  struct ips_proto *proto;
  uint16_t      epr_ccti;
  uint16_t      epr_ccti_min;
  psmi_timer    epr_timer_cca; /* Congestion timer for epr_ccti increment. */
  uint16_t      epr_active_ipd; /* The current active IPD. max(static,cct) */
  uint8_t       epr_cca_divisor; /* CCA divisor [14:15] in CCT entry */
  uint8_t       epr_pad;

  /* TODO: The endpoint timeout should also adjust based on epr_ird */ 
  uint32_t	epr_timeout_ack_factor;
  uint64_t	epr_timeout_ack; 
  uint64_t	epr_timeout_ack_max;
} ips_path_rec_t;

typedef struct _ips_opp_path_rec {
  ibta_path_rec_t opp_response;
  ips_path_rec_t ips;
} ips_opp_path_rec_t;

psm_error_t ips_opp_init(struct ips_proto *proto);

#endif
