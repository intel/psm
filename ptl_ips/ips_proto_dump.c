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

#include "ips_proto.h"
#include "ips_proto_internal.h"
#include "ips_proto_header.h"
#include "ips_proto_help.h"
#include "ips_epstate.h"

void ips_proto_dump_frame(void *frame, int lenght, char *message)
{
    uint8_t *raw_frame = frame;
    int counter;
    char default_message[] = "<UNKNOWN>";

    if(!message)
        message = default_message;

    printf("\nHex dump of %i bytes at %p from %s\n", lenght, frame, message);

    for(counter = 0; counter < lenght; counter++) {
        if((counter % 16) == 0)
            printf("\n");

        if((counter % 4) == 0)
            printf("   ");

        printf("%02X ", raw_frame[counter]);
    }
    printf("\n");
}

void ips_proto_dump_data(void *data, int data_length)
{
    int counter;
    uint8_t *payload = (uint8_t *)data;

    printf("\nHex dump of data, length = %i\n",
           data_length);

    for(counter = 0; counter < data_length; counter++) {
        if((counter % 16) == 0)
            printf("\n %04d: ", counter);

        if((counter % 4) == 0)
            printf("   ");

        printf("%02X ", payload[counter]);
    }
    printf("\n");
}

void ips_proto_show_header(struct ips_message_header *p_hdr, char *msg)
{
    uint32_t tid;
    psm_protocol_type_t protocol;
    psmi_seqnum_t ack_seq_num;
        
    printf("\nHeader decoding %s\n",msg?msg:"");

    printf("LRH: VL4-LVer4-SL4-Res2-LNH2: %x\n",
        __be16_to_cpu(p_hdr->lrh[0]));
    printf("LRH: DLID %x\n", __be16_to_cpu(p_hdr->lrh[1]));
    printf("LRH: PktLen %i (0x%x)\n", __be16_to_cpu(p_hdr->lrh[2]),
        __be16_to_cpu(p_hdr->lrh[2]));
    printf("LRH: SLID %x\n", __be16_to_cpu(p_hdr->lrh[3]));
    printf("BTH: OpCode8-SE1-M1-PC2-TVer4-Pkey16 %x\n",
        __be32_to_cpu(p_hdr->bth[0]));
    printf("BTH: R8-DestQP24 %x\n", __be32_to_cpu(p_hdr->bth[1]));
    printf("BTH: AR1-Res7-PSN24 %x\n", __be32_to_cpu(p_hdr->bth[2]));
    printf("IPH: chksum %x\n", __le16_to_cpu(p_hdr->iph.chksum));
    printf("IPH: pkt_flags %x\n", __le16_to_cpu(
        p_hdr->iph.pkt_flags) & INFINIPATH_KPF_INTR_HDRSUPP_MASK);
    printf("IPH: ver %i\n",
        (__le32_to_cpu(p_hdr->iph.ver_context_tid_offset)
        >> INFINIPATH_I_VERS_SHIFT) & INFINIPATH_I_VERS_MASK);
    printf("IPH: context %i\n", 
        (__le32_to_cpu(p_hdr->iph.ver_context_tid_offset)
        >> INFINIPATH_I_CONTEXT_SHIFT) & INFINIPATH_I_CONTEXT_MASK);
    printf("IPH: subcontext %i\n", p_hdr->dst_subcontext);
    tid = (__le32_to_cpu(p_hdr->iph.ver_context_tid_offset)
           >> INFINIPATH_I_TID_SHIFT) & INFINIPATH_I_TID_MASK;
    printf("IPH: tid %x\n", tid);
    printf("IPH: offset %x\n",
        (__le32_to_cpu(p_hdr->iph.ver_context_tid_offset)
        >> INFINIPATH_I_OFFSET_SHIFT) & INFINIPATH_I_OFFSET_MASK);

    printf("sub-opcode %x\n", p_hdr->sub_opcode);
    
    ack_seq_num.psn = p_hdr->ack_seq_num;
    protocol = IPS_FLOWID_GET_PROTO(p_hdr->flowid);
    if (protocol == PSM_PROTOCOL_GO_BACK_N)
      printf("ack_seq_num %x\n", ack_seq_num.psn);
    else
      printf("TidFlow Flow: %x, Gen: %x, Seq: %x\n", ack_seq_num.flow, ack_seq_num.gen, ack_seq_num.seq);
    
    printf("context %d (src_context %d src_context_ext %d) src_subcontext %d\n",
	IPS_HEADER_SRCCONTEXT_GET(p_hdr), p_hdr->src_context, p_hdr->src_context_ext,
	p_hdr->src_subcontext);
    printf("src_rank/commidx %i\n", p_hdr->commidx |
        INFINIPATH_KPF_RESERVED_BITS(p_hdr->iph.pkt_flags));
    if (tid != IPATH_EAGER_TID_ID)
	printf("expected_tid_session_id %i\n", p_hdr->data[0].u32w0);
    printf("flags %x\n", p_hdr->flags);
    printf("mqhdr %x\n", p_hdr->mqhdr);
}

// linux doesn't have strlcat; this is a stripped down implementation
// not super-efficient, but we use it rarely, and only for short strings
// not fully standards conforming!
static size_t strlcat(char *d, const char *s, size_t l)
{
    int dlen = strlen(d), slen, max;
    if(l<=dlen)  // bug
        return l;
    slen = strlen(s);
    max = l-(dlen+1);
    if(slen>max)
        slen = max;
    memcpy(d+dlen, s, slen);
    d[dlen+slen] = '\0';
    return dlen+slen+1; // standard says to return full length, not actual
}

// decode RHF errors; only used one place now, may want more later
void ips_proto_get_rhf_errstring(uint32_t err, char *msg, size_t len)
{
    *msg = '\0'; // if no errors, and so don't need to check what's first

    if(err & INFINIPATH_RHF_H_ICRCERR)
        strlcat(msg, "icrcerr ", len);
    if(err & INFINIPATH_RHF_H_VCRCERR)
        strlcat(msg, "vcrcerr ", len);
    if(err & INFINIPATH_RHF_H_PARITYERR)
        strlcat(msg, "parityerr ", len);
    if(err & INFINIPATH_RHF_H_LENERR)
        strlcat(msg, "lenerr ", len);
    if(err & INFINIPATH_RHF_H_MTUERR)
        strlcat(msg, "mtuerr ", len);
    if(err & INFINIPATH_RHF_H_IHDRERR)
        strlcat(msg, "ipathhdrerr ", len);
    if(err & INFINIPATH_RHF_H_TIDERR)
        strlcat(msg, "tiderr ", len);
    if(err & INFINIPATH_RHF_H_MKERR)
        strlcat(msg, "mkerr ", len);
    if(err & INFINIPATH_RHF_H_IBERR)
        strlcat(msg, "iberr ", len);
    if(err & INFINIPATH_RHF_L_SWA)
        strlcat(msg, "swA ", len);
    if(err & INFINIPATH_RHF_L_SWB)
        strlcat(msg, "swB ", len);
}

void ips_proto_dump_err_stats(struct ips_proto *proto)
{
  char err_stat_msg[2048];
  char tmp_buf[128];
  int len = sizeof(err_stat_msg);

  if (!(infinipath_debug & __IPATH_PKTDBG))
    return;
  
  *err_stat_msg = '\0';

  if (proto->error_stats.num_icrc_err ||
      proto->error_stats.num_vcrc_err ||
      proto->error_stats.num_ecc_err ||
      proto->error_stats.num_len_err ||
      proto->error_stats.num_mtu_err ||
      proto->error_stats.num_khdr_err ||
      proto->error_stats.num_tid_err ||
      proto->error_stats.num_mk_err ||
      proto->error_stats.num_ib_err) {
    
    snprintf(tmp_buf, sizeof(tmp_buf), "ERROR STATS: ");

    if (proto->error_stats.num_icrc_err) {
      snprintf(tmp_buf, sizeof(tmp_buf), "ICRC: %"PRIu64" ", proto->error_stats.num_icrc_err);
      strlcat(err_stat_msg, tmp_buf, len);
    }
    
    if (proto->error_stats.num_vcrc_err) {
      snprintf(tmp_buf, sizeof(tmp_buf), "VCRC: %"PRIu64" ", proto->error_stats.num_vcrc_err);
      strlcat(err_stat_msg, tmp_buf, len);
    }
    
    if (proto->error_stats.num_ecc_err) {
      snprintf(tmp_buf, sizeof(tmp_buf), "ECC: %"PRIu64" ", proto->error_stats.num_ecc_err);
      strlcat(err_stat_msg, tmp_buf, len);
    }
    
    if (proto->error_stats.num_len_err) {
      snprintf(tmp_buf, sizeof(tmp_buf), "LEN: %"PRIu64" ", proto->error_stats.num_len_err);
      strlcat(err_stat_msg, tmp_buf, len);
    }
    
    if (proto->error_stats.num_mtu_err) {
      snprintf(tmp_buf, sizeof(tmp_buf), "MTU: %"PRIu64" ", proto->error_stats.num_mtu_err);
    strlcat(err_stat_msg, tmp_buf, len);
    }
    
    if (proto->error_stats.num_khdr_err) {
      snprintf(tmp_buf, sizeof(tmp_buf), "KHDR: %"PRIu64" ", proto->error_stats.num_khdr_err);
      strlcat(err_stat_msg, tmp_buf, len);
    }
    
    if (proto->error_stats.num_tid_err) {
      snprintf(tmp_buf, sizeof(tmp_buf), "TID: %"PRIu64" ", proto->error_stats.num_tid_err);
      strlcat(err_stat_msg, tmp_buf, len);
    }
    
    if (proto->error_stats.num_mk_err) {
      snprintf(tmp_buf, sizeof(tmp_buf), "MKERR: %"PRIu64" ", proto->error_stats.num_mk_err);
      strlcat(err_stat_msg, tmp_buf, len);
    }
    
    if (proto->error_stats.num_ib_err) {
      snprintf(tmp_buf, sizeof(tmp_buf), "IBERR: %"PRIu64" ", proto->error_stats.num_ib_err);
      strlcat(err_stat_msg, tmp_buf, len);
    }
    strlcat(err_stat_msg, "\n", len);
  }
  else 
    strlcat(err_stat_msg, "No previous errors.\n", len);
  
  _IPATH_ERROR("%s", err_stat_msg);
}

