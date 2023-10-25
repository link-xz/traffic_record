#include "headers.p4"
#include "types.p4"
parser SwitchIngressParser(
        packet_in pkt,
        out switch_header_t hdr,
        out switch_ingress_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {
        ......
    state start {
                //init
        ig_md.pkt_len = 0;
        ig_md.hash_flow_info.stage = 0;
        ig_md.hash_flow_info.A_flag = 0;
        ig_md.hash_flow_info.A_cnt = 0;
        ig_md.hash_flow_info.M1_cnt = 0;
        ...........

            state parse_resubmit {
        // Parse resubmitted packet here.
        //Not parse PORT_METADATA_SIZE
        pkt.extract(hdr.hash_flow_resubmit);
        ig_md.hash_flow_info.stage = 1;        
        ig_md.port_lag_index = hdr.hash_flow_resubmit.port_lag_index;
        ig_md.port_lag_label = 0;
        
        transition parse_packet;
    }
}

}
control IngerssResubmit(
    inout switch_header_t hdr,
    in switch_ingress_metadata_t ig_md,
    in ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr) {
    Resubmit() resubmit;

    apply {
        if (ig_intr_md_for_dprsr.resubmit_type == SWITCH_RESUBMIT_TYPE_HASH_FLOW) {
            resubmit.emit<switch_hash_flow_resubmit_h>({
                ig_md.port_lag_index,
                ig_md.port,
                ig_md.hash_flow_info.A_cnt
            });
        } 
    }
}

//-----------------------------------------------------------------------------
// Ingress Deparser
//-----------------------------------------------------------------------------
control SwitchIngressDeparser(
    packet_out pkt,
    inout switch_header_t hdr,
    in switch_ingress_metadata_t ig_md,
    in ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr) {
    ....
        IngerssResubmit() resubmit;
    apply {
        resubmit.apply(hdr, ig_md, ig_intr_md_for_dprsr);
    }
    }
    
