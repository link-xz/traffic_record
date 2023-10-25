control SwitchIngress(
        inout switch_header_t hdr,
        inout switch_ingress_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_from_prsr,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm) {
        .........
            HashFlow() Hashflow;
                apply {   
                        pkt_validation.apply(hdr, ig_md);
                       Hashflow.apply(hdr, ig_md);
                       ...........
                       HashFlowSetResubmit.apply(ig_md.hash_flow_info, ig_intr_md_for_dprsr);
                       }
                       }
