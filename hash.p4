#include "types.p4"

control HashFlowSetResubmit(inout hash_flow_metadata_t hash_flow_info, inout ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr) {    
    apply {
        hash_flow_info.M1_cnt = hash_flow_info.A_cnt |-| hash_flow_info.M1_cnt;
        if (hash_flow_info.A_flag == 1 && hash_flow_info.M1_cnt > 0) {
            ig_intr_md_for_dprsr.resubmit_type = SWITCH_RESUBMIT_TYPE_HASH_FLOW;
        } else {
            ig_intr_md_for_dprsr.resubmit_type = SWITCH_RESUBMIT_TYPE_INVALID;
        }
    }
}

control HashFlowACnt(in switch_header_t hdr, inout switch_ingress_metadata_t ig_md) {
    Register<bit<32>, bit<7>>(128) A_sip;
    RegisterAction<bit<32>, bit<7>, bit<1>>(A_sip) update_A_sip = {
        void apply(inout bit<32> reg, out bit<1> rv) {
            if (reg == 0 || reg == hdr.ipv4.src_addr) {
                rv = 1;
            } else {
                rv = 0;
            }            
            reg = hdr.ipv4.src_addr;
        }
    };

    Register<bit<32>, bit<7>>(128) A_dip;
    RegisterAction<bit<32>, bit<7>, bit<1>>(A_dip) update_A_dip = {
        void apply(inout bit<32> reg, out bit<1> rv) {
            if (reg == 0 || reg == hdr.ipv4.dst_addr) {
                rv = 1;
            } else {
                rv = 0;
            }
            reg = hdr.ipv4.dst_addr;
        }
    };

    Register<bit<8>, bit<7>>(128) A_pro;
    RegisterAction<bit<8>, bit<7>, bit<1>>(A_pro) update_A_pro = {
        void apply(inout bit<8> reg, out bit<1> rv) {
            if (reg == 0 || reg == hdr.ipv4.protocol) {
                rv = 1;
            } else {
                rv = 0;
            }            
            reg = hdr.ipv4.protocol;
        }
    };

    Register<bit<16>, bit<7>>(128) A_port;
    RegisterAction<bit<16>, bit<7>, bit<1>>(A_port) update_A_port = {
        void apply(inout bit<16> reg, out bit<1> rv) {
            if (reg == 0 || reg ==  (bit<16>)ig_md.port) {
                rv = 1;
            } else {
                rv = 0;
            }            
            reg = (bit<16>)ig_md.port;
        }
    };        
            
    Register<bit<32>, bit<7>>(128) A_cnt;
    RegisterAction<bit<32>, bit<7>, bit<32>>(A_cnt) add_A_cnt = {
        void apply(inout bit<32> reg, out bit<32> rv) {
            reg = reg |+| (bit<32>)ig_md.pkt_len;
            rv = reg;
        }
    };
    
    RegisterAction<bit<32>, bit<7>, bit<32>>(A_cnt) set_A_cnt = {
        void apply(inout bit<32> reg, out bit<32> rv) {
            reg = (bit<32>)ig_md.pkt_len;
            rv = reg;
        }
    };
        
    Hash<bit<7>>(HashAlgorithm_t.CRC16) ipv4_hash;    
    bit<7> hash;

    apply {        
        hash = ipv4_hash.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.ipv4.protocol, ig_md.port});
        ig_md.hash_flow_info.same_dip_flag = update_A_sip.execute(hash);
        ig_md.hash_flow_info.same_sip_flag = update_A_pro.execute(hash);
        ig_md.hash_flow_info.same_pro_flag = update_A_dip.execute(hash);
        ig_md.hash_flow_info.same_port_flag = update_A_port.execute(hash);
        if (ig_md.hash_flow_info.same_dip_flag == 1 && ig_md.hash_flow_info.same_sip_flag == 1 &&
            ig_md.hash_flow_info.same_pro_flag == 1 && ig_md.hash_flow_info.same_port_flag == 1) {
            ig_md.hash_flow_info.A_cnt = add_A_cnt.execute(hash);
        } else {
            ig_md.hash_flow_info.A_cnt = set_A_cnt.execute(hash);
        }
    }
}

control HashFlow(in switch_header_t hdr, inout switch_ingress_metadata_t ig_md) {
    Register<bit<32>, bit<7>>(128) M1_sip;
    RegisterAction<bit<32>, bit<7>, bit<1>>(M1_sip) update_M1_sip = {
        void apply(inout bit<32> reg, out bit<1> rv) {
            if (reg == 0 || reg == hdr.ipv4.src_addr) {
                reg = hdr.ipv4.src_addr;
                rv = 1;
            } else {
                rv = 0;
            }
        }
    };
    RegisterAction<bit<32>, bit<7>, bit<1>>(M1_sip) replace_M1_sip = {
        void apply(inout bit<32> reg) {
            reg = hdr.ipv4.src_addr;
        }
    };

    Register<bit<32>, bit<7>>(128) M1_dip;
    RegisterAction<bit<32>, bit<7>, bit<1>>(M1_dip) update_M1_dip = {
        void apply(inout bit<32> reg, out bit<1> rv) {
            if (reg == 0 || reg == hdr.ipv4.dst_addr) {
                reg = hdr.ipv4.dst_addr;
                rv = 1;
            } else {
                rv = 0;
            }
        }
    };
    RegisterAction<bit<32>, bit<7>, bit<1>>(M1_dip) replace_M1_dip = {
        void apply(inout bit<32> reg) {
            reg = hdr.ipv4.dst_addr;
        }
    };

    Register<bit<8>, bit<7>>(128) M1_pro;
    RegisterAction<bit<8>, bit<7>, bit<1>>(M1_pro) update_M1_pro = {
        void apply(inout bit<8> reg, out bit<1> rv) {
            if (reg == 0 || reg == hdr.ipv4.protocol) {
                reg = hdr.ipv4.protocol;
                rv = 1;
            } else {
                rv = 0;
            }
        }
    };
    RegisterAction<bit<8>, bit<7>, bit<1>>(M1_pro) replace_M1_pro = {
        void apply(inout bit<8> reg) {
            reg = hdr.ipv4.protocol;
        }
    };

    Register<bit<16>, bit<7>>(128) M1_port;
    RegisterAction<bit<16>, bit<7>, bit<1>>(M1_port) update_M1_port = {
        void apply(inout bit<16> reg, out bit<1> rv) {
            if (reg == 0 || reg ==  (bit<16>)ig_md.port) {
                reg = (bit<16>)ig_md.port;
                rv = 1;
            } else {
                rv = 0;
            }
        }
    };        
    RegisterAction<bit<16>, bit<7>, bit<1>>(M1_port) replace_M1_port = {
        void apply(inout bit<16> reg) {
            reg = (bit<16>)hdr.hash_flow_resubmit.ing_port;
        }
    };
            
    Register<bit<32>, bit<7>>(128) M1_cnt;
    RegisterAction<bit<32>, bit<7>, bit<32>>(M1_cnt) read_M1_cnt = {
        void apply(inout bit<32> reg, out bit<32> rv) {
            rv = reg;            
        }
    };

    RegisterAction<bit<32>, bit<7>, bit<32>>(M1_cnt) update_M1_cnt = {
        void apply(inout bit<32> reg) {
            reg = reg |+| (bit<32>)ig_md.pkt_len;
        }
    };
    
    RegisterAction<bit<32>, bit<7>, bit<32>>(M1_cnt) set_M1_cnt = {
        void apply(inout bit<32> reg) {
            reg = hdr.hash_flow_resubmit.A_cnt;
        }
    };
        
    Hash<bit<7>>(HashAlgorithm_t.CRC8) ipv4_hash;    
    bit<7> hash;

    apply {        
        hash = ipv4_hash.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.ipv4.protocol, ig_md.port});
        if (ig_md.hash_flow_info.stage == 0) {
            if (hdr.ipv4.isValid() && ig_md.port != CPU_PORT_ID && 
                ig_md.port != RECIRC_PORT_ID1 && ig_md.port != RECIRC_PORT_ID1) {
                ig_md.hash_flow_info.same_dip_flag = update_M1_sip.execute(hash);
                ig_md.hash_flow_info.same_sip_flag = update_M1_pro.execute(hash);
                ig_md.hash_flow_info.same_pro_flag = update_M1_dip.execute(hash);
                ig_md.hash_flow_info.same_port_flag = update_M1_port.execute(hash);
                if (ig_md.hash_flow_info.same_dip_flag == 1 && ig_md.hash_flow_info.same_sip_flag == 1 &&
                    ig_md.hash_flow_info.same_pro_flag == 1 && ig_md.hash_flow_info.same_port_flag == 1) {
                    update_M1_cnt.execute(hash);
                } else {
                    ig_md.hash_flow_info.M1_cnt = read_M1_cnt.execute(hash);                    
                    HashFlowACnt.apply(hdr, ig_md);
                    ig_md.hash_flow_info.A_flag = 1; 
                }
            } 
        } else {        
            replace_M1_sip.execute(hash);
            replace_M1_dip.execute(hash);
            replace_M1_pro.execute(hash);
            replace_M1_port.execute(hash);
            set_M1_cnt.execute(hash);
            ig_md.port = hdr.hash_flow_resubmit.ing_port;
        }       
    }
}
