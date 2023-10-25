// ----------------------------------------------------------------------------
// special port
//-----------------------------------------------------------------------------
const switch_port_t CPU_PORT_ID = 192;
const switch_port_t RECIRC_PORT_ID1 = 68;
const switch_port_t RECIRC_PORT_ID2 = 196;

#define SWITCH_RESUBMIT_TYPE_INVALID 0
#define SWITCH_RESUBMIT_TYPE_HASH_FLOW 1

struct hash_flow_metadata_t {
    bit<32> M1_cnt;
    bit<32> A_cnt;    
    bit<1> stage;
    bit<1> A_flag;
    bit<1> same_dip_flag;
    bit<1> same_sip_flag;
    bit<1> same_pro_flag;
    bit<1> same_port_flag;
}
// Ingress metadata
struct switch_ingress_metadata_t {
    bit<16> pkt_len;
    .........

    hash_flow_metadata_t hash_flow_info;
}

struct switch_header_t {
......
    switch_hash_flow_resubmit_h hash_flow_resubmit;
}
