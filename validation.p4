    action valid_ipv4_pkt(switch_ip_frag_t ip_frag, bool is_link_local) {
...........

        ig_md.pkt_len = ig_md.pkt_len + hdr.ipv4.total_len;
    }
