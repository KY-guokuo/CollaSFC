#include <core.p4>
#include <v1model.p4>


const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_ARP = 0x0806;
const bit<16> TYPE_NSH = 0x894F;           //NSH头部-实现服务功能链的方式
const bit<8> TYPE_TCP = 0x06;
const bit<8> TYPE_UDP = 0x11;
const bit<2> TYPE_INT_HEADER = 1; //we use 01 define int header
#define MAX_HOPS 10
#define MAX_PORTS 8


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<48> time_t;
typedef bit<32> qdepth_t;
typedef bit<7>  shared_vnf_num_t;
typedef bit<1>  first_vnf_flag_t;

header ethernet_t {                           //以太网头部
    macAddr_t               dstAddr;
    macAddr_t               srcAddr;
    bit<16>                 etherType;
}

header arp_t {
    bit<16>                 ar_hrd;     //  HW type
    bit<16>                 ar_pro;     //  protocol type
    bit<8>                  ar_hln;     //  HW addr len
    bit<8>                  ar_pln;     //  proto addr len
    bit<16>                 ar_op;
    macAddr_t               src_macAddr;
    ip4Addr_t               src_ipAddr;
    macAddr_t               dst_macAddr;
    ip4Addr_t               dst_ipAddr;
}

header sfc_t {                           //SFC头部
    bit<2>                  ver;
    bit<1>                  zerobit;
    bit<1>                  Cbit;
    bit<6>                  res_bits;
    bit<6>                  len;
    bit<8>                  MDtype;
    bit<8>                  protocol;
    bit<24>                 SPI;
    bit<8>                  SI;
    bit<120>                context;
    bit<1>                  class8;
    bit<1>                  class7;
    bit<1>                  class6;
    bit<1>                  class5;
    bit<1>                  class4;
    bit<1>                  class3;
    bit<1>                  class2;
    bit<1>                  class1;
}

header ipv4_t {                                             //ipv4头部
    bit<4>                  version;
    bit<4>                  ihl;
    bit<6>                  def_sfc;              // We use 6bit field to assign SFP   
    bit<2>                  def_int;              // We use 2bit field to assign INT
    bit<16>                 totalLen;
    bit<16>                 identification;
    bit<3>                  flags;
    bit<13>                 fragOffset;
    bit<8>                  ttl;
    bit<8>                  protocol;
    bit<16>                 hdrChecksum;
    ip4Addr_t               srcAddr;
    ip4Addr_t               dstAddr;
}

header tcp_t {
    bit<16>                 srcPort;
    bit<16>                 dstPort;
    bit<32>                 seqNo;
    bit<32>                 ackNo;
    bit<4>                  dataOffset;
    bit<3>                  res;
    bit<3>                  ecn;
    bit<6>                  ctrl;
    bit<16>                 window;
    bit<16>                 checksum;
    bit<16>                 urgentPtr;
}

header udp_t {
    bit<16>                 srcPort;
    bit<16>                 dstPort;
    bit<16>                 len;
    bit<16>                 checksum;

}

header int_header_t {             //INT头部
    bit<8>                  hop_cnt;
    bit<7>                  shared_vnf_num;     //该节点共享一条SFC中的VNF数量
    bit<1>                  first_vnf_flag;     //1表示是该SFC的第一个VNF，0则表示相反
}

header int_data_t {               //INT数据部分
    bit<1>                  parser_flag;        //解析标志位
    bit<7>                  swid;               //交换机ID
    qdepth_t                qdepth;             //队列深度
    bit<8>                  port;               //端口号
    bit<32>                 byte_cnt;           //字节数
    time_t                  last_time;          //上一次时间
    time_t                  cur_time;           //当前时间
    time_t                  hop_latency;        //延迟
}

header kube_header_t {
    bit<8>                  vnf_cnt;
}

header kube_data_t {
    bit<8>                  parser_kube_flag;
    bit<16>                 node_status;
    bit<24>                 node_cpu_utilization;
    bit<24>                 node_memory_utilization;
    bit<16>                 vnf_status;
    bit<24>                 vnf_cpu_utilization;
    bit<24>                 vnf_memory_utilization;
}

struct parser_metadata_t {
    bit<8>                  remaining;
    bit<8>                  parser_kube_flag;
}

struct metadata {
    bit<8>                  egress_spec;
    parser_metadata_t       parser_metadata;
}

struct headers {
    ethernet_t              ethernet;
    arp_t                   arp;
    sfc_t                   sfc;
    ipv4_t                  ipv4;
    tcp_t                   tcp;
    udp_t                   udp;
    int_header_t            int_header;
    int_data_t[MAX_HOPS]    int_data;
    kube_header_t           kube_header;
    kube_data_t[MAX_HOPS]   kube_data;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_ARP: parse_arp;
            TYPE_NSH: parse_sfc;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_sfc {
        packet.extract(hdr.sfc);
        transition parse_ipv4;
    } 

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP: parse_tcp;
            TYPE_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition  select(hdr.ipv4.def_int) {
            TYPE_INT_HEADER: parse_int_header;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition  select(hdr.ipv4.def_int) {
            TYPE_INT_HEADER: parse_int_header;
            default: accept;
        }
    }

    state parse_int_header {
        packet.extract(hdr.int_header);
        meta.parser_metadata.remaining = hdr.int_header.hop_cnt;
        transition select(hdr.int_header.hop_cnt) {
            0: accept;
            default: parse_int_data;
        }
    }

    state parse_int_data {
        packet.extract(hdr.int_data.next);
        meta.parser_metadata.remaining = meta.parser_metadata.remaining  - 1;
        transition select(meta.parser_metadata.remaining) {
            0 : parse_kube_header;
            default: parse_int_data;
        }
    }

    state parse_kube_header {
        packet.extract(hdr.kube_header);
        meta.parser_metadata.parser_kube_flag = hdr.kube_header.vnf_cnt;
        transition select(hdr.kube_header.vnf_cnt) {
            0: accept;
            default: parse_kube_data;
        }
    }

    state parse_kube_data {
        packet.extract(hdr.kube_data.next);
        meta.parser_metadata.parser_kube_flag = meta.parser_metadata.parser_kube_flag - 1;
        transition select(meta.parser_metadata.parser_kube_flag) {
            0: accept;
            default: parse_kube_data;
        }
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }
/*******************arp数据包的处理***********************/    
    action arp_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    table arp_request {
        key = {
            hdr.arp.src_ipAddr : lpm;      //最长前缀匹配
        }
        actions = {
            arp_forward;
            drop;
        }
        size = 1024;
        default_action = drop;
    }
    table arp_reply {
        key = {
            hdr.arp.dst_ipAddr : lpm;
        }
        actions = {
            arp_forward;
            drop;
        }
        size = 1024;
        default_action = drop;
    }
/*******************正常三层数据转发—ipv4******************************/
    action ipv4_forward( egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }                                     

    table ipv4_match {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
        }
        size = 1024;
        default_action = drop;
    }
/**************Pod转发给SFF，第一步，交换机封装sfc包头 ************/
    action pod_to_switch_encap(bit<24> SPI, bit<8> SI) {
        hdr.ethernet.etherType = TYPE_NSH;
        hdr.sfc.setValid();
        hdr.sfc.ver = 0x1; //0x1 RFC8300
        hdr.sfc.zerobit = 0;
        hdr.sfc.Cbit = 0;
        hdr.sfc.res_bits = 63;
        hdr.sfc.len = 0x6;
        hdr.sfc.MDtype = 0x1; // Fixed sized
        hdr.sfc.protocol = 0x1; // 0x1:  IPv4
        hdr.sfc.SPI = SPI;
        hdr.sfc.SI = SI;
    }
    table pod_to_switch1 {
        key = {
        hdr.ipv4.def_sfc: exact;
        }
        actions = {
            pod_to_switch_encap;
            NoAction;
        }
    }
/************Pod转发给SFF，第二步，SFF根据SPI和SI从相应端口转发出去***************/
    action sfc_forward1(egressSpec_t port) {
        standard_metadata.egress_spec = port;          //定义sfc_forward动作：找到出端口号并赋值
    }

    table sfc_egress1 {
        key = {
            hdr.sfc.SPI: exact;                     //识别SPI和SI—知道是哪条服务链，要将数据包转发给VNF(SF)
            hdr.sfc.SI: exact;
        }
        actions = {
            sfc_forward1;
            NoAction;
        }
        default_action = NoAction();
    }

/*********************交换机直接转发给下一个交换机：SFF1把包转发给SFF2******************/
    action sfc_forward2(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    table sfc_egress2 {
        key = {
            hdr.sfc.SPI: exact;
            hdr.sfc.SI: exact;
        }
        actions = {
            sfc_forward2;
            NoAction;
        }
        default_action = NoAction();
    }
/*************定义交换机解包头并转发给第一个pod（如果只有一个pod，添加一次流表就行了） — SFF转发包给SF***************/
    action switch_to_pod_decap(macAddr_t dstAddr, shared_vnf_num_t shared_vnf_num, first_vnf_flag_t first_vnf_flag, egressSpec_t port) {
        hdr.ethernet.etherType = TYPE_IPV4;
        hdr.sfc.setInvalid();
        hdr.ethernet.dstAddr = dstAddr;
        hdr.int_header.shared_vnf_num = shared_vnf_num;
        hdr.int_header.first_vnf_flag = first_vnf_flag;
        standard_metadata.egress_spec = port;
    }
    table switch_to_pod {
        key = {
            hdr.sfc.SPI: exact;
            hdr.sfc.SI: exact;    
        }
        actions = {
            switch_to_pod_decap;
            NoAction;
        }
    }

/**************一个交换机上有多个Pod情况:pod转发给交换机，交换机转发给第二个pod及之后的pod，都采用以下方式 srcAddr 为host1, host2, host3, host4, host5和host6的mac地址, dstAddr为下一个VNF的mac地址************/       
    action ipv4_forward2(macAddr_t srcAddr, macAddr_t dstAddr, first_vnf_flag_t first_vnf_flag, egressSpec_t port) {
        hdr.ethernet.srcAddr = srcAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.int_header.first_vnf_flag = first_vnf_flag;
        standard_metadata.egress_spec = port;
    }
    table switch_to_multi_pods {
        key = {
        hdr.ipv4.def_sfc: exact;
        }
        actions = {
            ipv4_forward2;
            NoAction;
        }
    }

/*****************INT数据包转发，key值:INT数据包及源地址/目的地址********************/
    action int_forward(egressSpec_t port){
        standard_metadata.egress_spec = port;
    }

    table int_egress{
        key = {
            hdr.ipv4.def_int: exact;
            hdr.ipv4.dstAddr: exact;
            hdr.ipv4.srcAddr: exact;
        }
        actions = {
            int_forward;
            drop;
        }
        size = 1024;
        default_action = drop;
    }
/*****************数据逻辑处理********************/
    apply {
        if (hdr.arp.isValid()) {
            if(arp_request.apply().hit) {  
                return;
            }
            else {arp_reply.apply();}
        }

        else if (hdr.ipv4.isValid() && hdr.ipv4.def_sfc == 0 && hdr.ipv4.def_int == 0){
            ipv4_match.apply();
        }

        /***********DSCP字段的后两位有值，但前六位为0，表明是INT数据包**********************/
        else if (hdr.ipv4.isValid() && hdr.ipv4.def_sfc == 0 && hdr.ipv4.def_int == 1){
             int_egress.apply();   // 应用int_egress表，要在前面定义
        }

        else if (hdr.sfc.isValid()) {
             switch_to_pod.apply();
             sfc_egress2.apply();
        }

        else if (!hdr.sfc.isValid() && hdr.ipv4.def_sfc != 0) { 
                if (hdr.ipv4.def_int == 0) {
                    pod_to_switch1.apply();
                    sfc_egress1.apply();
                }
                else if (hdr.ipv4.def_int == 1) {
                    if (hdr.int_header.shared_vnf_num != 1) {
                        switch_to_multi_pods.apply();
                        hdr.int_header.shared_vnf_num = hdr.int_header.shared_vnf_num - 1; 
                    }  
                    else if (hdr.int_header.shared_vnf_num == 1) { 
                        pod_to_switch1.apply();
                        sfc_egress1.apply();
                    }

            }
            
        }
    }

}   

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    register<bit<32>>(MAX_PORTS) byte_cnt_reg;
    register<time_t>(MAX_PORTS) last_time_reg;
    bit<32> byte_cnt;
    bit<32> new_byte_cnt;
    time_t last_time;
    time_t hop_latency;
    time_t cur_time = standard_metadata.egress_global_timestamp;

    action drop() {
        mark_to_drop(standard_metadata);
    }
    /****************封装int头部*********************************/
    action int_header_encap_tcp() {
        hdr.ipv4.def_int = TYPE_INT_HEADER;
        hdr.int_header.setValid();
        hdr.int_header.hop_cnt = 0;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 2;
    }

    table int_passive_header_tcp {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            int_header_encap_tcp;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table int_active_header_tcp {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            int_header_encap_tcp;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    action int_header_encap_udp(){
        hdr.ipv4.def_int = TYPE_INT_HEADER;
        hdr.int_header.setValid();
        hdr.int_header.hop_cnt = 0;
        hdr.udp.len = hdr.udp.len + 2;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 2;
    }

    table int_passive_header_udp {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            int_header_encap_udp;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table int_active_header_udp {
    key = {
        hdr.ipv4.dstAddr: lpm;
    }
    actions = {
        int_header_encap_udp;
        NoAction;
    }
    size = 1024;
    default_action = NoAction();
    }

    action sfc_decapsulation() {
        hdr.ethernet.etherType = TYPE_IPV4;
        hdr.ipv4.def_sfc = 0;
        hdr.ipv4.def_int = 0;
        hdr.sfc.setInvalid();
    }
    table sfc_termination {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            sfc_decapsulation;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
/*******************int数据部分头部入栈*********************/

    action set_swid_tcp(bit<7> swid) {
        hdr.int_header.hop_cnt = hdr.int_header.hop_cnt + 1;
        hdr.int_data.push_front(1);
        hdr.int_data[0].setValid();
        hdr.int_data[0].swid = swid;
        hdr.int_data[0].qdepth = (qdepth_t)standard_metadata.deq_qdepth;
        hdr.int_data[0].port = (bit<8>)standard_metadata.egress_port;
        hdr.int_data[0].byte_cnt = byte_cnt;

        // read / update the last_time_reg
        last_time_reg.read(last_time, (bit<32>)standard_metadata.egress_port);
        last_time_reg.write((bit<32>)standard_metadata.egress_port, cur_time);
        hdr.int_data[0].last_time = last_time;
        hdr.int_data[0].cur_time = cur_time;
        hdr.int_data[0].hop_latency = hop_latency;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 28;
    }

    action set_swid_udp(bit<7> swid) {
        hdr.int_header.hop_cnt = hdr.int_header.hop_cnt + 1;
        hdr.int_data.push_front(1);
        hdr.int_data[0].setValid();
        hdr.int_data[0].swid = swid;
        hdr.int_data[0].qdepth = (qdepth_t)standard_metadata.deq_qdepth;
        hdr.int_data[0].port = (bit<8>)standard_metadata.egress_port;
        hdr.int_data[0].byte_cnt = byte_cnt;

        // read / update the last_time_reg
        last_time_reg.read(last_time, (bit<32>)standard_metadata.egress_port);
        last_time_reg.write((bit<32>)standard_metadata.egress_port, cur_time);
        hdr.int_data[0].last_time = last_time;
        hdr.int_data[0].cur_time = cur_time;
        hdr.int_data[0].hop_latency = hop_latency;
        hdr.udp.len = hdr.udp.len + 28;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 28;
    }

//  we define the six actions for in-network-computing failure detection. 
    action in_network_computing_execution_sfc1() { }

    action in_network_computing_execution_sfc2() { }

    action in_network_computing_execution_sfc3() { }

    action in_network_computing_execution_sfc4() { }

    action in_network_computing_execution_sfc5() { }

    action in_network_computing_execution_sfc6() { }

/**********************the DT depth of sfc1 ******************/
    action dt_depth_2_sfc1() {
        if (hdr.kube_header.vnf_cnt == 1) {
            if (hdr.kube_data[0].vnf_status == 1) {
                hdr.sfc.class1 = 0;
            }
        }
        else if (hdr.kube_header.vnf_cnt == 2) {
            if (hdr.kube_data[0].node_status == 1 && hdr.kube_data[1].node_status == 1) {
                hdr.sfc.class1 = 0;
            }
            else {
                hdr.sfc.class1 = 1;
            } 
        } 
        else if (hdr.kube_header.vnf_cnt >= 3) {
            if (hdr.int_data[2].qdepth <= 30) {
                if (hdr.kube_data[1].node_cpu_utilization <= 80) {
                    hdr.sfc.class1 = 0;
                }
                else {
                    hdr.sfc.class1 = 1;
                }
            }
            else {
                if (hdr.kube_data[3].node_memory_utilization <= 80) {
                    hdr.sfc.class3 = 1;                
                }
                else {
                    hdr.sfc.class5 = 1;
                }

            } 
        }

    }

    action dt_depth_3_sfc1() {
        if (hdr.kube_header.vnf_cnt == 3) {
            if (hdr.int_data[2].qdepth <= 30) {
                if (hdr.kube_data[1].node_cpu_utilization <= 80) {
                    if (hdr.kube_data[2].vnf_cpu_utilization <= 2) {
                        hdr.sfc.class1 = 0;
                    }
                    else {
                        hdr.sfc.class2 = 1;
                    }
                }
                else {
                    hdr.sfc.class1 = 1;
                }
            }
            else {
                if (hdr.kube_data[3].node_memory_utilization <= 80) {
                    if (hdr.kube_data[0].node_memory_utilization <= 80) {
                        hdr.sfc.class3 = 1;
                    }
                    else {
                        hdr.sfc.class5 = 1;
                    }
                }
                else {
                    hdr.sfc.class5 = 1;
                }

            }
        }

    }

    action dt_depth_4_sfc1() {
        if (hdr.kube_header.vnf_cnt == 3) {
            if (hdr.int_data[2].qdepth <= 30) {
                if (hdr.kube_data[1].node_cpu_utilization <= 80) {
                    if (hdr.kube_data[2].vnf_cpu_utilization <= 2) {
                        if (hdr.kube_data[3].node_cpu_utilization <= 80) {
                            hdr.sfc.class1 = 0;
                        }
                        else {
                            hdr.sfc.class1 = 1;
                        }
                    }
                    else {
                        if (hdr.kube_data[2].vnf_status <= 1) {
                            hdr.sfc.class2 = 1;
                        }
                        else {
                            hdr.sfc.class2 = 1;
                        }
                    }
                }
                else {
                    hdr.sfc.class1 = 1;
                }
            }
            else {
                if (hdr.kube_data[3].node_memory_utilization <= 80) {
                    if (hdr.kube_data[0].node_memory_utilization <= 80) {
                        if (hdr.kube_data[4].node_memory_utilization <= 47) {
                            hdr.sfc.class3 = 1;
                        }
                        else {
                            hdr.sfc.class5 = 1;
                        }
                    }
                    else {
                        hdr.sfc.class5 = 1;
                    }
                }
                else {
                    hdr.sfc.class5 = 1;
                }
            }
        }
        
    }

    action dt_depth_5_sfc1() {
        if (hdr.kube_header.vnf_cnt == 3) {
            if (hdr.int_data[2].qdepth <= 30) {
                if (hdr.kube_data[1].node_cpu_utilization <= 80) {
                    if (hdr.kube_data[2].vnf_cpu_utilization <= 1) {
                        if (hdr.kube_data[0].node_memory_utilization <= 80) {
                            if (hdr.kube_data[3].node_cpu_utilization <= 80) {
                                hdr.sfc.class1 = 0;
                            }
                            else {
                                hdr.sfc.class1 = 1;
                            }
                        }
                        else {
                            hdr.sfc.class1 = 1;
                        }
                    }
                    else {
                        if (hdr.kube_data[2].vnf_status <= 0) {
                            if (hdr.kube_data[0].node_memory_utilization <= 81) {
                                hdr.sfc.class2 = 1;
                            }
                            else {
                                hdr.sfc.class4 = 1;
                            }
                        }
                        else {
                            if (hdr.kube_data[2].vnf_cpu_utilization <= 60) {
                                hdr.sfc.class1 = 0;
                            }
                            else {
                                hdr.sfc.class2 = 1;
                            }
                        }
                    }
                }
                else {
                    hdr.sfc.class1 = 1;
                }
            }
            else {
                if (hdr.kube_data[3].node_memory_utilization <= 80) {
                    if (hdr.kube_data[0].node_memory_utilization <= 80) {
                        if (hdr.kube_data[4].node_memory_utilization <= 47) {
                            if (hdr.kube_data[1].node_cpu_utilization <= 51) {
                                hdr.sfc.class3 = 1;
                            }
                            else {
                                hdr.sfc.class5 = 1;
                            }
                        }
                        else {
                         hdr.sfc.class5 = 1;
                        }
                    }
                    else {
                        hdr.sfc.class5 = 1;
                    }
                }
                else {
                    hdr.sfc.class5 = 1;
                }
            }
        }
    }

    action dt_depth_6_sfc1() {
        if (hdr.kube_header.vnf_cnt == 3) {
            if (hdr.int_data[2].qdepth <= 30) {
                if (hdr.kube_data[1].node_cpu_utilization <= 80) {
                    if (hdr.kube_data[2].vnf_cpu_utilization <= 1) {
                        if (hdr.kube_data[0].node_memory_utilization <= 80) {
                            if (hdr.kube_data[3].node_cpu_utilization <= 80) {
                                if (hdr.kube_data[1].node_memory_utilization <= 77) {
                                    hdr.sfc.class1 = 0;
                                }
                                else {
                                    hdr.sfc.class1 = 1;
                                }
                            }
                        }
                        else {
                            hdr.sfc.class1 = 1;
                        }
                    }
                    else {
                        if (hdr.kube_data[2].vnf_status <= 0) {
                            if (hdr.kube_data[0].node_memory_utilization <= 81) {
                                hdr.sfc.class2 = 1;
                            }
                            else {
                                hdr.sfc.class4 = 1;
                            } 
                        }
                        else {
                            if (hdr.kube_data[2].vnf_cpu_utilization <= 60) {
                                if (hdr.kube_data[1].node_cpu_utilization <= 23) {
                                    hdr.sfc.class1 = 0;
                                }
                                else {
                                    hdr.sfc.class1 = 1;
                                }
                            }
                            else {
                                if (hdr.kube_data[1].node_cpu_utilization <= 55) {
                                    hdr.sfc.class2 = 1;
                                }
                                else {
                                    hdr.sfc.class4 = 1;
                                }
                            }    
                        }
                    }
                }
                else {
                    hdr.sfc.class1 = 1;
                }
            }
            else {
                if (hdr.kube_data[3].node_memory_utilization >= 80) {
                    if (hdr.kube_data[0].node_memory_utilization <= 80) {
                        if (hdr.kube_data[4].node_memory_utilization <= 47) {
                            if (hdr.int_data[2].hop_latency <= 83788) {
                                hdr.sfc.class3 = 1;
                            }
                            else {
                                hdr.sfc.class5 = 1;
                            }
                        }
                        else {
                            hdr.sfc.class5 = 1;
                        }
                    }
                    else {
                        hdr.sfc.class5 = 1;
                    }
                }
                else {
                    hdr.sfc.class5 = 1;
                }
            }
        }
    }

    action dt_depth_7_sfc1() {
        if (hdr.kube_header.vnf_cnt == 3) {
            if (hdr.int_data[2].qdepth <= 30) {
                if (hdr.kube_data[1].node_cpu_utilization <= 80) {
                    if (hdr.kube_data[2].vnf_cpu_utilization <= 1) {
                        if (hdr.kube_data[0].node_memory_utilization <= 80) {
                            if (hdr.kube_data[3].node_cpu_utilization <= 80) {
                                if (hdr.kube_data[1].node_memory_utilization <= 77) {
                                    if (hdr.int_data[2].swid <= 4) {
                                        hdr.sfc.class3 = 1;
                                    }
                                    else {
                                        hdr.sfc.class1 = 0;
                                    }
                                }
                                else {
                                    if (hdr.kube_data[1].node_memory_utilization <= 80) {
                                        hdr.sfc.class1 = 1;
                                    }
                                    else {
                                        hdr.sfc.class1 = 1;
                                    }
                                }                            
                            }
                            else {
                                hdr.sfc.class1 = 1;
                            }                      
                        }
                        else {
                            hdr.sfc.class1 = 1;
                        }
                    }
                    else {
                        if (hdr.kube_data[2].vnf_status <= 0) {
                            if (hdr.kube_data[0].node_memory_utilization <= 81) {
                                hdr.sfc.class2 = 1;
                            }
                            else {
                                hdr.sfc.class4 = 1;
                            }
                        }
                        else {
                            if (hdr.kube_data[2].vnf_cpu_utilization <= 60) {
                                if (hdr.kube_data[1].node_cpu_utilization <= 23) {
                                    if (hdr.int_data[0].hop_latency <= 37) {
                                        hdr.sfc.class1 = 0;
                                    }
                                    else {
                                        hdr.sfc.class1 = 1;
                                    }
                                }
                                else {
                                    if (hdr.kube_data[2].vnf_cpu_utilization <= 58) {
                                        hdr.sfc.class1 = 1;
                                    }
                                    else {
                                        hdr.sfc.class1 = 0;
                                    }
                                }
                            }
                            else {
                                if (hdr.kube_data[1].node_cpu_utilization <= 55) {
                                    hdr.sfc.class2 = 1;
                                }
                                else {
                                    hdr.sfc.class4 = 1;
                                }
                            }
                        }
                    }
                }
                else {
                    hdr.sfc.class1 = 1;
                }
            }
            else {
                if (hdr.kube_data[3].node_memory_utilization <= 80) {
                    if (hdr.kube_data[0].node_memory_utilization <= 80) {
                        if (hdr.kube_data[4].node_memory_utilization <= 47) {
                            if (hdr.kube_data[1].node_cpu_utilization <= 51) {
                                hdr.sfc.class3 = 1;
                            }
                            else {
                                hdr.sfc.class5 = 1;
                            }
                        }
                        else {
                            hdr.sfc.class5 = 1;
                        }
                    }
                    else {
                        hdr.sfc.class5 = 1;
                    }
                }
                else {
                    hdr.sfc.class5 = 1;
                }
            }
        }
    }

/**********************the DT depth of sfc2 ******************/
    action dt_depth_2_sfc2() {
        NoAction();
    }
    action dt_depth_3_sfc2() {
        NoAction();
    }

    action dt_depth_4_sfc2() {
        NoAction();
    }

    action dt_depth_5_sfc2() {
        NoAction();
    }

    action dt_depth_6_sfc2() {
        NoAction();
    }

    action dt_depth_7_sfc2() {
        NoAction();
    }

/**********************the DT depth of sfc3 ******************/
    action dt_depth_2_sfc3() {
        NoAction();
    }
    action dt_depth_3_sfc3() {
        NoAction();
    }

    action dt_depth_4_sfc3() {
        NoAction();
    }

    action dt_depth_5_sfc3() {
        NoAction();
    }

    action dt_depth_6_sfc3() {
        NoAction();
    }

    action dt_depth_7_sfc3() {
        NoAction();
    }

/**********************the DT depth of sfc4 ******************/
    action dt_depth_2_sfc4() {
        NoAction();
    }
    action dt_depth_3_sfc4() {
        NoAction();
    }

    action dt_depth_4_sfc4() {
        NoAction();
    }

    action dt_depth_5_sfc4() {
        NoAction();
    }

    action dt_depth_6_sfc4() {
        NoAction();
    }

    action dt_depth_7_sfc4() {
        NoAction();
    }

/**********************the DT depth of sfc5 ******************/
    action dt_depth_2_sfc5() {
        NoAction();
    }
    action dt_depth_3_sfc5() {
        NoAction();
    }

    action dt_depth_4_sfc5() {
        NoAction();
    }

    action dt_depth_5_sfc5() {
        NoAction();
    }

    action dt_depth_6_sfc5() {
        NoAction();
    }

    action dt_depth_7_sfc5() {
        NoAction();
    }

/**********************the DT depth of sfc6 ******************/
    action dt_depth_2_sfc6() {
        NoAction();
    }
    action dt_depth_3_sfc6() {
        NoAction();
    }

    action dt_depth_4_sfc6() {
        NoAction();
    }

    action dt_depth_5_sfc6() {
        NoAction();
    }

    action dt_depth_6_sfc6() {
        NoAction();
    }

    action dt_depth_7_sfc6() {
        NoAction();
    }

    table swid_tcp_passive1 {
        actions = {
            set_swid_tcp;
            NoAction;
        }
        default_action = NoAction();
    }

    table swid_tcp_passive2 {
        actions = {
            set_swid_tcp;
            NoAction;
        }
        default_action = NoAction();
    }

    table swid_tcp_active1 {
        actions = {
            set_swid_tcp;
            NoAction;
        }
        default_action = NoAction();
    }

    table swid_tcp_active2 {
        actions = {
            set_swid_tcp;
            NoAction;
        }
        default_action = NoAction();
    }

    table swid_udp_passive1 {
        actions = {
            set_swid_udp;
            NoAction;
        }
        default_action = NoAction();
    }

    table swid_udp_passive2 {
        actions = {
            set_swid_udp;
            NoAction;
        }
        default_action = NoAction();
    }

    table swid_udp_active1 {
        actions = {
            set_swid_udp;
            NoAction;
        }
        default_action = NoAction();
    }

    table swid_udp_active2 {
        actions = {
            set_swid_udp;
            NoAction;
        }
        default_action = NoAction();
    }

    table set_NoAction {
        actions = {
            NoAction;
        }
    }

    table in_network_computing {
        key = {
            hdr.sfc.SPI : exact; 
        }
        actions = {
            in_network_computing_execution_sfc1;
            in_network_computing_execution_sfc2;
            in_network_computing_execution_sfc3;
            in_network_computing_execution_sfc4;
            in_network_computing_execution_sfc5;
            in_network_computing_execution_sfc6;
        }
    }

    table DT_depth_sfc1 {
        actions = {
            dt_depth_2_sfc1;
            dt_depth_3_sfc1;
            dt_depth_4_sfc1;
            dt_depth_5_sfc1;
            dt_depth_6_sfc1;
            dt_depth_7_sfc1;   
        }
    }

    table DT_depth_sfc2 {
        actions = {
            dt_depth_2_sfc2;
            dt_depth_3_sfc2;
            dt_depth_4_sfc2;
            dt_depth_5_sfc2;
            dt_depth_6_sfc2;
            dt_depth_7_sfc2;   
        }
    }

    table DT_depth_sfc3 {
        actions = {
            dt_depth_2_sfc3;
            dt_depth_3_sfc3;
            dt_depth_4_sfc3;
            dt_depth_5_sfc3;
            dt_depth_6_sfc3;
            dt_depth_7_sfc3;   
        }
    }

    table DT_depth_sfc4 {
        actions = {
            dt_depth_2_sfc4;
            dt_depth_3_sfc4;
            dt_depth_4_sfc4;
            dt_depth_5_sfc4;
            dt_depth_6_sfc4;
            dt_depth_7_sfc4;   
        }
    }

    table DT_depth_sfc5 {
        actions = {
            dt_depth_2_sfc5;
            dt_depth_3_sfc5;
            dt_depth_4_sfc5;
            dt_depth_5_sfc5;
            dt_depth_6_sfc5;
            dt_depth_7_sfc5;   
        }
    }

    table DT_depth_sfc6 {
        actions = {
            dt_depth_2_sfc6;
            dt_depth_3_sfc6;
            dt_depth_4_sfc6;
            dt_depth_5_sfc6;
            dt_depth_6_sfc6;
            dt_depth_7_sfc6;   
        }
    }

/************************逻辑处理********************************/
    apply {
     /******************************UDP数据包**********************************/
        // ipv4数据包
        if (hdr.ipv4.isValid() && hdr.ipv4.def_sfc == 0 && hdr.ipv4.def_int == 0){
                set_NoAction.apply();
        }

        // SFC数据包
        /** 
        else if (hdr.ipv4.def_int == 0 && hdr.sfc.isValid() && hdr.udp.isValid()){
            sfc_termination.apply();
        }
        **/
        // SFC+INT 被动探测法
        else if (hdr.sfc.isValid() && hdr.udp.isValid()){
            if (standard_metadata.egress_port == 0){
                set_NoAction.apply();
            }
            else {
                if (hdr.int_header.isValid()){
                    byte_cnt_reg.read(byte_cnt, (bit<32>)standard_metadata.egress_port);
                    byte_cnt = byte_cnt + standard_metadata.packet_length;
                    new_byte_cnt = (hdr.int_header.isValid()) ? 0 : byte_cnt;
                    byte_cnt_reg.write((bit<32>)standard_metadata.egress_port, new_byte_cnt);
                    hop_latency = standard_metadata.egress_global_timestamp - standard_metadata.ingress_global_timestamp;
                    swid_udp_passive1.apply();
                    if (hdr.int_header.hop_cnt == 1) {
                        hdr.int_data[0].parser_flag = 1;
                    }
                    else {
                        hdr.int_data[0].parser_flag = 0;
                    }
                    /***** DT testing ********when qdepth > 50, we use control plane to classfy the failure ****/
                    if (hdr.int_data[0].qdepth <= 50) {
                        if (hdr.kube_header.isValid()){
                            switch (in_network_computing.apply().action_run) {
                                in_network_computing_execution_sfc1: { DT_depth_sfc1.apply(); }
                                in_network_computing_execution_sfc2: { DT_depth_sfc2.apply(); }
                                in_network_computing_execution_sfc3: { DT_depth_sfc3.apply(); }
                                in_network_computing_execution_sfc4: { DT_depth_sfc4.apply(); }
                                in_network_computing_execution_sfc5: { DT_depth_sfc5.apply(); }
                                in_network_computing_execution_sfc6: { DT_depth_sfc6.apply(); }
                            }
                        } 
                    }

                }
                else if (!hdr.int_header.isValid()){
                    int_passive_header_udp.apply();
                    byte_cnt_reg.read(byte_cnt, (bit<32>)standard_metadata.egress_port);
                    byte_cnt = byte_cnt + standard_metadata.packet_length;
                    new_byte_cnt = (hdr.int_header.isValid()) ? 0 : byte_cnt;
                    byte_cnt_reg.write((bit<32>)standard_metadata.egress_port, new_byte_cnt);
                    hop_latency = standard_metadata.egress_global_timestamp - standard_metadata.ingress_global_timestamp;
                    swid_udp_passive2.apply();
                    if (hdr.int_header.hop_cnt == 1) {
                        hdr.int_data[0].parser_flag = 1;
                    }
                    else {
                        hdr.int_data[0].parser_flag = 0;
                    }
                    //int_sink1.apply(); 
                }
            }
        }

        // INT主动探测法
        else if (hdr.ipv4.def_int == 1 && !hdr.sfc.isValid() && hdr.udp.isValid()){
            if (!hdr.int_header.isValid()){
                int_active_header_udp.apply();
                byte_cnt_reg.read(byte_cnt, (bit<32>)standard_metadata.egress_port);
                byte_cnt = byte_cnt + standard_metadata.packet_length;
                new_byte_cnt = (hdr.int_header.isValid()) ? 0 : byte_cnt;
                byte_cnt_reg.write((bit<32>)standard_metadata.egress_port, new_byte_cnt);
                hop_latency = standard_metadata.egress_global_timestamp - standard_metadata.ingress_global_timestamp;
                swid_udp_active1.apply();
            }
            else if (hdr.int_header.isValid()){
                byte_cnt_reg.read(byte_cnt, (bit<32>)standard_metadata.egress_port);
                byte_cnt = byte_cnt + standard_metadata.packet_length;
                new_byte_cnt = (hdr.int_header.isValid()) ? 0 : byte_cnt;
                byte_cnt_reg.write((bit<32>)standard_metadata.egress_port, new_byte_cnt);
                hop_latency = standard_metadata.egress_global_timestamp - standard_metadata.ingress_global_timestamp;
                swid_udp_active2.apply();
                //int_sink2.apply();
            }
        }
    /******************************TCP数据包***********************************/
        // SFC数据包
        else if (hdr.ipv4.def_int == 0 && hdr.sfc.isValid() && hdr.tcp.isValid()){
            sfc_termination.apply();
        }

        // SFC+INT 被动探测法
        else if (hdr.ipv4.def_int == 1 && hdr.sfc.isValid() && hdr.tcp.isValid()){
            if (standard_metadata.egress_port == 0){
                    set_NoAction.apply();
                }
            else {
                if (!hdr.int_header.isValid()){
                    int_passive_header_tcp.apply();
                    byte_cnt_reg.read(byte_cnt, (bit<32>)standard_metadata.egress_port);
                    byte_cnt = byte_cnt + standard_metadata.packet_length;
                    new_byte_cnt = (hdr.int_header.isValid()) ? 0 : byte_cnt;
                    byte_cnt_reg.write((bit<32>)standard_metadata.egress_port, new_byte_cnt);
                    hop_latency = standard_metadata.egress_global_timestamp - standard_metadata.ingress_global_timestamp;
                    swid_tcp_passive1.apply();
                    //sfc_termination.apply();
                    if (hdr.int_header.hop_cnt == 1) {
                        hdr.int_data[0].parser_flag = 1;
                    }
                    else {
                        hdr.int_data[0].parser_flag = 0;
                    }
                }
                else if (hdr.int_header.isValid()){
                    byte_cnt_reg.read(byte_cnt, (bit<32>)standard_metadata.egress_port);
                    byte_cnt = byte_cnt + standard_metadata.packet_length;
                    new_byte_cnt = (hdr.int_header.isValid()) ? 0 : byte_cnt;
                    byte_cnt_reg.write((bit<32>)standard_metadata.egress_port, new_byte_cnt);
                    hop_latency = standard_metadata.egress_global_timestamp - standard_metadata.ingress_global_timestamp;
                    swid_tcp_passive2.apply();
                    //sfc_termination.apply();
                    if (hdr.int_header.hop_cnt == 1) {
                        hdr.int_data[0].parser_flag = 1;
                    }
                    else {
                        hdr.int_data[0].parser_flag = 0;
                    }
                    //int_sink1.apply();
                }
            }
        }

        // INT主动探测法
        else if (hdr.ipv4.def_int == 1 && !hdr.sfc.isValid() && hdr.tcp.isValid()){
            if (!hdr.int_header.isValid()){
                int_active_header_tcp.apply();
                byte_cnt_reg.read(byte_cnt, (bit<32>)standard_metadata.egress_port);
                byte_cnt = byte_cnt + standard_metadata.packet_length;
                new_byte_cnt = (hdr.int_header.isValid()) ? 0 : byte_cnt;
                byte_cnt_reg.write((bit<32>)standard_metadata.egress_port, new_byte_cnt);
                hop_latency = standard_metadata.egress_global_timestamp - standard_metadata.ingress_global_timestamp;
                swid_tcp_active1.apply();
            }
            else if (hdr.int_header.isValid()){
                byte_cnt_reg.read(byte_cnt, (bit<32>)standard_metadata.egress_port);
                byte_cnt = byte_cnt + standard_metadata.packet_length;
                new_byte_cnt = (hdr.int_header.isValid()) ? 0 : byte_cnt;
                byte_cnt_reg.write((bit<32>)standard_metadata.egress_port, new_byte_cnt);
                hop_latency = standard_metadata.egress_global_timestamp - standard_metadata.ingress_global_timestamp;
                swid_tcp_active2.apply();
                //int_sink2.apply();
            }
        }    
    }
}


/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
    update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.def_sfc,
              hdr.ipv4.def_int,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.sfc);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.int_header);
        packet.emit(hdr.int_data);
        packet.emit(hdr.kube_header);
        packet.emit(hdr.kube_data);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;

