from scapy.all import *
load_contrib('nsh')


class KUBE_HEADER(Packet):
    fields_desc = [ByteField("vnf_cnt", 0)]


class KUBE_DATA(Packet):
    fields_desc = [ByteField("parser_kube_flag", 0),
                   BitField("node_status", 0, 16),
                   BitField("veth_status", 0, 16),
                   BitField("node_cpu_utilization", 0, 24),
                   BitField("node_memory_utilization", 0, 24),
                   BitField("vnf_status", 0, 16),
                   BitField("vnf_cpu_utilization", 0, 24),
                   BitField("vnf_memory_utilization", 0, 24)]

