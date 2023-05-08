from scapy.all import *

load_contrib('nsh')


class INT_HEADER(Packet):
    fields_desc = [BitField("hop_cnt", 0, 8),
                   BitField("shared_vnf_num", 0, 7),
                   BitField("first_vnf_flag", 0, 1)]


class INT_DATA(Packet):
    fields_desc = [BitField("parser_flag", 0, 1),
                   BitField("swid", 0, 7),
                   BitField("qdepth", 0, 32),
                   ByteField("port", 0),
                   IntField("byte_cnt", 0),
                   BitField("last_time", 0, 48),
                   BitField("cur_time", 0, 48),
                   BitField("hop_latency", 0, 48)]


bind_layers(TCP, INT_HEADER)
bind_layers(UDP, INT_HEADER)
bind_layers(INT_HEADER, INT_DATA)
bind_layers(INT_DATA, INT_DATA, parser_flag=0)
