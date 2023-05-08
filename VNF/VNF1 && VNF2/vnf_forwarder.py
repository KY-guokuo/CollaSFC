#!/usr/bin/env python3
# _*_ coding: utf-8 _*_
from __future__ import print_function
from io import open
import os
import sys
import multiprocessing as mp
import threading
import json
import time
from int_hdrs import *
from scapy.all import Ether, IP, UDP, TCP, IPOption, get_if_list, sniff, sendp, get_if_hwaddr, hexdump
import socket


class KUBE_HEADER(Packet):
    """
    k8s header definition.
    """
    fields_desc = [ByteField("vnf_cnt", 0)]


class KUBE_DATA(Packet):
    """
    K8s data definition, and the fields are the following,
    where the parser_kube_flag is the end of parser flag.
    """
    fields_desc = [ByteField("parser_kube_flag", 0),
                   BitField("node_status", 0, 16),
                   BitField("node_cpu_utilization", 0, 24),
                   BitField("node_memory_utilization", 0, 24),
                   BitField("vnf_status", 0, 16),
                   BitField("vnf_cpu_utilization", 0, 24),
                   BitField("vnf_memory_utilization", 0, 24)]


def get_if():
    ifs = get_if_list()
    iface = None  # "h1-eth0"
    for i in ifs:
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return


def layer_assembly(pkt, src_mac, dst_mac, header_len_offset):
    ether_to_udp_layers = Ether(src=src_mac, dst=dst_mac, type=pkt[Ether].type) / \
                          IP(version=pkt[IP].version, ihl=pkt[IP].ihl, tos=pkt[IP].tos,
                             len=pkt[IP].len + header_len_offset,
                             id=pkt[IP].id, flags=pkt[IP].flags, frag=pkt[IP].frag, ttl=pkt[IP].ttl,
                             proto=pkt[IP].proto, chksum=pkt[IP].chksum, src=pkt[IP].src, dst=pkt[IP].dst) / \
                          UDP(sport=pkt[UDP].sport, dport=pkt[UDP].dport, len=pkt[UDP].len + header_len_offset,
                              chksum=pkt[UDP].chksum)
    return ether_to_udp_layers


class packet_reconstruction(object):

    def __init__(self, pkt, src_mac, dst_mac, header_len_offset, vnf_num=None):
        self.pkt = pkt
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.header_len_offset = header_len_offset
        self.vnf_num = vnf_num
        self.INT_DATA = INT_DATA
        self.KUBE_HEADER = KUBE_HEADER
        self.KUBE_DATA = KUBE_DATA

    # def packet_assembly1 第一个VNF, def packet_assembly2 非第一个VNF。
    def packet_assembly_1(self, node_vnf_info_tuple, first_node_info_tuple):
        pkt2 = layer_assembly(self.pkt, self.src_mac, self.dst_mac, self.header_len_offset) / \
               raw(self.pkt[UDP].payload)[:-len(self.pkt.load)] / \
               KUBE_HEADER(vnf_cnt=1) / \
               KUBE_DATA(parser_kube_flag=0, node_status=node_vnf_info_tuple[0],
                         node_cpu_utilization=node_vnf_info_tuple[1], node_memory_utilization=node_vnf_info_tuple[2],
                         vnf_status=node_vnf_info_tuple[3], vnf_cpu_utilization=node_vnf_info_tuple[4],
                         vnf_memory_utilization=node_vnf_info_tuple[5]) / \
               KUBE_DATA(parser_kube_flag=1, node_status=first_node_info_tuple[0],
                         node_cpu_utilization=first_node_info_tuple[1], node_memory_utilization=first_node_info_tuple[2],
                         vnf_status=first_node_info_tuple[3], vnf_cpu_utilization=first_node_info_tuple[4],
                         vnf_memory_utilization=first_node_info_tuple[5]) / self.pkt.load
        sendp(pkt2)
        pkt2.show2()

    def packet_assembly_2(self, node_vnf_info_tuple):
        int_index = 2 + self.pkt[INT_HEADER].hop_cnt * 28 - 1
        # self.pkt[UDP].payload)[:int_index + 1]---> int_header and int_data
        # self.pkt[UDP].payload)[int_index + 2:]---> last k8s data
        # vnf_cnt数量增加1
        vnf_cnt = raw(self.pkt[UDP].payload)[int_index + 1] + 1
        pkt2 = layer_assembly(self.pkt, self.src_mac, self.dst_mac, self.header_len_offset) / \
               raw(self.pkt[UDP].payload)[:int_index + 1] / KUBE_HEADER(vnf_cnt=vnf_cnt) / \
               KUBE_DATA(parser_kube_flag=0, node_status=node_vnf_info_tuple[0],
                         node_cpu_utilization=node_vnf_info_tuple[1], node_memory_utilization=node_vnf_info_tuple[2],
                         vnf_status=node_vnf_info_tuple[3], vnf_cpu_utilization=node_vnf_info_tuple[4],
                         vnf_memory_utilization=node_vnf_info_tuple[5]) / \
               raw(self.pkt[UDP].payload)[int_index + 2:]
        sendp(pkt2)
        pkt2.show2()


def insert_k8s_message_1(json_file, k8s_node_name):
    # ---------------------k8s-node6 data, vnf is none--------------------------------
    node6_status = json_file["node_status"][k8s_node_name]["status"]
    node6_cpu_utilization = json_file["node_metrics"][k8s_node_name]["cpu"]
    node6_memory_utilization = json_file["node_metrics"][k8s_node_name]["memory"]
    vnf_status = -1
    vnf_cpu_utilization = -1
    vnf_memory_utilization = -1
    return node6_status, node6_cpu_utilization, node6_memory_utilization, vnf_status, \
        vnf_cpu_utilization, vnf_memory_utilization


def insert_k8s_message_2(json_file, vnf_name):
    # ---------------------k8s-node1 data and vnf2------------------------------------------
    node1_status = json_file["node_status"]["k8s-node1"]["status"]
    node1_cpu_utilization = json_file["node_metrics"]["k8s-node1"]["cpu"]
    node1_memory_utilization = json_file["node_metrics"]["k8s-node1"]["memory"]
    vnf1_status = json_file["pod_status"][vnf_name]["status"]
    vnf1_cpu_utilization = json_file["pod_metrics"][vnf_name]["cpu"]
    vnf1_memory_utilization = json_file["pod_metrics"][vnf_name]["memory"]
    return node1_status, node1_cpu_utilization, node1_memory_utilization, vnf1_status, \
        vnf1_cpu_utilization, vnf1_memory_utilization


def send_l2_packet(pkt, iface):
    sendp(pkt, iface=iface, verbose=False)


def handle_pkt(pkt, iface):
    if UDP in pkt and pkt[UDP].dport == 5001 and (pkt[Ether].dst == get_if_hwaddr(iface)):
        pkt.show2()
        src_mac = get_if_hwaddr(iface)
        dst_mac = 'ff:ff:ff:ff:ff:ff'
        vnf_name = socket.gethostname()
        print('-------------show k8s packets------------------')
        with open('computing_resource.json', encoding='utf-8') as json_obj:
            computing_data = json.load(json_obj)
            if pkt[IP].tos == 5:
                # 根据INT_HEADER中的first_vnf_flag进行头部堆栈，如果为第一个VNF，则需要增加kube_header和kube_data,
                # kube_data总长度为18Bytes + 17Bytes = 35Bytes.
                if pkt[INT_HEADER].first_vnf_flag == 1:
                    # ---------------------k8s-node6 data, vnf is none--------------------------------
                    first_node_info_tuple = insert_k8s_message_1(computing_data, "k8s-node6")
                    # ---------------------k8s-node1 data and vnf1------------------------------------------
                    node_vnf_info_tuple = insert_k8s_message_2(computing_data, vnf_name)
                    pc = packet_reconstruction(pkt, src_mac, dst_mac, header_len_offset=35, vnf_num=1)
                    pc.packet_assembly_1(node_vnf_info_tuple, first_node_info_tuple)
                else:
                    # 非第一个vnf时，除去kube_header,需增加kube_data的长度为17Bytes.
                    # ---------------------k8s-node1 data and vnf2------------------------------------------
                    node_vnf_info_tuple = insert_k8s_message_2(computing_data, vnf_name)
                    pc = packet_reconstruction(pkt, src_mac, dst_mac, header_len_offset=17)
                    pc.packet_assembly_2(node_vnf_info_tuple)
            if pkt[IP].tos == 9:
                # 根据INT_HEADER中的first_vnf_flag进行头部堆栈，如果为第一个VNF，则需要增加kube_header和kube_data,
                # kube_data总长度为18Bytes + 17Bytes = 35Bytes.
                # k8s-node6 -> k8s-node3 -> vnf5 -> k8s-node5 -> vnf7 -> vnf8 -> k8s-node4
                if pkt[INT_HEADER].first_vnf_flag == 1:
                    # ---------------------k8s-node6 data, vnf is none--------------------------------
                    first_node_info_tuple = insert_k8s_message_1(computing_data, "k8s-node6")
                    # ---------------------k8s-node3 data and vnf5------------------------------------------
                    node_vnf_info_tuple = insert_k8s_message_2(computing_data, vnf_name)
                    pc = packet_reconstruction(pkt, src_mac, dst_mac, header_len_offset=35, vnf_num=1)
                    pc.packet_assembly_1(node_vnf_info_tuple, first_node_info_tuple)
                else:
                    # 非第一个vnf时，除去kube_header,需增加kube_data的长度为17Bytes.
                    # -------------------k8s-node5 -> vnf7 -> vnf8 -> k8s-node4--------------------------
                    node_vnf_info_tuple = insert_k8s_message_2(computing_data, vnf_name)
                    pc = packet_reconstruction(pkt, src_mac, dst_mac, header_len_offset=17)
                    pc.packet_assembly_2(node_vnf_info_tuple)
            if pkt[IP].tos == 13:
                # 根据INT_HEADER中的first_vnf_flag进行头部堆栈，如果为第一个VNF，则需要增加kube_header和kube_data,
                # kube_data总长度为18Bytes + 17Bytes = 35Bytes.
                # k8s-node6 -> k8s-node1 -> vnf1 -> k8s-node5 -> vnf9 -> k8s-node2 -> vnf3 -> k8s-node4
                if pkt[INT_HEADER].first_vnf_flag == 1:
                    # ---------------------k8s-node6 data, vnf is none--------------------------------
                    first_node_info_tuple = insert_k8s_message_1(computing_data, "k8s-node6")
                    # ---------------------k8s-node1 data and vnf1------------------------------------------
                    node_vnf_info_tuple = insert_k8s_message_2(computing_data, vnf_name)
                    pc = packet_reconstruction(pkt, src_mac, dst_mac, header_len_offset=35, vnf_num=1)
                    pc.packet_assembly_1(node_vnf_info_tuple, first_node_info_tuple)
                else:
                    # 非第一个vnf时，除去kube_header,需增加kube_data的长度为17Bytes.
                    # -------------------k8s-node5 -> vnf9 -> k8s-node2 -> vnf3 -> k8s-node4--------------------------
                    node_vnf_info_tuple = insert_k8s_message_2(computing_data, vnf_name)
                    pc = packet_reconstruction(pkt, src_mac, dst_mac, header_len_offset=17)
                    pc.packet_assembly_2(node_vnf_info_tuple)
            if pkt[IP].tos == 17:
                # 根据INT_HEADER中的first_vnf_flag进行头部堆栈，如果为第一个VNF，则需要增加kube_header和kube_data,
                # kube_data总长度为18Bytes + 17Bytes = 35Bytes.
                # k8s-node6 -> k8s-node3 -> vnf6 -> k8s-node2 -> vnf4 -> k8s-node5 -> vnf7 -> k8s-node4
                if pkt[INT_HEADER].first_vnf_flag == 1:
                    # ---------------------k8s-node6 data, vnf is none--------------------------------
                    first_node_info_tuple = insert_k8s_message_1(computing_data, "k8s-node6")
                    # ---------------------k8s-node3 data and vnf6------------------------------------------
                    node_vnf_info_tuple = insert_k8s_message_2(computing_data, vnf_name)
                    pc = packet_reconstruction(pkt, src_mac, dst_mac, header_len_offset=35, vnf_num=1)
                    pc.packet_assembly_1(node_vnf_info_tuple, first_node_info_tuple)
                else:
                    # 非第一个vnf时，除去kube_header,需增加kube_data的长度为17Bytes.
                    # -------------------k8s-node2 -> vnf4 -> k8s-node5 -> vnf7 -> k8s-node4--------------------------
                    node_vnf_info_tuple = insert_k8s_message_2(computing_data, vnf_name)
                    pc = packet_reconstruction(pkt, src_mac, dst_mac, header_len_offset=17)
                    pc.packet_assembly_2(node_vnf_info_tuple)
            if pkt[IP].tos == 21:
                # 根据INT_HEADER中的first_vnf_flag进行头部堆栈，如果为第一个VNF，则需要增加kube_header和kube_data,
                # kube_data总长度为18Bytes + 17Bytes = 35Bytes.
                # k8s-node3 -> k8s-node5 -> vnf8 -> k8s-node4 -> vnf11 -> k8s-node2 -> vnf3 -> k8s-node1
                if pkt[INT_HEADER].first_vnf_flag == 1:
                    # ---------------------k8s-node3 data, vnf is none--------------------------------
                    first_node_info_tuple = insert_k8s_message_1(computing_data, "k8s-node3")
                    # ---------------------k8s-node5 data and vnf8------------------------------------------
                    node_vnf_info_tuple = insert_k8s_message_2(computing_data, vnf_name)
                    pc = packet_reconstruction(pkt, src_mac, dst_mac, header_len_offset=35, vnf_num=1)
                    pc.packet_assembly_1(node_vnf_info_tuple, first_node_info_tuple)
                else:
                    # 非第一个vnf时，除去kube_header,需增加kube_data的长度为17Bytes.
                    # -------------------k8s-node4 -> vnf11 -> k8s-node2 -> vnf3 -> k8s-node1--------------------------
                    node_vnf_info_tuple = insert_k8s_message_2(computing_data, vnf_name)
                    pc = packet_reconstruction(pkt, src_mac, dst_mac, header_len_offset=17)
                    pc.packet_assembly_2(node_vnf_info_tuple)
            if pkt[IP].tos == 25:
                # 根据INT_HEADER中的first_vnf_flag进行头部堆栈，如果为第一个VNF，则需要增加kube_header和kube_data,
                # kube_data总长度为18Bytes + 17Bytes = 35Bytes.
                # k8s-node5 -> k8s-node3 -> vnf5 -> k8s-node6 -> vnf10 -> k8s-node1 -> vnf1 -> k8s-node2
                if pkt[INT_HEADER].first_vnf_flag == 1:
                    # ---------------------k8s-node5 data, vnf is none--------------------------------
                    first_node_info_tuple = insert_k8s_message_1(computing_data, "k8s-node5")
                    # ---------------------k8s-node3 data and vnf5------------------------------------------
                    node_vnf_info_tuple = insert_k8s_message_2(computing_data, vnf_name)
                    pc = packet_reconstruction(pkt, src_mac, dst_mac, header_len_offset=35, vnf_num=1)
                    pc.packet_assembly_1(node_vnf_info_tuple, first_node_info_tuple)
                else:
                    # 非第一个vnf时，除去kube_header,需增加kube_data的长度为17Bytes.
                    # ----------------k8s-node6 -> vnf10 -> k8s-node1 -> vnf1 -> k8s-node2-----------------
                    node_vnf_info_tuple = insert_k8s_message_2(computing_data, vnf_name)
                    pc = packet_reconstruction(pkt, src_mac, dst_mac, header_len_offset=17)
                    pc.packet_assembly_2(node_vnf_info_tuple)


def main():
    # ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    # iface = ifaces[0]
    iface = 'eth0'
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    pool_nums = mp.Pool(processes=10)
    # with HiddenPrints():
    sniff(iface=iface, prn=lambda x: handle_pkt(x, iface))
    sniff(iface=iface, prn=lambda x: pool_nums.apply_async(handle_pkt, args=(x, iface)))
    pool_nums.close()
    pool_nums.join()


if __name__ == '__main__':
    main()
