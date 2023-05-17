#!/usr/bin/env python3
from scapy.all import *
import ipaddress
import argparse

parser = argparse.ArgumentParser(description='Decode MAP-T (RFC7598) translated pcaps')
parser.add_argument('-r', dest='pcap_in', metavar='<input.pcap>', help='Read pcap file', required=True)
parser.add_argument('-w', dest='pcap_out', metavar='<output.pcap>', help='Write pcap file')
parser.add_argument('-d', dest='dmr', metavar='<v6/len>', help='Default Mapping Rule IPv6 prefix', required=True)
parser.add_argument('-4', dest='bmr4', metavar='<v4/len>', help='Basic Mapping Rule IPv4 Prefix', required=True)
parser.add_argument('-6', dest='bmr6', metavar='<v6/len>', help='Basic Mapping Rule IPv6 Prefix', required=True)
parser.add_argument('-e', dest='bmrea', metavar='<ea_bits>', help='Basic Mapping Rule EA bits', default=0)
parser.add_argument('-o', dest='bmroff', metavar='<psid_offset>', help='Basic Mapping Rule PSID Offset', default=0)
parser.add_argument('-pd', dest='pd_size', metavar='<dhcpv6_pd_size>', help='DHCPv6 PD size', required=True)

args = parser.parse_args()


def decode_rfc6052(dmr, ipv6):

    v6_length = dmr.prefixlen
    v6_addr = ipv6.exploded.split(':')

    if v6_length == 32:
        v4_addr = ipaddress.IPv4Address(int(v6_addr[2] + v6_addr[3], 16))
    elif v6_length == 40:
        v4_addr = ipaddress.IPv4Address(int(v6_addr[2][2:] + v6_addr[3] + v6_addr[4][2:], 16))
    elif v6_length == 48:
        v4_addr = ipaddress.IPv4Address(int(v6_addr[3] + v6_addr[4][2:] + v6_addr[5][:2], 16))
    elif v6_length == 56:
        v4_addr = ipaddress.IPv4Address(int(v6_addr[3][2:] + v6_addr[4][2:] + v6_addr[5], 16))
    elif v6_length == 64:
        v4_addr = ipaddress.IPv4Address(int(v6_addr[4][2:] + v6_addr[5] + v6_addr[6][:2], 16))
    elif v6_length == 96:
        v4_addr = ipaddress.IPv4Address(int(v6_addr[6] + v6_addr[7], 16))
    else:
        raise ValueError('Error: IPv6 prefix length must be on the byte boundaries. eg. /48, /56, /64 etc.')

    return str(v4_addr)


def main():

    try:
        bmr6 = ipaddress.ip_network(args.bmr6)
    except ValueError:
        print(f'Error: You must provide a valid IPv6 prefix: {args.bmr6}')
        exit(1)
    try:
        bmr4 = ipaddress.ip_network(args.bmr4)
    except ValueError:
        print(f'Error: You must provide a valid IPv4 prefix: {args.bmr4}')
        exit(1)

    ea_length = int(args.pd_size) - bmr6.prefixlen
    psid_length = ea_length - (32 - bmr4.prefixlen)
    ratio = 2 ** psid_length

    try:
        pcap = rdpcap(args.pcap_in)
    except FileNotFoundError:
        print('You must specify a valid input pcap file')
        exit(1)

    try:
        dmr = ipaddress.ip_network(args.dmr)
    except ValueError:
        print(f'Couldn\'t parse the DMR prefix {dmr}\nMake sure it is a valid IPv6 prefix')
        exit(1)

    for pkt in pcap:
        # Iterate through headers until we find an IPv6 header
        # Keep all underlay headers intact, as well as the payload.
        if pkt.haslayer(scapy.layers.inet6.IPv6):
            p6 = pkt.payload
            payload_idx = 1
            # TODO: Keep iterating until we match IPv6 hdr src/dst to BMR/DMR, in case of additional IPv6 encapsulation
            while isinstance(p6, scapy.layers.inet6.IPv6) is False:
                payload_idx += 1
                p6 = p6.payload

            v6_src = ipaddress.ip_address(p6.src)
            v6_dst = ipaddress.ip_address(p6.dst)

            p4 = IP()

            # Decode saddr
            if v6_src in dmr:
                p4.src = decode_rfc6052(dmr, v6_src)
            elif v6_src in bmr6:
                v4_saddr = (int(ipaddress.IPv6Address(v6_src)) & (0xffffffff << 16)) >> 16
                p4.src = '{}'.format(ipaddress.ip_address(v4_saddr))
            else:
                f'Warn: Couldn\'t parse source addr: {v6_src}, check the DMR and BMR are correct'
                p4.src = '0.0.0.0'

            # Decode daddr
            if v6_dst in dmr:
                p4.dst = decode_rfc6052(dmr, v6_dst)
            elif v6_dst in bmr6:
                v4_daddr = (int(ipaddress.IPv6Address(v6_dst)) & (0xffffffff << 16)) >> 16
                p4.dst = '{}'.format(ipaddress.ip_address(v4_daddr))
            else:
                f'Warn: Couldn\'t parse source addr: {v6_src}, check the DMR and BMR are correct'
                p4.dst = '0.0.0.0'

            # Pop off IPv6 Fragment Headers
            # TODO: Check to see if we should do anything else with the IPv4 header
            if isinstance(p6.payload, scapy.layers.inet6.IPv6ExtHdrFragment):
                p4 = p4 / p6.payload.payload
                if p6.payload.m == 1:
                    p4.flags = 'MF'
                if p6.payload.offset > 0:
                    p4.frag = p6.payload.offset
            else:
                p4 = p4 / p6.payload

            pkt_out = pkt
            pkt_out[payload_idx] = p4

            # If Payload parent header is Ethernet, set Ethertype to 0x0800 (IPv4)
            if isinstance(pkt_out[payload_idx - 1], scapy.layers.l2.Ether):
                pkt_out[payload_idx - 1].type = 2048

            if args.pcap_out:
                wrpcap(args.pcap_out, pkt_out, append=True)
            else:
                print(pkt_out)


if __name__ == '__main__':
    main()
