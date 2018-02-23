#!/usr/bin/env python3
import sys
import ipaddress
import argparse


parser = argparse.ArgumentParser(description='An IPv4-embedded IPv6 address calculator')
parser.add_argument('-6', dest='v6', metavar='<v6/length>', help='Provide the IPv6 prefix and size. eg. 2001:db8:cafe::/64')
parser.add_argument('-4', dest='v4', metavar='<v4_address>', help='Provide the IPv4 address. eg. 192.168.1.1')
arg = parser.parse_args()

if arg.v4 is None:
    print("Error: Please specify an IPv4 address to map\n")
    parser.print_help()
    exit(1)

try:
    v4 = ipaddress.IPv4Address(arg.v4)
except:
    print("Error: Invalid IPv4 address: %s" % arg.v4)
    exit(1)

if arg.v6 is None:
    v6 = ipaddress.ip_network('64:ff9b::/96')
else:
    try:
        v6 = ipaddress.ip_network(arg.v6, strict=False)
    except:
        print("Error: Invalid IPv6 prefix: %s" % arg.v6)
        exit(1)

oct1, oct2, oct3, oct4 = v4.exploded.split('.')
v6_prefix = v6.network_address
v6_length = v6.prefixlen

mapped_prefix = v6.network_address.compressed.split(':')
mapped_v6 = list(filter(None, mapped_prefix))
mapped = [None] * 8

count = 0
for nibble in mapped_v6:
    if nibble == '':
        pass
    else:
        mapped[count] = nibble
    count += 1

if v6_length == 32:
    mapped[2] = format(int(oct1), 'x').zfill(2) + format(int(oct2), 'x').zfill(2)
    mapped[3] = format(int(oct3), 'x').zfill(2) + format(int(oct4), 'x').zfill(2)

elif v6_length == 40:
    if mapped[2] is not None:
        mapped[2] = mapped[2][:1] + format(int(oct1), 'x').zfill(2)
    else:
        mapped[2] = str('00') + format(int(oct1), 'x').zfill(2)
    mapped[3] = format(int(oct2), 'x').zfill(2) + format(int(oct3), 'x').zfill(2)
    mapped[4] = str('00') + format(int(oct4), 'x').zfill(2)

elif v6_length == 48:
    mapped[3] = format(int(oct1), 'x').zfill(2) + format(int(oct2), 'x').zfill(2)
    mapped[4] = str('00') + format(int(oct3), 'x').zfill(2)
    mapped[5] = format(int(oct4), 'x').zfill(2) + str('00')

elif v6_length == 56:
    if mapped[3] is not None:
        mapped[3] = mapped[3][:1] + format(int(oct1), 'x').zfill(2)
    else:
        mapped[3] = str('00') + format(int(oct1), 'x').zfill(2)
    mapped[4] = str('00') + format(int(oct2), 'x').zfill(2)
    mapped[5] = format(int(oct3), 'x').zfill(2) + format(int(oct4), 'x').zfill(2)

elif v6_length == 64:
    mapped[4] = str('00') + format(int(oct1), 'x').zfill(2)
    mapped[5] = format(int(oct2), 'x').zfill(2) + format(int(oct3), 'x').zfill(2)
    mapped[6] = format(int(oct4), 'x').zfill(2) + str('00')

elif v6_length == 96:
    mapped[6] = format(int(oct1), 'x').zfill(2) + format(int(oct2), 'x').zfill(2)
    mapped[7] = format(int(oct3), 'x').zfill(2) + format(int(oct4), 'x').zfill(2)

else:
    print('Error: IPv6 prefix length must be on the 8 byte boundaries. eg. /48, /56, /64 etc.')
    exit(1)

ipv6 = ''
for nibble in mapped:
    if ipv6 == '':
        ipv6 = nibble
    elif nibble is not None:
        ipv6 = ipv6 + ':' + str(nibble)
    else:
        ipv6 = ipv6 + ':' + str('0000')

try:
    ipv6 = ipaddress.IPv6Address(ipv6)
except:
    print('Error: Mapping failed: %s' % ipv6)
    exit(1)

print(ipv6.compressed)


