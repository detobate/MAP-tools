#!/usr/bin/env python3
import ipaddress
import argparse


parser = argparse.ArgumentParser(description='An IPv4-embedded IPv6 address calculator')
parser.add_argument('-6', dest='v6', metavar='<v6/length>', help='Provide the IPv6 prefix and size. eg. 2001:db8:cafe::/64')
parser.add_argument('-4', dest='v4', metavar='<v4_address>', help='Provide the IPv4 address to embed')
arg = parser.parse_args()


def main():
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
    v6_length = v6.prefixlen

    mapped_prefix = v6.network_address.compressed.split(':')
    mapped_v6 = list(filter(None, mapped_prefix))
    mapped = [None] * 8

    count = 0
    for hextet in mapped_v6:
        if hextet == '':
            pass
        else:
            mapped[count] = hextet
        count += 1

    if v6_length == 32:
        mapped[2] = hex_encode(oct1) + hex_encode(oct2)
        mapped[3] = hex_encode(oct3) + hex_encode(oct4)

    elif v6_length == 40:
        if mapped[2] is not None:
            mapped[2] = mapped[2][:2] + hex_encode(oct1)
        else:
            mapped[2] = str('00') + hex_encode(oct1)
        mapped[3] = hex_encode(oct2) + hex_encode(oct3)
        mapped[4] = str('00') + hex_encode(oct4)

    elif v6_length == 48:
        mapped[3] = hex_encode(oct1) + hex_encode(oct2)
        mapped[4] = str('00') + hex_encode(oct3)
        mapped[5] = hex_encode(oct4) + str('00')

    elif v6_length == 56:
        if mapped[3] is not None:
            mapped[3] = mapped[3][:2] + hex_encode(oct1)
        else:
            mapped[3] = str('00') + hex_encode(oct1)
        mapped[4] = str('00') + hex_encode(oct2)
        mapped[5] = hex_encode(oct3) + hex_encode(oct4)

    elif v6_length == 64:
        mapped[4] = str('00') + hex_encode(oct1)
        mapped[5] = hex_encode(oct2) + hex_encode(oct3)
        mapped[6] = hex_encode(oct4) + str('00')

    elif v6_length == 96:
        mapped[6] = hex_encode(oct1) + hex_encode(oct2)
        mapped[7] = hex_encode(oct3) + hex_encode(oct4)

    else:
        print('Error: IPv6 prefix length must be on the 8 byte boundaries. eg. /48, /56, /64 etc.')
        exit(1)

    ipv6 = ''
    for hextet in mapped:
        if ipv6 == '':
            ipv6 = hextet
        elif hextet is not None:
            ipv6 = ipv6 + ':' + str(hextet)
        else:
            ipv6 = ipv6 + ':' + str('0000')

    try:
        ipv6 = ipaddress.IPv6Address(ipv6)
    except:
        print('Error: Mapping failed: %s' % ipv6)
        exit(1)

    print(ipv6.compressed)


def hex_encode(value, z=2):
    """ Hex encode and zero pad"""
    try:
        h = format(int(value), 'x').zfill(z)
    except:
        print('Error: Couldn\'t hex encode %s' % value)
        h = None

    return(h)


if __name__ == '__main__':
    main()