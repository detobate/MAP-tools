#!/usr/bin/env python3
import ipaddress
import argparse

"""RFC6052 - IPv6 Addressing of IPv4/IPv6 Translators

IPv4-Embedded IPv6 Address Format

   IPv4-converted IPv6 addresses and IPv4-translatable IPv6 addresses
   follow the same format, described here as the IPv4-embedded IPv6
   address Format.  IPv4-embedded IPv6 addresses are composed of a
   variable-length prefix, the embedded IPv4 address, and a variable-
   length suffix, as presented in the following diagram, in which PL
   designates the prefix length:

    +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    |PL| 0-------------32--40--48--56--64--72--80--88--96--104---------|
    +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    |32|     prefix    |v4(32)         | u | suffix                    |
    +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    |40|     prefix        |v4(24)     | u |(8)| suffix                |
    +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    |48|     prefix            |v4(16) | u | (16)  | suffix            |
    +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    |56|     prefix                |(8)| u |  v4(24)   | suffix        |
    +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    |64|     prefix                    | u |   v4(32)      | suffix    |
    +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    |96|     prefix                                    |    v4(32)     |
    +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
"""


parser = argparse.ArgumentParser(description='An IPv4-embedded IPv6 address calculator')
parser.add_argument('-6', dest='v6', metavar='<v6_prefix/length>', help='Provide the IPv6 prefix and size. eg. 2001:db8:cafe::/64')
parser.add_argument('-4', dest='v4', metavar='<v4_address>', help='Provide an IPv4 address to embed')
parser.add_argument('-d', dest='d', metavar='<v6_address/length>', help='Decode an IPv4-embedded IPv6 address e.g., 2001:db8:cafe:0:c0:a800:100:0/64')
arg = parser.parse_args()


def decode(v6):
    try:
        v6_addr, v6_length = v6.split('/')
        v6_length = int(v6_length)
        v6_addr = ipaddress.IPv6Address(v6_addr).exploded.split(':')
    except ValueError:
        raise ValueError('Couldn\'t parse the IPv6 address %s \nMake sure it is a valid IPv6 address and includes prefix length' % v6)
    

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
        
    print(v4_addr)
    

def embed(v4, v6):
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
        raise ValueError('Error: IPv6 prefix length must be on the byte boundaries. eg. /48, /56, /64 etc.')

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


def main():
    if arg.v4 is None and arg.d is None:
        print("Error: Please specify an IPv4 address to map\n")
        parser.print_help()
        exit(1)
    
    elif arg.v4:
        try:
            v4 = ipaddress.IPv4Address(arg.v4)
        except ipaddress.AddressValueError:
            print("Error: Invalid IPv4 address: %s" % arg.v4)
            exit(1)

    if arg.d:
        decode(arg.d)
    else:
        if arg.v6 is None:
            v6 = ipaddress.ip_network('64:ff9b::/96')
        else:
            try:
                v6 = ipaddress.ip_network(arg.v6, strict=False)
            except:
                print("Error: Invalid IPv6 prefix: %s" % arg.v6)
                exit(1)
        
        embed(v4, v6)
        


def hex_encode(value, z=2):
    """ Hex encode an integer and zero pad"""
    try:
        h = format(int(value), 'x').zfill(z)
    except:
        print('Error: Couldn\'t hex encode %s' % value)
        h = None

    return(h)


if __name__ == '__main__':
    main()