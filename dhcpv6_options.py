#!/usr/bin/env python3
import ipaddress
import argparse


parser = argparse.ArgumentParser(description='Generate hex-encoded DHCPv6 Options for MAP-T/E based on RFC7598')
parser.add_argument('-t', action='store_true', help='Build rules for MAP-T (RFC7599)')
parser.add_argument('-e', action='store_true', help='Build rules for MAP-E (RFC7597)')
parser.add_argument('-d', dest='dmr', metavar='<v6/len>', help='Default Mapping Rule IPv6 prefix and size')
parser.add_argument('-b4', dest='bmr4', metavar='<v4/len>', help='Basic Mapping Rule IPv4 Prefix')
parser.add_argument('-b6', dest='bmr6', metavar='<v6/len>', help='Basic Mapping Rule IPv6 Prefix')
parser.add_argument('-be', dest='bmrea', metavar='<ea_bits>', help='Basic Mapping Rule EA bits', default=0)
parser.add_argument('-bo', dest='bmroff', metavar='<psid_offset>', help='Basic Mapping Rule PSID Offset', default=0)
parser.add_argument('-f4', dest='fmr4', metavar='<v4/len>', help='Forward Mapping Rule IPv4 Prefix')
parser.add_argument('-f6', dest='fmr6', metavar='<v6/len>', help='Forward Mapping Rule IPv6 Prefix')
parser.add_argument('-fe', dest='fmrea', metavar='<ea_bits>', help='Forward Mapping Rule EA bits', default=0)


args = parser.parse_args()


def get_length(field, z=4):
    """ Calculate number of bytes by halving the length of nibbles(4bits)
        Zero pad the total to 4 by default"""
    try:
        length = format(int(len(field) / 2), 'x').zfill(z)
    except:
        print('Error: Couldn\'t parse length of %s' % field)
        exit(1)

    return str(length)


def build_port_opts(offset):
    # TODO: Build explicit PSID functionality
    psid_id = format(0, 'x').zfill(4)
    psid_len = format(0, 'x').zfill(2)
    psid_off = format(int(offset), 'x').zfill(2)
    port_opt = format(93, 'x').zfill(4)
    port_params = port_opt + '0004' + psid_off + psid_len + psid_id
    return(port_params)


def build_rule(v4, v6, ea, offset=0, FMR=False):
    # Basic Mapping Rule
    rule_cont = format(89, 'x').zfill(4)
    ea_bits = format(int(ea), 'x').zfill(2)

    if FMR is False:
        flags = format(0, 'x').zfill(2)
    else:
        flags = format(1, 'x').zfill(2)

    port_params = build_port_opts(offset)

    try:
        v4 = ipaddress.ip_network(v4)
        v6 = ipaddress.ip_network(v6)
    except:
        print('Error: Invalid v4 and/or v6 prefix: %s, %s' % (v4, v6))
        exit(1)

    rule_v4 = ''
    for octet in v4.network_address.exploded.split('.'):
        rule_v4 = rule_v4 + format(int(octet), 'x').zfill(2)
    rule_v4_len = format(v4.prefixlen, 'x').zfill(2)

    rule_v6_len = v6.prefixlen
    # Get the network address and mask off the prefix size
    mask = int(rule_v6_len / 4)
    rule_v6 = v6.network_address.exploded
    rule_v6 = ''.join(rule_v6.split(':'))
    rule_v6 = rule_v6[:mask]
    rule_v6_len = format(v6.prefixlen, 'x').zfill(2)

    rule = flags + ea_bits + rule_v4_len + rule_v4 + rule_v6_len + rule_v6 + port_params
    rule = rule_cont + get_length(rule) + rule
    return(rule)


def build_dmr(args):
    rule_cont = format(91, 'x').zfill(4)
    try:
        v6 = ipaddress.ip_network(args.dmr, strict=False)
    except:
        print('Error: Invalid IPv6 Prefix: %s' % args.dmr)
        exit(1)

    rule_v6_len = v6.prefixlen

    # Get the network address and mask off the prefix size
    mask = int(rule_v6_len / 4)
    rule_v6 = v6.network_address.exploded
    rule_v6 = ''.join(rule_v6.split(':'))
    rule_v6 = rule_v6[:mask]

    rule = format(rule_v6_len, 'x').zfill(2) + str(rule_v6)
    rule = rule_cont + get_length(rule) + rule

    return(rule)


def main():

    if (args.t and args.e) or (not args.t and not args.e):
        print('\nError: Must provide either -t or -e\n')
        parser.print_help()
        exit(1)

    # Setup outer container type
    if args.t:
        container = format(95, 'x').zfill(4)
    elif args.e:
        container = format(94, 'x').zfill(4)

    rules = []
    if args.dmr:
        rules.append(build_dmr(args))
    if args.bmr4 and args.bmr6:
        rules.append(build_rule(args.bmr4, args.bmr6, args.bmrea, args.bmroff))
    if args.fmr4 and args.fmr6:
        rules.append(build_rule(args.fmr4, args.fmr6, args.fmrea, FMR=True))

    compiled = container + get_length(''.join(rules)) + ''.join(rules)
    print(compiled)


if __name__ == '__main__':
    main()