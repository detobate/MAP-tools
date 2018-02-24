#!/usr/bin/env python3
import ipaddress
import argparse


parser = argparse.ArgumentParser(description='Generate MAP rules for DHCPv6 (RFC7598)')
parser.add_argument('-t', action='store_true', help='Build rules for MAP-T (RFC7599)')
parser.add_argument('-e', action='store_true', help='Build rules for MAP-E (RFC7597)')
parser.add_argument('-d', dest='dmr', metavar='<v6/len>', help='DMR IPv6 prefix and size. eg. 2001:db8:cafe::/64')
parser.add_argument('-b4', dest='bmr4', metavar='<v4/len>', help='BMR IPv4 Prefix')
parser.add_argument('-b6', dest='bmr6', metavar='<v6/len>', help='BMR IPv6 Prefix')
parser.add_argument('-be', dest='be', metavar='<ea_bits>', help='BMR EA bits')
parser.add_argument('-bp', dest='bp', metavar='<psid_offset>', help='BMR PSID Offset')

args = parser.parse_args()


if args.t and args.e:
    print("Error: Use either -t or -e")
    exit(1)

if args.t:
    container = format(95, 'x').zfill(4)
elif args.e:
    container = format(94, 'x').zfill(4)

rules = []

if args.bmr4 and args.bmr6 and args.be and args.bp:
    # Basic Mapping Rule
    rule_cont = format(89, 'x').zfill(4)
    flags = format(0, 'x').zfill(2)
    ea_bits = format(int(args.be), 'x').zfill(2)

    # TODO: Build explicit PSID functionality
    psid_id = format(0, 'x').zfill(4)
    psid_len = format(0, 'x').zfill(2)
    psid_off = format(int(args.bp), 'x').zfill(2)
    port_opt = format(93, 'x').zfill(4)
    port_params = port_opt + '0004' + psid_off + psid_len + psid_id

    try:
        bmr_v4 = ipaddress.ip_network(args.bmr4)
        bmr_v6 = ipaddress.ip_network(args.bmr6)
    except:
        print('Error: Please provide valid v4 and v6 prefixes: %s, %s' % (args.bmr4, args.bmr6))
        exit(1)

    rule_v4 = ''
    for z in bmr_v4.network_address.exploded.split('.'):
        rule_v4 = rule_v4 + format(int(z), 'x').zfill(2)
    rule_v4_len = format(bmr_v4.prefixlen, 'x').zfill(2)

    rule_v6_len = bmr_v6.prefixlen
    # Get the network address and mask off the prefix size
    mask = int(rule_v6_len / 4)
    rule_v6 = bmr_v6.network_address.exploded
    rule_v6 = ''.join(rule_v6.split(':'))
    rule_v6 = rule_v6[:mask]
    rule_v6_len = format(bmr_v6.prefixlen, 'x').zfill(2)

    rule = flags + ea_bits + rule_v4_len + rule_v4 + rule_v6_len + rule_v6 + port_params
    rule = rule_cont + format(int(len(rule)/2), 'x').zfill(4) + rule
    rules.append(rule)


if args.dmr:
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
    rule = rule_cont + format(int(len(rule)/2), 'x').zfill(4) + rule

    rules.append(rule)

compiled = container + format(int(len(''.join(rules))/2), 'x').zfill(4) + ''.join(rules)
print(compiled)
