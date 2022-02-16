#!/usr/bin/python

# This script outputs the mapping from GnuTLS ciphersuite names to
# IANA ciphersuite names.  It can be invoked as:
#
#   $ wget https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv
#   $ python devel/gen-ciphersuite-names.py \
#       lib/algorithms/ciphersuites.c tls-parameters-4.csv

from typing import Mapping, TextIO, Tuple
import csv
import re


def read_c(io: TextIO) -> Mapping[Tuple[int, int], str]:
    result = dict()
    for line in io:
        m = re.match((r'#define\s+(GNUTLS_\S*)\s+\{\s*'
                      r'0x([0-9a-fA-F]{2})\s*,\s*'
                      r'0x([0-9a-fA-F]{2})\s*\}'),
                     line)
        if m:
            result[(int(m.group(2), 16),
                    int(m.group(3), 16))] = m.group(1)
    return result


def read_csv(io: TextIO) -> Mapping[Tuple[int, int], str]:
    result = dict()
    for row in csv.reader(io):
        m = re.match((r'\s*0x([0-9a-fA-F]{2})\s*,'
                      r'\s*0x([0-9a-fA-F]{2})'
                      r'(?:-([0-9a-fA-F]{2}))?\s*'), row[0])
        if m:
            first = int(m.group(1), 16)
            second = list()
            second.append(int(m.group(2), 16))
            if m.lastindex == 3:
                second = list(range(second[-1], int(m.group(3), 16)+1))
            for c in second:
                result[(first, c)] = re.sub(r'\s+', ' ', row[1])
    return result


UNASSIGNED = {
    (0x00, 0x66): 'TLS_DHE_DSS_RC4_128_SHA'
}


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('c', type=argparse.FileType('r'))
    parser.add_argument('csv', type=argparse.FileType('r'))

    args = parser.parse_args()

    g = read_c(args.c)
    i = read_csv(args.csv)

    for (k, v) in g.items():
        if i[k].startswith('TLS_'):
            canonical_name = i[k]
        else:
            canonical_name = UNASSIGNED[k]
        print(f'{v}\t{canonical_name}')
