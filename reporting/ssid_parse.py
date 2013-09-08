#!/usr/bin/env python

import xml.etree.ElementTree as ET
import argparse
import sys

#set up arguments
parser = argparse.ArgumentParser()
parser.add_argument('-o', '--output', help='Output file to write to', metavar='output')
parser.add_argument('-s', '--ssid', action='append', default=[], \
                    metavar='ssid', help='An SSID to look for, can be used more than once')
parser.add_argument('-S', '--ssid-file', dest='ssid_file', metavar='ssid-file', help='A file with SSIDs to look for')
parser.add_argument('file', nargs=1, help='Kismet NETXML file to parse', metavar='xml-file')
args = parser.parse_args()
results = []

#build the list of requested SSIDs
ssid_list = []
for ssid in args.ssid:
    ssid_list.append(ssid)
if args.ssid_file:
    try:
        ssid_file = open(args.ssid_file, 'r')
        for line in ssid_file:
            ssid_list.append(line.rstrip())
        ssid_file.close()
    except Exception as e:
        exit(format(e))

#try to read and parse input XML file
try:
    tree = ET.parse(args.file[0])
except Exception as e:
    exit(format(e))

#do work, son
root = tree.getroot()

for network in root.findall('wireless-network'):
    try: #cause parsing fails sometimes
        bssid = network.find('BSSID').text
        for ssid in network.findall('SSID'):
            if ssid.find('essid').text is not None:
                #if we didn't ask for this SSID or have only seen one packet from it, don't bother
                if (not ssid_list and int(ssid.find('packets').text) > 1) \
                    or ssid.find('essid').text in ssid_list:
                    results.append('{0}\t{1}'.format(bssid,ssid.find('essid').text.encode("utf8")))
    except:
        pass

if args.output:
    outfile = open(args.output, 'w')
    for result in results:
        outfile.write('{0}\n'.format(result))
    outfile.close()
    print 'Output written to \'{0}\''.format(args.output)
else:
    for result in results:
        print result