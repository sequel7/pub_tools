#!/usr/bin/env python

import xml.etree.ElementTree as et
import argparse

#set up arguments
parser = argparse.ArgumentParser()
parser.add_argument('-s', '--ssid', action='append', default=[],
                    metavar='ssid', help='An SSID to look for, can be used more than once')
parser.add_argument('-S', '--ssid-file', dest='ssid_file', metavar='ssid-file', help='A file with SSIDs to look for')
parser.add_argument("--hidden", help="show undiscovered hidden SSIDs", action="store_true")
parser.add_argument('netxml', nargs='+', help='Kismet netxml file to parse', metavar='netxml')
args = parser.parse_args()
show_hidden = args.hidden
results = {}

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

def parse_xml(netxml):
    #try to read and parse input XML file
    try:
        tree = et.parse(netxml)
    except Exception as e:
        exit(format(e))

    #do work, son
    root = tree.getroot()

    for network in root.findall('wireless-network'):
        try:  # cause parsing fails sometimes
            bssid = network.find('BSSID').text
            for ssid in network.findall('SSID'):
                info = ssid.findtext('info', '')
                ssid_text = ssid.find('essid').text
                if ssid_text:  # sometimes ssid is "\" for no good reason
                    ssid_is_slash = ord(list(ssid_text)[0]) == 92 and len(ssid_text) == 1
                else:
                    ssid_is_slash = False
                if show_hidden and (ssid_text is None or ssid_is_slash):
                    ssid_text = '<hidden>'
                if ssid_text is not None and not ssid_is_slash:
                    #seen more than one packet, or asked for this SSID, or asked to be shown hidden SSIDs
                    if (not ssid_list and int(ssid.find('packets').text) > 1) \
                            or ssid_text in ssid_list \
                            or (show_hidden and ssid_text == '<hidden>' and int(ssid.find('packets').text) > 1):
                        if not results.has_key(bssid) or results[bssid][0] == '<hidden>':
                            results[bssid] = [ssid_text.encode("utf8"), info]
        except Exception as e:
            exit(e)
            pass

for netxml in args.netxml:
    try:
        parse_xml(netxml)
    except Exception as e:
        exit('Error: File could not be parsed: {0}\r\n{1}'.format(netxml, e))


print '{2},{0},{1}'.format('BSSID','SSID','AP')
for result in sorted(results):
    print '{2},{0},{1}'.format(result.lower(), results[result][0], results[result][1])