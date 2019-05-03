import json
import bluetooth
from masai.attack.wep import AttackWEP
from masai.attack.wpa import AttackWPA
from masai.attack.scandevice import ScanDevice
from masai.attack.portassessment import PortAssessment
from masai.attack.portattack import PortAttack
from masai.attack.bluetoothattack import BluetoothAttack
from masai.model.router import Router
from masai.model.result import Result
from masai.model.interruptresult import InterruptResult
from masai.config import Configuration
from masai.tools.networkmanager import WifiConnectionManager
from masai.utils.process import Process
from masai.utils.jobthread import JobThread


class StaticVar:
	ROUTER_TYPE_WEP = 'WEP'
	ROUTER_TYPE_WPA = 'WPA'
	ROUTER_TYPE_NO_SECURITY = '--'
	UUID = "94f39d29-7d6d-437d-973b-fba39e49d4ee"
	SERVER_NAME = 'MASaiBox'

class MasaiServer(object):
	'''
		RfcommServer class is the main class to handle the input and output from android using bluetooth
        It received the input from user and create another process to handle the long job
        It also received the output from the another process by callback method
	'''

	def __init__(self):
		self.running_job_thread = None
		self.waiting_job_threads = []
		self.client_sock = None

	def run(self):
		'''
			Run the server
		'''
		self.server_sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
		self.server_sock.bind(("", bluetooth.PORT_ANY))
		self.server_sock.listen(1)
		self.port = self.server_sock.getsockname()[1]

		bluetooth.advertise_service(self.server_sock, StaticVar.SERVER_NAME,
									service_id = StaticVar.UUID,
									service_classes = [StaticVar.UUID, bluetooth.SERIAL_PORT_CLASS],
									profiles = [bluetooth.SERIAL_PORT_PROFILE], 
									)
		
		wifi_connection_manager = WifiConnectionManager()
		Process.call('bluetoothctl discoverable on')
		
		Configuration.initialize(False)
		Configuration.ignore_old_handshakes = True

		while True:
			self.client_sock = None
			self.remove_all_waiting_thread()
			self.running_job_thread = None
			job_thread = self.init_job_thread(target=wifi_connection_manager.disconnect_wifi)
			self.start_job_thread(job_thread=job_thread)
			print("Waiting for connection on RFCOMM channel %d" % self.port)
			self.client_sock, self.client_info = self.server_sock.accept()
			print("Accepted connection from ", self.client_info)

			long_data = ''
			try:
				while True:
					data = self.client_sock.recv(1024)
					if len(data) == 0: break
					data = data.decode('utf-8')
					print("received [%s]" % data)
					if '|' not in data:
						long_data += data
					else:
						if(len(data)) != 1:
							data = data.replace("|", "")
							long_data += data

						data_json = json.loads(long_data)
						data_command = data_json['command']
						data_payload = data_json['payload']
						data_activity_id = None
						job_thread = None
						if 'activityId' in data_json:
							data_activity_id = data_json['activityId']

						if data_command == 'wifiScan':
							job_thread = self.init_job_thread(target=wifi_connection_manager.scan_wifi, name="wifiScan")
						elif data_command == 'wifiCracking':
							target_router = MasaiServer.to_router_from_dict(data_payload)
							job_thread = self.init_job_thread(target=MasaiServer.start_router_attack, kwargs={'target_router': target_router}, name="wifiCracking", activity_id=data_activity_id)
						elif data_command == 'wifiConnect':
							data_password = data_payload['password']
							data_router = data_payload['router']
							target_router = MasaiServer.to_router_from_dict(data_router)
							job_thread = self.init_job_thread(target=wifi_connection_manager.connect_wifi, kwargs={'target_router':target_router, 'password': data_password}, name="wifiConnect")
						elif data_command == 'wifiDisconnect':
							job_thread = self.init_job_thread(target=wifi_connection_manager.disconnect_wifi, name="wifiDisconnect")
						elif data_command == 'deviceScan':
							scan_device = ScanDevice(wifi_connection_manager)
							job_thread = self.init_job_thread(target=scan_device.run, name="deviceScan",activity_id=data_activity_id)
						elif data_command == 'deviceAssess':
							port_assessment = PortAssessment(MasaiServer.to_host_from_dict(data_payload))
							job_thread = self.init_job_thread(target=port_assessment.run, name="deviceAssess", activity_id=data_activity_id)
						elif data_command == 'devicePortAttack':
							host = data_payload['host']
							target_service = data_payload['targetService']
							port_attack = PortAttack(MasaiServer.to_host_from_dict(host), target_service)
							job_thread = self.init_job_thread(target=port_attack.run, name="devicePortAttack", activity_id=data_activity_id)
						elif data_command == 'bluetoothAttack':
							target_device = data_payload['target']
							bluetooth_attack = BluetoothAttack(MasaiServer.to_bluetooth_device_from_dict(target_device))
							job_thread = self.init_job_thread(target=bluetooth_attack.run, name="bluetoothAttack", activity_id=data_activity_id)						
						elif data_command == 'interrupt':
							self.send_interrupt_signal_to_running_thread()
							result = InterruptResult()
							result.set_result()
							self.client_sock.send(result.to_json_str())
							self.client_sock.send("|")
						elif data_command == 'checkProcess':
							result = InterruptResult()
							if(self.check_running_thread_status()):
								result.set_result(status='up')
							else:
								result.set_result(status='down')
							self.client_sock.send(result.to_json_str())
							self.client_sock.send("|")
						self.start_job_thread(job_thread=job_thread)
						long_data = ''
			except IOError:
				print('Disconnected from master')
				self.client_sock = None
				self.remove_all_waiting_thread()
				self.send_interrupt_signal_to_running_thread()
				print(self.check_running_thread_status())
				self.running_job_thread = None
				pass

		self.client_sock.close()
		self.server_sock.close()
		print("all done")

	def init_job_thread(self, target=None, name=None, args=(), kwargs={}, daemon=None, activity_id=None):
		job_thread = JobThread(parent=self, target=target, name=name, args=args, kwargs=kwargs, daemon=daemon)
		job_thread.activity_id = activity_id
		return job_thread

	def start_job_thread(self, job_thread=None):
		print('start job thread if any')
		immediate_job_thread_run = ['wifiScan', 'wifiConnect', 'wifiDisconnect']
		if job_thread is not None:
			self.waiting_job_threads.append(job_thread)
			if job_thread.name in immediate_job_thread_run:
				self.waiting_job_threads.pop()
				self.running_job_thread = job_thread
				self.running_job_thread.start()

		if self.running_job_thread is None:
			try:
				self.running_job_thread = self.waiting_job_threads.pop(0)
				self.running_job_thread.start()
			except IndexError:
				print('no job thread left in queue, cannot start job thread')
		else:
			print('There is a running jobthread, waiting for current jobthread is finished')
	
	def callback(self, thread, result:Result):
		'''
			This callback method will get the result from working thread and output as json.
			The format is as follows:
			{
				'resultType': String e.g. 'wifiScan', 'wifiConnect', 'wifiCracking'
				'payload': JsonObject of that result type
			}
		'''
		print('Scanner receive the notification (callback) from thread id %d (name: %s)' % (thread.ident, thread.name))
		if self.client_sock:
			if result:
				print(result.to_json_str())
				self.client_sock.send(result.to_json_str())
			else:
				error = {'resultType': 'error', 'payload': None}
				self.client_sock.send(json.dumps(error))
			self.client_sock.send('|')
		self.running_job_thread = None
		print('result message sent, starting a job in queue if any.')
		self.start_job_thread()


	def send_interrupt_signal_to_running_thread(self):
		if self.running_job_thread and self.running_job_thread.is_alive():
			# signal.pthread_kill(self.child_thread.ident, )
			self.running_job_thread.terminate()

	def check_running_thread_status(self):
		status = False
		# if len(self.running_job_threads) == 0:
		# 	print('No running job thread')
		# 	return status
		if self.running_job_thread:
			status = self.running_job_thread.is_alive()
			print('Thread %d is' % self.running_job_thread.ident, status)
		return status
	
	def remove_all_waiting_thread(self):
		self.waiting_job_threads = []

	@staticmethod
	def to_router_from_dict(router_dict):
		'''
			Parameters
				dict - router_dict: a dict get from json received from masai box
			Return
				Router: a router object
		'''
		return Router(router_dict)

	@staticmethod
	def to_host_from_dict(host_dict):
		from masai.model.device import Host
		return Host.get_host_from_json(host_dict)

	@staticmethod
	def to_bluetooth_device_from_dict(bluetooth_device_dict):
		from masai.model.bluetoothdevice import BluetoothDevice
		return BluetoothDevice.get_bluetooth_device_from_json(bluetooth_device_dict)

	@staticmethod
	def start_router_attack(target_router):
		'''
			Parameters
				Router - target_router: a router object to be cracked
			Return
				CrackResult: a CrackResult object
		'''
		
		Configuration.initialize(True)
		Configuration.get_monitor_mode_interface()
		attack = None
		print(target_router.encryption)
		if target_router.encryption == StaticVar.ROUTER_TYPE_WEP:
			attack = MyAttackWep(target_router)
		elif target_router.encryption == StaticVar.ROUTER_TYPE_WPA:
			# Configuration.wordlist = './wordlist.txt'
			attack = AttackWPA(target_router)
		elif target_router.encryption == StaticVar.ROUTER_TYPE_NO_SECURITY:
			attack = None
		if attack is not None:
			return attack.run()
		return None

if __name__ == "__main__":
	masai_server = MasaiServer()
	masai_server.run()