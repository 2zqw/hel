import requests, re, uuid, time, threading, os, socket, random
from string import ascii_lowercase, digits, ascii_uppercase
from random import choice, choices
from tkinter import Tk, messagebox
from os import system
from threading import Thread
from requests import get
from os import kill, getpid
from signal import SIGTERM
from urllib3 import PoolManager
run = input(" - Press Enter To Start")
if run == "":
	try:
		settings = open('Settings.txt', 'r').read().splitlines()
	except:
		input(' - There Is No File Named Settings.txt')
		exit()
	window = Tk()
	get = requests.get
	post = requests.post
	req = requests.session()
	uid4 = uuid.uuid4()
	csrf2 = ''
	device_id = ''.join(choices(ascii_lowercase + digits, k=16))
	Clear = lambda: system("cls")
	system('mode 75,23')
	os.system('title Programmed By @mzo9')


	class Moha_V3:
		def __init__(self):
			print("""
			
                                                        
     __    _     _   _       _            _____             
    |  |  |_|___| |_| |_ ___|_|___ ___   |   __|___ ___ ___ 
    |  |__| | . |   |  _|   | |   | . |  |   __|  _| -_| -_|
    |_____|_|_  |_|_|_| |_|_|_|_|_|_  |  |__|  |_| |___|___|
            |___|                 |___|                     
                                                            
                                                            
                                                    
			""")
			self.lock = threading.Lock()
			self.webhook_url = settings[1].split(':')[1]
			self.discord_message = settings[2].split(':')[1]
			self.messagebox_title = settings[3].split(':')[1]
			self.messagebox_message = settings[4].split(':')[1]
			self.choose = input(' - Login With\n\n [1] Normal Login [2] Session-id (Api): ')
			if self.choose == '1':
				self.username = input('\n - Enter Username : ')
				self.password = input('\n - Enter Password : ')
			elif self.choose == '2':
					self.sid = input('\n - Enter Api Session : ')
					try:
						email_text = req.get("https://i.instagram.com/api/v1/accounts/current_user/?edit=true",
											 headers={
												 'User-Agent': 'Instagram 113.0.0.39.122 Android (24/5.0; 515dpi; 1440x2416; huawei/google; Nexus 6P; angler; angler; en_US)',
												 "Accept": "*/*",
												 "Cookie": f"sessionid={self.sid}",
												 "Accept-Encoding": "gzip, deflate",
												 "Accept-Language": "en-US",
												 "X-IG-Capabilities": "3brTvw==",
												 "X-IG-Connection-Type": "WIFI",
												 "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
												 'Host': 'i.instagram.com'})
						print(email_text.text)
						self.email = re.search('[\w\.-]+@[\w\.-]+', email_text.text).group()
						print(self.email)
					except Exception as ex:
						print(ex)
			else:
				input(' - Error, Press Enter To Try Again.')
				Clear()
				Moha_V3()
			self.target = input('\n - Enter Target : ')
			self.th = int(input('\n - Enter Thread : '))
			self.loop = int(input('\n - Enter Loop : '))
			self.req = PoolManager()
			self.g = 0
			self.e = 0
			self.us = ''.join(random.choice('1234567890qwertyuiopasdfghjklzxcvbnm') for i in range(8))
			self.threads = []
			if self.choose == '2':
				self.checkblock()
			elif self.choose == '1':
				self.api_login()

		def api_login(self):
			global csrf2
			try:
				username = self.username
				password = self.password
				uplogin = 'https://i.instagram.com/api/v1/accounts/login/'
				upheaders = {}
				upheaders[
					"User-Agent"] = 'Instagram 135.0.0.00.000 Android (25/7.1.2; 192dpi; 720x1280; google; G011A; G011A; intel; en_US; 289692181)'
				upheaders["Connection"] = 'keep-alive'
				updata = {}
				updata["uuid"] = uid4
				updata["password"] = password
				updata["username"] = username
				updata["device_id"] = device_id
				updata["from_reg"] = 'false'
				updata["_csrftoken"] = 'missing'
				updata["login_attempt_countn"] = '0'
				upreq = post(url=uplogin, headers=upheaders, data=updata)

				if "challenge_required" in upreq.text:
					print(' - Challenge Required [!]')
					loggc = upreq.cookies
					info = get(url=f"https://i.instagram.com/api/v1{upreq.json()['challenge']['api_path']}",
							   headers=upheaders, cookies=loggc)
					if "step_data" not in info.text:
						print(f' - {info.text}')
					if "phone_number" in info.json()["step_data"] and "email" in info.json()["step_data"]:
						print(
							f'[0] Phone_Number: ' + f'{info.json()["step_data"]["phone_number"]} \n' + '[1] Email: ' + F'{info.json()["step_data"]["email"]}')
					elif "phone_number" in info.json()["step_data"]:
						print(f'[0] Phone_Number: ' + f'{info.json()["step_data"]["phone_number"]}')
					elif "email" in info.json()["step_data"]:
						print(f'[1] Email: ' + f'{info.json()["step_data"]["email"]}')
					else:
						print(f'[!] {info.json}')
					print(' - choose a number: ', end='')
					choice = input()
					secure_data = {'choice': str(choice), 'device_id': f"android-{uid4}", 'guid': uid4,
								   '_csrftoken': 'massing'}
					send_choice = post(url=f"https://i.instagram.com/api/v1{upreq.json()['challenge']['api_path']}",
									   headers=upheaders, data=secure_data, cookies=loggc)
					if "step_data" not in send_choice.text:
						print(f'[!] {send_choice.text}')
					elif "step_data" in send_choice.text:
						def Codeeror():
							global csrf2
							print(f' - code sent to: {send_choice.json()["step_data"]["contact_point"]}')
							print(' - enter the code: ', end='')
							code = input()
							code_data = {
								'security_code': str(code),
								'device_id': f"android-{uid4}",
								'guid': uid4,
								'_csrftoken': 'massing'
							}
							send_code = requests.post(
								url=f"https://i.instagram.com/api/v1{upreq.json()['challenge']['api_path']}",
								headers=upheaders, data=code_data, cookies=loggc)
							if "logged_in_user" in send_code.text:
								print(' - Logged In ')
								logc = send_code.cookies
								self.sid = logc['sessionid']
								print(self.sid)
								email_text = req.get("https://i.instagram.com/api/v1/accounts/current_user/?edit=true",
													 headers={
														 'User-Agent': 'Instagram 113.0.0.39.122 Android (24/5.0; 515dpi; 1440x2416; huawei/google; Nexus 6P; angler; angler; en_US)',
														 "Accept": "*/*",
														 "Cookie": f"sessionid={self.sid}",
														 "Accept-Encoding": "gzip, deflate",
														 "Accept-Language": "en-US",
														 "X-IG-Capabilities": "3brTvw==",
														 "X-IG-Connection-Type": "WIFI",
														 "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
														 'Host': 'i.instagram.com'})
								self.email = re.search('[\w\.-]+@[\w\.-]+', email_text.text).group()
								with open(f'{username}.txt', 'a') as addo:
									addo.write(f'Session-id:{self.sid}')
								csrf2 = logc['csrftoken']
								do_you = input(' - Do You Want To Check The Account? [Y/N] : ').lower()
								if do_you == 'y':
									self.checkblock()
								elif do_you == 'n':
									messagebox._show('Ready?', f'Target : {self.target}\nThread : {self.thread}')
									window.destroy()
									self.thread_base()
							elif "Please check the code we sent you and try again." in send_code.text:
								print("[?] you entered wrong code , try again")
								self.api_login()
							elif "This field is required." in send_code.text:
								print("[?] Enter the code!")
								return Codeeror()
							else:
								print(f'[?] {send_code.text}')
								return Codeeror()

						Codeeror()
				elif "logged_in_user" in upreq.text:
					print(' - Logged In ')
					logc = upreq.cookies
					self.sid = logc['sessionid']
					print(self.sid)
					email_text = req.get("https://i.instagram.com/api/v1/accounts/current_user/?edit=true",
										 headers={
											 'User-Agent': 'Instagram 113.0.0.39.122 Android (24/5.0; 515dpi; 1440x2416; huawei/google; Nexus 6P; angler; angler; en_US)',
											 "Accept": "*/*",
											 "Cookie": f"sessionid={self.sid}",
											 "Accept-Encoding": "gzip, deflate",
											 "Accept-Language": "en-US",
											 "X-IG-Capabilities": "3brTvw==",
											 "X-IG-Connection-Type": "WIFI",
											 "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
											 'Host': 'i.instagram.com'})
					self.email = re.search('[\w\.-]+@[\w\.-]+', email_text.text).group()
					csrf2 = logc['csrftoken']
					with open(f'{username}.txt', 'a') as addo:
						addo.write(f'Session-id:{self.sid}')
					do_you = input(' - Do You Want To Check The Account? [Y/N] : ').lower()
					if do_you == 'y':
						self.checkblock()
					elif do_you == 'n':
						messagebox._show('Ready?', f'Target : {self.target}')
						window.destroy()
						self.thread_base()
					pass
				elif "Please check your username and try again." in upreq.text:
					print("\n[?] username not found , try again\n")
				elif "The password you entered is incorrect. Please try again." in upreq.text:
					print("\n[?] check your password and try again\n")
				elif 'two_factor_required":true' in upreq.text:
					print("\n[!] two factor authentication is enabled\n")
				elif 'Please wait a few minutes before you try again.' in upreq.text:
					print("\n[!] your ip is blocked from login\n")
				elif "missing_parameters" in upreq.text:
					print("\n[?] error missing parameters , try again\n")
				else:
					print(f'\n[?] {upreq.text}')
			except:
				pass
		def api_swap_edit(self):
			for i in range(70):
				try:
					swap_req_edit = self.req.request('POST', 'https://i.instagram.com/api/v1/accounts/edit_profile/', headers={'Connection': 'close','Cookie': f'sessionid={self.sid}','user-agent': 'Instagram 113.0.0.39.122 Android (24/5.0; 515dpi; 1440x2416; huawei/google; Nexus 6P; angler; angler; en_US)'}, fields={"biography": ' - There Is One King In The Arena ',
												   'email': self.email, 'username': self.target, 'phone_number': ''})
					if swap_req_edit.status == 400:
						self.g += 1
					elif swap_req_edit.status == 429:
						self.e += 1
					elif swap_req_edit.status == 200:
						self.lock.acquire()
						self.send_discord()
						self.lock.release()
				except:
					pass

		def api_swap_set(self):
			for i in range(100):
				try:
					swap_req_set = self.req.request('POST', 'https://i.instagram.com/api/v1/accounts/set_username/', fields={'username': self.target}, headers={'Connection': 'close','Cookie': f'sessionid={self.sid}','user-agent': 'Instagram 113.0.0.39.122 Android (24/5.0; 515dpi; 1440x2416; huawei/google; Nexus 6P; angler; angler; en_US)'})
					if swap_req_set.status == 400:
						self.g += 1
					elif swap_req_set.status == 429:
						Thread(target=self.api_swap_edit).start()
					elif swap_req_set.status == 200:
						self.lock.acquire()
						self.send_discord()
						self.lock.release()
				except:
					pass

		def checkblock(self):
			print(' - Checking Started!')
			s1 = req.post('https://i.instagram.com/api/v1/accounts/set_username/',
						  data={'username': 'check.' + self.us},
						  headers={'Accept': '*/*', 'Accept-Language': 'en-US',
								   'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
								   'Cookie': f'sessionid={self.sid}',
								   'user-agent': 'Instagram 113.0.0.39.122 Android (24/5.0; 515dpi; 1440x2416; huawei/google; Nexus 6P; angler; angler; en_US)'})
			s2 = req.post('https://i.instagram.com/api/v1/accounts/edit_profile/',
						  data={"biography": '', 'email': self.email,
								'username': 'check.' + self.us, 'phone_number': ''},
						  headers={'Accept': '*/*', 'Accept-Language': 'en-US',
								   'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
								   'Cookie': f'sessionid={self.sid}',
								   'user-agent': 'Instagram 113.0.0.39.122 Android (24/5.0; 515dpi; 1440x2416; huawei/google; Nexus 6P; angler; angler; en_US)'})
			if s1.status_code == 403:
				print(' - Account Blocked : 1')
			if s2.status_code == 403:
				print(' - Account Blocked : 2')
			else:
				print(' - Your Account is Not Blocked.')
			co = input(' - Do You Want To Continue? [Y/N] : ').lower()
			if co == 'y':
				messagebox._show('Ready?', f'Target : {self.target}')
				window.destroy()
				self.thread_base()
			elif co == 'n':
				input(' - Press Enter To Exit.')
				exit()
			else:
				print(' - an error occurred.')
				input(' - Press Enter To Exit.')
				exit()

		def send_discord(self):
			global g
			if self.target.__len__() >= 4:
				data = {}
				data["embeds"] = [{"description": f"\n** Fast As Lightning\n Swapped : @{self.target} **",
								   "color": choice([0x3498db, 0x2ecc71, 0xe91e63, 0xf1c40f, 0xe74c3c, 0xe67e22]),
								   "footer": {"text": 'Coded By @11221130'},
								   "thumbnail": {
									   "url": 'https://c.tenor.com/jDULGzcZvwoAAAAd/bring-me-thanos-thor.gif'},
								   "author": {"name": "Lightning Free"}}]
				try:
					post('url', json=data)

				except:
					pass
			if 'https' in self.webhook_url or 'http' in self.webhook_url:
				data1 = {}
				data1["embeds"] = [{"description": f"\n** {self.discord_message} : @{self.target} **",
								   "color": choice([0x3498db, 0x2ecc71, 0xe91e63, 0xf1c40f, 0xe74c3c, 0xe67e22]),
								   "footer": {"text": 'Coded By @11221130'},
								   "thumbnail": {
									   "url": 'https://c.tenor.com/jDULGzcZvwoAAAAd/bring-me-thanos-thor.gif'},
								   "author": {"name": "Lightning Free"}}]
				try:
					post(self.webhook_url, json=data1)
					self.messagebox()
				except:
					pass

		def messagebox(self):
			global g
			try:
				messagebox._show(self.messagebox_title, f'{self.messagebox_message} -> {self.target}\nAt : {self.g}')
			except:
				pass
			kill(getpid(), SIGTERM)

		def counter(self):
			while 1:
				time.sleep(0.1)
				print(f'\r GR / [{self.g}]  ER / [{self.e}]', end='')

		def generating_threads(self):

			[
				[self.threads.append(Thread(target=self.api_swap_set, daemon=True))
					for _ in range(self.th)]
				for _ in range(self.loop)
			]

		def thread_base(self):
			self.generating_threads()
			Thread(target=self.counter).start()

			for threads_waiting in self.threads:
				threads_waiting.start()


	Moha_V3()
