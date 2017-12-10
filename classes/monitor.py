import ctypes
import os.path
import shutil
import socket
import subprocess
import sys
import urllib2

class Monitor(object):
	"""Checks that everything is looking good before the fuzzer stats, and while the fuzzer operates"""
	def __init__(self, settings):
		"""Execute all the checks within this class to verify that canarys have been properly set up in the testcases"""
		self.settings = settings

	def check_once(self):
		"""Check only once"""
		status = self.check_canary_references(self.settings['canaryfile'])
		status += self.check_canary_references("canaryhost")
		status += self.check_canary_web(self.settings['canaryhost'], self.settings['canaryfile'], self.settings['canaryfileremote'])
		status += self.check_canary_command(self.settings['canaryexec'], self.settings['canaryexectoken'])
		status += self.check_ulimit()
		self.check()
		return None

	def check(self):
		"""Check on each loop the canary file and the free space"""
		self.remove_stuff()
		status  = self.check_canary_file(self.settings['tmp_dir'] + self.settings['canaryfile'], self.settings['canaryfiletoken'])
		status += self.check_free_space()
		return status

	def remove_stuff(self):
		"""Remove files that may affect the behaviour"""
		# delete specific files
		if sys.platform == "linux2":
			try:
				os.remove(os.getenv("HOME") + '.hhvm.hhbc') # hhvm may fill up the disk with temp stuff
			except:
				pass
		# delete all tmp_dir files
		for root, dirs, files in os.walk(self.settings['tmp_dir']):
			for f in files:
				try:
					if os.path.isfile(os.path.join(root, f)):
						os.unlink(os.path.join(root, f))
				except:
					pass
			for d in dirs:
				try:
					if os.path.isdir(os.path.join(root, d)):
						shutil.rmtree(os.path.join(root, d))
				except:
					pass

	def check_canary_file(self, filename, token):
		"""Check if the file exists and its contents are equal to the token"""
		if os.path.isfile(filename):
			try:
				token_file = open(filename, 'r')
			except:
				self.settings['logger'].debug("CanaryFile could not be open, changing its permissions")
				os.chmod(filename, 0o644)
				token_file = open(filename, 'r')
			tmptoken = token_file.read().strip()
			token_file.close()
			if tmptoken == token:
				return 1
			else:
				self.settings['logger'].debug("CanaryFile token differs, creating a new one")
		else:
			self.settings['logger'].debug("CanaryFile " + str(filename) + " not found, creating a new one")
		return self.create_canary_file(filename, token)

	def create_canary_file(self, filename, token):
		"""Create a text file with a certain token"""
		canaryFile = open(filename, 'w')
		canaryFile.write(token)
		canaryFile.close()
		self.settings['logger'].debug("CanaryFile created")
		return 1

	def check_canary_web(self, hostname, filename, token):
		"""Check if the hostname exists, that is possible to retrieve the filename and the contents are equal to the token"""
		url = "http://" + hostname + "/" + filename + "?monitor"
		try:
			response = urllib2.urlopen("http://" + hostname + "/" + filename + "?monitor", timeout=5)
			data = response.read().strip()
			if data == token:
				return 1
			else:
				self.settings['logger'].warning("CanaryWeb token mismatch: expected " + token + " and received " + data)
			return 0
		except socket.error:
			self.settings['logger'].warning("CanaryWeb Hostname " + str(hostname) + " not found")
			return 0
		except urllib2.HTTPError:
			self.settings['logger'].warning("CanaryWeb Filename " + str(filename) + " not found: " + url)
			return 0
		except urllib2.URLError:
			self.settings['logger'].warning("CanaryWeb may not work, network is unreachable")
			return 0

	def check_canary_command(self, command, token):
		"""Check that the command can be executed and returns the expected token"""
		try:
			stdout, stderr = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
		except Exception as e:
			self.settings['logger'].warning("CanaryCommand " + str(command) + " not found")
			return 0

		if token in stdout.strip():
			return 1
		else:
			self.settings['logger'].warning("CanaryCommand token (" + token + ") differs: '"+str(stdout.strip())+"'")
			return 0

	def check_canary_references(self, reference):
		"""Check if the reference is on any of the testcases of the database"""
		if self.settings['db'].count_reference(reference) == 0:
			self.settings['logger'].warning("CanaryReferences were not found for the string: " + str(reference))
			return 0
		else:
			return 1

	#@staticmethod
	def check_free_space(self, lowerlimit=200):
		"""Check if the there are more than Xmb free"""
		if sys.platform == "win32":
			free_bytes = ctypes.c_ulong(0)
			ctypes.windll.kernel32.GetDiskFreeSpaceExW(ctypes.c_wchar_p("."), None, None, ctypes.pointer(free_bytes))
			free_mb = free_bytes.value / 1024 / 1024
		else:
			stat = os.statvfs('.')
			free_mb = stat.f_bfree*stat.f_frsize/1024/1024
		if free_mb <= lowerlimit:
			self.settings['logger'].critical("There is not enough space on the device. The current free disk space in gigabytes is: " + str(stat.f_bfree*stat.f_frsize/1024/1024))
			sys.exit()
		return 1

	def check_ulimit(self):
		"""Check that the command can be executed and returns the expected token"""
		if sys.platform != "win32":
			minimum = 1024
			try:
				stdout, stderr = subprocess.Popen(["ulimit", "-n"], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
			except:
				self.settings['logger'].debug("ulimit check did not work")
				return 0

			if int(stdout.strip()) < minimum:
				self.settings['logger'].critical("ulimit is too low (" + str(stdout.strip()) + "), you must raise ulimit (`ulimit -n " + str(minimum) + "`)")
				sys.exit()
		return 1
