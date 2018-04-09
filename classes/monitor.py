#
# Copyright (C) 2018  Fernando Arnaboldi
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
import ctypes
import os.path
import shutil
import socket
import subprocess
import sys


try:
	from urllib2 import urlopen         # python 2
	from urllib2 import HTTPError
	from urllib2 import URLError
except ImportError:
	from urllib.request import urlopen  # python 3
	from urllib.error import HTTPError
	from urllib.error import URLError


class Monitor(object):
	"""Checks that everything is looking good before the fuzzer stats, and while the fuzzer operates"""
	def __init__(self, settings):
		"""Execute all the checks within this class to verify that canarys have been properly set up in the testcases"""
		self.settings = settings

	def check_once(self):
		"""Check only once"""
		self.check_canary_references(self.settings['canaryfile'])
		self.check_canary_references("canaryhost")
		self.check_canary_web(self.settings['canaryhost'], self.settings['canaryfile'], self.settings['canaryfileremote'])
		self.check_canary_command(self.settings['canaryexec'], self.settings['canaryexectoken'])
		self.check_ulimit()
		self.check()
		return None

	def check(self):
		"""Check on each loop the canary file and the free space"""
		self.remove_stuff()
		status = self.check_canary_file(self.settings['tmp_dir'] + self.settings['canaryfile'], self.settings['canaryfiletoken'])
		status += self.check_free_space()
		return status

	def remove_stuff(self):
		"""Remove files that may affect the behaviour"""
		# delete specific files
		if sys.platform == "linux2":
			try:
				os.remove(os.getenv("HOME") + '.hhvm.hhbc')  # hhvm may fill up the disk with temp stuff
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
		status = None
		if not isinstance(filename, str):
			self.settings['logger'].error("Filename is not a string")
		elif not isinstance(token, str):
			self.settings['logger'].error("Token is not a string")
		else:
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
				self.settings['logger'].debug("CanaryFile %s not found, creating a new one", str(filename))
				status = self.create_canary_file(filename, token)
		return status

	def create_canary_file(self, filename, token):
		"""Create a text file with a certain token"""
		status = None
		if not isinstance(filename, str):
			self.settings['logger'].error("Filename is not a string")
		elif not isinstance(token, str):
			self.settings['logger'].error("Token is not a string")
		else:
			canary_file = open(filename, 'w')
			canary_file.write(token)
			canary_file.close()
			self.settings['logger'].debug("CanaryFile created")
			status = True
		return status

	def check_canary_web(self, hostname, filename, token):
		"""Check if the hostname exists, that is possible to retrieve the filename and the contents are equal to the token"""
		status = None
		if not isinstance(hostname, str):
			self.settings['logger'].error("Hostname is not a string")
		elif not isinstance(filename, str):
			self.settings['logger'].error("Filename is not a string")
		elif not isinstance(token, str):
			self.settings['logger'].error("Token is not a string")
		else:
			url = "http://" + hostname + "/" + filename + "?monitor"
			try:
				response = urlopen("http://" + hostname + "/" + filename + "?monitor", timeout=5)
				data = response.read().strip()
				if data == token:
					status = True
				else:
					self.settings['logger'].warning("CanaryWeb token mismatch: expected %s and received %s", token, data)
					status = False
			except socket.error:
				self.settings['logger'].warning("CanaryWeb Hostname %s not found", str(hostname))
				status = False
			except HTTPError:
				self.settings['logger'].warning("CanaryWeb Filename %s not found: %s", str(filename), url)
				status = False
			except URLError:
				self.settings['logger'].warning("CanaryWeb may not work, network is unreachable")
				status = False
		return status

	def check_canary_command(self, command, token):
		"""Check that the command can be executed and returns the expected token"""
		stdout = None
		found = None
		try:
			stdout, stderr = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
		except Exception as e:
			self.settings['logger'].warning("CanaryCommand %s not found: %s", str(command), str(e))

		if stdout:
			found = True
			if token not in stdout.strip():
				self.settings['logger'].warning("CanaryCommand token (%s) differs: '%s'", token, str(stdout.strip()))
				found = False
		return found

	def check_canary_references(self, reference):
		"""Check if the reference is on any of the testcases of the database"""
		found = 1
		if self.settings['db'].count_reference(reference) == 0:
			self.settings['logger'].warning("CanaryReferences were not found in the db for the string: %s", str(reference))
			found = 0
		return found

	def check_free_space(self):
		"""Check if the there are more than Xmb free"""
		if sys.platform == "win32":
			free_bytes = ctypes.c_ulong(0)
			ctypes.windll.kernel32.GetDiskFreeSpaceExW(ctypes.c_wchar_p("."), None, None, ctypes.pointer(free_bytes))
			free_mb = free_bytes.value / 1024 / 1024
		else:
			stat = os.statvfs('.')
			free_mb = stat.f_bfree * stat.f_frsize / 1024 / 1024
		if free_mb <= self.settings['lowerlimit']:
			self.settings['logger'].critical("There is not enough space on the device. The current free disk space in gigabytes is: %s", str(stat.f_bfree * stat.f_frsize / 1024 / 1024))
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
				self.settings['logger'].critical("ulimit is too low (%s), you must raise ulimit (`ulimit -n %s`)", str(stdout.strip()), str(minimum))
				sys.exit()
		return 1
