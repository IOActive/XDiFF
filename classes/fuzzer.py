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
import os
import random
import string
import subprocess
import sys
import tempfile
import compat
from distutils.spawn import find_executable
from .execute import Execute


class Fuzzer(object):
	"""Executes fuzzing threads"""
	def __init__(self, settings, ids):
		self.settings = settings
		self.ids = ids

	def chdir_tmp(self):
		"""Change to the temporary directory"""
		status = False
		try:
			os.chdir(self.settings['tmp_dir'])		# it is safer to operate somewhere else
			status = True
		except Exception as e:
			self.settings['logger'].error("It wasn't possible to change to the ram disk directory (%s). Instructions to mount it: %s\nError: %s" % (self.settings['tmp_dir'], self.settings['tmp_dir_howto'], e))
		return status

	def fuzz(self, tests):
		"""Executes something in all the different pieces of software"""
		process = []		# info to be return and saved in the database
		# go through each test
		for test in tests:
			for piece in self.settings['software']:
				input = self.get_input(piece, test)
				try:
					process.append(Execute(self.settings, piece, input))
				except Exception:
					self.settings['logger'].critical("Error when trying to append a new process, try using less parallel threads. Just in case, check also if there are too many processes running in the background.")
					sys.exit()
		for x in range(0, len(process)):
			process[x].join()
		for x in range(0, len(process)):
			process[x] = process[x].get_output()
		# save the network results
		if self.ids:
			for x in range(0, len(self.ids)):
				for z in range(0, len(process)):
					if process[z]['testcaseid'] == self.ids[x][0] and process[z]['softwareid'] == self.ids[x][1]:
						process[z]['network'] = self.ids[x][2]
						if self.ids[x][3] != None:
							process[z]['stdout'] = self.ids[x][3]
						if self.ids[x][4] != None:
							process[z]['elapsed'] = self.ids[x][4]
						if self.ids[x][5] != None:
							process[z]['stderr'] = self.ids[x][5]
						break
			self.ids = []
		self.settings['logger'].debug("Process: %s" % str(process))
		return process

	def get_input(self, piece, test):
		"""Based on how the type, suffix and fuzzdata that were defined in the piece of software,
		create a valid input file, url or as part of the CLI for the test"""
		input = {}
		input['testcaseid'] = test[0]
		input['execute'] = []
		input['data'] = []
		# default values
		data = ""
		typeid = 0
		for arg in piece['execute']:
			if arg.startswith("-fuzzdata="):
				randomstring = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(10))
				data = compat.unicode(arg[len("-fuzzdata="):])
				data = data.replace("[[test]]", test[1])
				data = data.replace("canaryhost", self.settings['canaryhost'])
				data = data.replace("[[softwareid]]", str(piece['softwareid']))
				data = data.replace("[[randomstring]]", randomstring)
				data = data.replace("[[testcaseid]]", str(input['testcaseid']))
				input_type = piece['type'][typeid].lower()
				if input_type in ['file', 'url']:
					if 'suffix' not in piece:
						piece['suffix'] = []
						for suffixid in xrange(0, len(piece['type'])):
							piece['suffix'].append("")
					if 'filename' in piece and piece['filename'][0]:
						fileid = os.open(piece['filename'][typeid], os.O_RDWR|os.O_CREAT)
						datafile = []
						datafile.append(fileid)
						datafile.append(piece['filename'][typeid])
					else:
						datafile = tempfile.mkstemp(suffix=piece['suffix'][typeid], prefix=self.settings['tmp_prefix'] + str(test[0]) + "_", dir=self.settings['tmp_dir'])
					input['data'].append({"data": data, "datafile": datafile})
					if input_type == "file":
						input['execute'].append(datafile[1])
					elif input_type == "url":
						input['execute'].append("http://" + self.settings['canaryhost'] + "/" + os.path.basename(datafile[1]))
				elif input_type == 'stdin':
					input['stdin'] = data
				else:
					input['execute'].append(data)  # cli
				typeid += 1
			else:
				input['execute'].append(arg)
		for id in xrange(0, len(input['data'])):
			for id2 in xrange(0, len(input['data'])):
				input['data'][id]['data'] = input['data'][id]['data'].replace("[[file" + str(id2) + "]]", os.path.basename(input['data'][id2]['datafile'][1]))
				if 'canaryhost' in self.settings:
					input['data'][id]['data'] = input['data'][id]['data'].replace("[[url" + str(id2) + "]]", "http://" + self.settings['canaryhost'] + "/" + os.path.basename(input['data'][id2]['datafile'][1]))
			os.write(input['data'][id]['datafile'][0], input['data'][id]['data'].encode('utf8'))
			os.close(input['data'][id]['datafile'][0])
		return input

	def generate_tests(self, latest_id, limit):
		"""Generate random tests using functions as an input and values as random entry points"""
		if 'generate_tests' not in self.settings:
			self.settings["logger"].error("Generate test option not defined")
		elif self.settings['generate_tests'] > 5 or self.settings['generate_tests'] < 0:
			self.settings["logger"].error("Option for random tests not available")
		elif not isinstance(latest_id, int):
			self.settings["logger"].error("The latest id should be an int")
		elif not isinstance(limit, int):
			self.settings["logger"].error("The limit should be an int")
		else:
			values = self.settings['db'].get_values()
			if not values:
				self.settings["logger"].error("No values detected, you require at least 1 value in the table 'value'. For example: ./xdiff_dbaction.py -d %s -t value -i canaryfile", self.settings['db_file'])
			else:
				functions = self.settings['db'].get_functions()
				if not functions:
					self.settings["logger"].error("No functions detected, you require at least 1 value in the table 'function'. For example: ./xdiff_dbaction.py -d %s -t function -i [[test]]", self.settings['db_file'])
				else:
					self.settings['logger'].info("Testcases being generated")
					count = 0
					while count < (limit * self.settings['generate_multiplier']):  # add more tests than necessary
						for value in values:
							stdout = []  # where the new random values will be stored
							if self.settings['generate_tests'] in [0, 1, 2, 3]:  # radamsa
								if not find_executable("radamsa"):
									self.settings["logger"].error("Radamsa not found within PATH")
									sys.exit()
								input_value = tempfile.mkstemp(suffix="File", prefix=self.settings['tmp_prefix'] + "mutate_", dir=self.settings['tmp_dir'])
								if self.settings['generate_tests'] in [0, 2]:  # add a newline to speed up the generation process
									os.write(input_value[0], value[0] + "\n")
									repeat = 1
									input_count = limit
								else:
									os.write(input_value[0], value[0])
									repeat = limit
									input_count = 1
								os.close(input_value[0])
								for x in range(0, repeat):
									stdout.append(self.execute_shell("radamsa -n " + str(input_count) + " " + input_value[1]))
								os.unlink(input_value[1])
							if self.settings['generate_tests'] in [0, 1, 4, 5]:  # zzuf
								if not find_executable("zzuf"):
									self.settings["logger"].error("Zzuf not found within PATH")
									sys.exit()
								input_value = tempfile.mkstemp(suffix="File", prefix=self.settings['tmp_prefix'] + "mutate_", dir=self.settings['tmp_dir'])
								if self.settings['generate_tests'] in [0, 4]:  # add a newline to speed up the generation process
									os.write(input_value[0], "\n".join([value[0]] * limit))
									repeat = 1
								else:
									os.write(input_value[0], value[0])
									repeat = limit
								os.close(input_value[0])
								for x in range(0, repeat):
									stdout.append(self.execute_shell("zzuf -r" + str(random.uniform(0.01, 0.03)) + " -s" + str(latest_id + repeat + x) + " <" + input_value[1]))  # zzuf -s 1<file, without a space before the '<' sign, causes a crash :)
								os.unlink(input_value[1])
							if self.settings['generate_tests'] in [0, 2, 4]:
								stdout = '\n'.join(str(x) for x in stdout).split('\n')
							for x in range(0, len(stdout)):
								stdout[x] = compat.unicode(stdout[x], errors='ignore')
							# uncommenting the next line may crash python depending on the values :P
							# print "values:",stdout
							count += self.settings['dbaction'].permute(functions, stdout)
					self.settings['logger'].debug("Testcases generated: %s" % str(count))

	def execute_shell(self, cmd):
		"""Execute a fuzzer generator within a shell context"""
		p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
		stdout, stderr = p.communicate()
		return stdout
