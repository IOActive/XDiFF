import os
import random
#import selenium.webdriver
import string
import subprocess
import sys
import tempfile
from distutils.spawn import find_executable
from execute import Execute

class Fuzzer(object):
	"""Executes fuzzing threads"""
	def __init__(self, settings, ids):
		self.settings = settings
		self.ids = ids

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
					print "Error when trying to append a new process. Try using less parallel threads. Terminating..."
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
				#data = str(arg[len("-fuzzdata="):]).replace("[[test]]", test) #python3
				data = unicode(arg[len("-fuzzdata="):]).replace("[[test]]", test[1].replace("canaryhost", self.settings['canaryhost']).replace("[[softwareid]]", str(piece['softwareid'])).replace("[[randomstring]]", randomstring)) # python2
				input_type = piece['type'][typeid].lower()
				if input_type in ['file', 'url']:
					datafile = tempfile.mkstemp(suffix=piece['suffix'][typeid], prefix=self.settings['tmp_prefix']+str(test[0])+"_", dir=self.settings['tmp_dir'])
					input['data'].append({"data":data, "datafile":datafile})
					if input_type == "file":
						input['execute'].append(datafile[1])
					elif input_type == "url":
						input['execute'].append("http://"+ self.settings['canaryhost'] + "/" + os.path.basename(datafile[1]))
				elif input_type == 'stdin':
					input['stdin'] = data
				else:
					input['execute'].append(data) # cli
				typeid += 1
			else:
				input['execute'].append(arg)
		#for id in range(0, len(input['data'])): # python3
		for id in xrange(0, len(input['data'])): # python2
			#for id2 in range(len(input['data'])): # python3
			for id2 in xrange(0, len(input['data'])): # python2
				input['data'][id]['data'] = input['data'][id]['data'].replace("[[file" + str(id2) + "]]", os.path.basename(input['data'][id2]['datafile'][1]))
				if 'canaryhost' in self.settings:
					input['data'][id]['data'] = input['data'][id]['data'].replace("[[url" + str(id2) + "]]", "http://" + self.settings['canaryhost'] + "/" + os.path.basename(input['data'][id2]['datafile'][1]))
			os.write(input['data'][id]['datafile'][0], input['data'][id]['data'].encode('utf8'))
			os.close(input['data'][id]['datafile'][0])
		return input

	def generate_tests(self, latest_id, limit):
		"""Generate random tests using functions as an input and values as random entry points"""
		if self.settings['generate_tests'] > 5:
			print "Error: option for random tests not available"
			sys.exit()

		values = self.settings['db'].get_values()
		count = 0
		while count < (limit * 100): # add more tests than necessary
			for value in values:
				stdout = [] # where the new random values will be stored
				if self.settings['generate_tests'] in [0, 1, 2, 3]: # radamsa
					if not find_executable("radamsa"):
						print "Error: radamsa not found within PATH"
						sys.exit()
					input_value = tempfile.mkstemp(suffix="File", prefix=self.settings['tmp_prefix']+"mutate_", dir=self.settings['tmp_dir'])
					if self.settings['generate_tests'] in [0, 2]: # add a newline to speed up the generation process
						os.write(input_value[0], value[0]+"\n")
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
				if self.settings['generate_tests'] in [0, 1, 4, 5]: # zzuf
					if not find_executable("zzuf"):
						print "Error: zzuf not found within PATH"
						sys.exit()
					input_value = tempfile.mkstemp(suffix="File", prefix=self.settings['tmp_prefix']+"mutate_", dir=self.settings['tmp_dir'])
					if self.settings['generate_tests'] in [0, 4]: # add a newline to speed up the generation process
						os.write(input_value[0], "\n".join([value[0]]*limit))
						repeat = 1
					else:
						os.write(input_value[0], value[0])
						repeat = limit
					os.close(input_value[0])
					for x in range(0, repeat):
						stdout.append(self.execute_shell("zzuf -r" + str(random.uniform(0.01, 0.03)) + " -s" + str(latest_id+repeat+x) + " <" + input_value[1])) # zzuf -s 1<file, without a space before the '<' sign, causes a crash :)
					os.unlink(input_value[1])
				if self.settings['generate_tests'] in [0, 2, 4]:
					stdout = '\n'.join(str(x) for x in stdout).split('\n')
				for x in range(0, len(stdout)):
					stdout[x] = unicode(stdout[x], errors='ignore')
				functions = self.settings['db'].get_functions()
				# uncomment the next line to crash python :P
				#print "values:",stdout
				count += self.settings['dbaction'].permute(functions, stdout)
		self.settings['logger'].info("Testcases generated: %s" % str(count))

	def execute_shell(self, cmd):
		"""Execute a fuzzer generator within a shell context"""
		p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
		stdout, stderr = p.communicate()
		return stdout

	"""
	def startDriver(self, name):
		Selenium works better than subprocess() for web browsers
		driver = None
		if name == 'Firefox':
			profile = selenium.webdriver.FirefoxProfile()
			driver = selenium.webdriver.Firefox(firefox_profile=profile)
		elif name == 'Chrome':
			driver = selenium.webdriver.Chrome("/Users/fear/Documents/iaaa/javascript/seleniumchromedriverosx")
		elif name == 'Safari':
			driver = selenium.webdriver.Safari()
		else:
			self.settings['logger'].critical("Driver %s not found" % str(name))
		return driver

	def stopDriver(self):
		if there were any selenium drivers started, stop them
		for piece in self.software:
			if "driver" in piece:
				piece["driver"].quit()
	"""
