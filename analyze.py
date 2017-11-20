#!/usr/bin/env python
import datetime
import getopt
import getpass
import os
#import profile
import re
import sys
import time
import classes.settings
from classes.dump import Dump

MAX = 999999999 # ridiculous high number to get all the occurrences of a function

class Analyze(object):
	"""Analyzes the fuzzing information for abnormal behaviors"""
	def __init__(self, settings):
		reload(sys)
		sys.setdefaultencoding('utf8')
		self.settings = settings
		self.settings['output_width'] = 130
		self.settings['output_file'] = settings['db_file'] + "." + settings['output_type']
		self.settings['testcase_limit'] = 100
		self.dump = Dump(self.settings)
		self.settings['tmp_dir'] = "ramdisk" # by using this, it will work on multiple directories (ie, /Volumes/ramdisk, /mnt/ramdisk, etc)

		self.count_results = None

	def dump_results(self, method, toplimit, extra):
		"""Prints the output of an internal method"""
		try:
			method_to_call = getattr(self, method)
		except:
			print "Error: method should be a valid local method name\n"
			help()
		start_time = time.time()
		if method != "report":
			self.dump.set_toggle_table(False)
		self.settings['logger'].info("Dumping: database %s - method %s - output %s" % (self.settings['db_file'], method, self.settings['output_type']))
		self.dump.pre_general(self.settings['output_type'])

		if extra:
			try:
				method_to_call(self.settings['output_type'], toplimit, extra)
			except Exception as e:
				print "Error executing the method: %s" % e
				return
		else:
			try:
				method_to_call(self.settings['output_type'], toplimit)
			except Exception as e:
				print "Error executing the method: %s" % e
				return

		self.dump.post_general(self.settings['output_type'])
		size = ""
		if 'output_file' in self.settings:
			size = ", output file: " + self.settings['output_file'] + " (" + str(int(os.stat(self.settings['output_file']).st_size/1024)) + " kb)"
		finish_time = time.time() - start_time
		self.settings['logger'].info("Time elapsed %s seconds%s" % (str(int(finish_time)), size))

	def report(self, output, toplimit):
		"""Print several functions in the form of a report (useful for HTML)"""
		#self.settings['db'].set_software(["2"])
		#self.settings['db'].set_software(["9", "10"])

		#self.list_summary(output, toplimit) # informational
		self.list_software(output, MAX)

		#self.analyze_elapsed(output, toplimit) # informational
		self.list_results(output, toplimit)

		#self.analyze_top_elapsed_killed(output, toplimit) # informational
		#self.analyze_top_elapsed_not_killed(output, toplimit) # informational

		self.analyze_valgrind(output, toplimit)
		self.analyze_username_disclosure(output, toplimit, username="root")
		self.analyze_username_disclosure(output, toplimit, username=getpass.getuser())
		self.analyze_canary_token_file(output, toplimit)
		self.analyze_canary_token_code(output, toplimit)
		self.analyze_remote_connection(output, toplimit)
		self.analyze_canary_token_command(output, toplimit)
		self.analyze_canary_file(output, toplimit)

		#self.analyze_killed_differences(output, toplimit) # informational

		self.analyze_return_code(output, toplimit)
		self.analyze_specific_return_code(output, toplimit)
		self.analyze_return_code_differences(output, toplimit)
		self.analyze_return_code_same_software_differences(output, toplimit)

		self.analyze_output_messages(output, toplimit, 'stderr')
		self.analyze_output_messages(output, toplimit, 'stdout')
		#self.analyze_same_software(output, toplimit) # low_risk
		self.analyze_stdout(output, toplimit)
		#self.analyze_same_stdout(output, toplimit) # low_risk

		#self.analyze_file_disclosure(output, toplimit) # low_risk
		#self.analyze_file_disclosure_without_path(output, toplimit) # low_risk
		#self.analyze_path_disclosure(output, toplimit) # low_risk
		#self.analyze_path_disclosure_without_file(output, toplimit) # low_risk

	def list_summary(self, output, toplimit):
		"""Print an quantitative information summary using all the analytic functions from this class"""
		title = "Summary for " + self.settings['db_file']
		columns = ["Information", "Amount"]
		if output:
			self.settings['logger'].info(title)

		rows = []

		results = self.list_software(None, MAX)
		rows.append([["Pieces of Software", str(results)]])
		if self.count_results is None:
			self.count_results = self.settings['db'].count_results(0, None)
		rows.append([["Amount of Testcases", str(self.count_results)]])
		rows.append([["Output Top Limit", str(toplimit)]])

		results = self.analyze_valgrind(None, MAX)
		rows.append([["Valgrind References Found", str(results)]])
		results = self.analyze_username_disclosure(None, MAX, "root")
		rows.append([["Username 'root' Disclosure", str(results)]])
		results = self.analyze_username_disclosure(None, MAX, getpass.getuser())
		rows.append([["Username '" + getpass.getuser() + "' Disclosure", str(results)]])
		results = self.analyze_canary_token_file(None, MAX)
		rows.append([["Canary Token File Found", str(results)]])
		results = self.analyze_canary_token_code(None, MAX)
		rows.append([["Canary Token Code Found", str(results)]])
		results = self.analyze_canary_token_command(None, MAX)
		rows.append([["Canary Token Command Found", str(results)]])
		results = self.analyze_canary_file(None, MAX)
		rows.append([["Canary File Found", str(results)]])
		results = self.analyze_top_elapsed_killed(None, MAX)
		rows.append([["Testcases Killed", str(results)]])
		results = self.analyze_top_elapsed_not_killed(None, MAX)
		rows.append([["Testcases not Killed", str(results)]])
		results = self.analyze_killed_differences(None, MAX)
		rows.append([["Software Killed and Not Killed", str(results)]])
		results = self.analyze_return_code(None, MAX)
		rows.append([["Return Code", str(results)]])
		results = self.analyze_return_code_differences(None, MAX)
		rows.append([["Return Code Differences", str(results)]])
		results = self.analyze_return_code_same_software_differences(None, MAX)
		rows.append([["Return Code Same Software Differences", str(results)]])
		results = self.analyze_same_software(None, MAX)
		rows.append([["Same Software having a Different Output", str(results)]])
		results = self.analyze_stdout(None, MAX)
		rows.append([["Different Stderr Messages", str(results)]])
		results = self.analyze_output_messages(None, MAX, 'stderr')
		rows.append([["Different Stdout Messages", str(results)]])
		results = self.analyze_output_messages(None, MAX, 'stdout')
		rows.append([["Stdout for Different Results", str(results)]])
		results = self.analyze_same_stdout(None, MAX)
		rows.append([["Testcases that Produce the Same Stdout", str(results)]])
		results = self.analyze_file_disclosure(None, MAX)
		rows.append([["Temp File Disclosure", str(results)]])
		results = self.analyze_file_disclosure_without_path(None, MAX)
		rows.append([["Temp File Disclosure (without path)", str(results)]])
		results = self.analyze_path_disclosure(None, MAX)
		rows.append([["Path Disclosure", str(results)]])
		results = self.analyze_path_disclosure_without_file(None, MAX)
		rows.append([["Path Disclosure (without temp file)", str(results)]])
		results = self.analyze_elapsed(None, MAX)
		results = datetime.timedelta(seconds=round(results, 0))
		rows.append([["Total Time Elapsed", str(results)]])

		self.dump.general(output, title, columns, rows)

	def list_software(self, output, toplimit):
		"""Print the list of [active] software used with testcases from the database"""
		title = "List Software Tested - list_software "
		columns = ["ID", "Software", "Type", "OS"]
		if output:
			self.settings['logger'].info(title)

		rows = []
		results = self.settings['db'].list_software()
		for result in results:
			if toplimit is not None and len(rows) >= toplimit:
				break
			rows.append([result])

		self.dump.general(output, title, columns, rows)
		return len(rows)

	def list_results(self, output, toplimit):
		"""Print the fuzzing results: valuable to see how the software worked with the testcases defined, without using any constrains"""
		lowerlimit = 0
		title = "Analyze the Testcase Results from " + str(int(lowerlimit)) + " to " + str(lowerlimit + toplimit) + " - list_results"
		columns = ["Testcase", "Software", "Type", "OS", "Stdout", "Stderr", "Kill"]
		if output:
			self.settings['logger'].info(title)

		total = 0
		rows = []
		testcase = None
		tmpoutput = []
		results = self.settings['db'].list_results(lowerlimit, toplimit*self.list_software(None, MAX))
		for result in results:
			if toplimit is not None and len(rows) >= toplimit:
				break
			if testcase is None:
				testcase = result[0]
			if testcase != result[0]:
				testcase = result[0]
				rows.append(tmpoutput)
				tmpoutput = []
				total += 1
			tmpoutput.append((result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4], result[5], result[6]))
		if len(rows) < toplimit and tmpoutput:
			rows.append(tmpoutput)

		self.dump.general(output, title, columns, rows)
		return total

	def analyze_valgrind(self, output, toplimit):
		"""Find Valgrind references in case it was used"""
		title = "Analyze Valgrind Output - analyze_valgrind"
		columns = ["Testcase", "Software", "Type", "OS", "Stdout", "Stderr", "Return Code"]
		if output:
			self.settings['logger'].info(title)

		rows = []
		results = self.settings['db'].analyze_string_disclosure("== ",)
		for result in results:
			if toplimit is not None and len(rows) >= toplimit:
				break
			if result[5][:10].count('=') == 4: # Valgrind outputs can be detected because they have 4 equal signs in the first 10 characters
				rows.append([(result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4], result[5], result[6])])
		self.dump.general(output, title, columns, rows)
		return len(rows)

	def list_killed_results(self, output, toplimit):
		"""Print the killed fuzzing results"""
		title = "Analyze the Killed Testcase Results - list_killed_results"

		columns = ["Testcase", "Software", "Type", "OS", "Stdout", "Stderr", "Kill"]
		if output:
			self.settings['logger'].info(title)

		total = 0
		rows = []
		testcase = None
		tmpoutput = []
		results = self.settings['db'].list_killed_results()
		for result in results:
			if toplimit is not None and len(rows) >= toplimit:
				break
			if testcase is None:
				testcase = result[0]
			if testcase != result[0]:
				testcase = result[0]
				rows.append(tmpoutput)
				tmpoutput = []
				total += 1
			tmpoutput.append((result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4][:500], result[5][:500], result[6]))
		if len(rows) < toplimit and tmpoutput:
			rows.append(tmpoutput)

		self.dump.general(output, title, columns, rows)
		return total

	def analyze_return_code(self, output, toplimit):
		"""Get the different return codes for each piece of software"""
		title = "Analyze Different Return Codes per Software - analyze_return_code"
		columns = ["Software", "Type", "OS", "Return Code", "Amount"]
		if output:
			self.settings['logger'].info(title)

		rows = []
		results = self.settings['db'].list_return_code_per_software()
		for result in results:
			if toplimit is not None and len(rows) >= toplimit:
				break
			rows.append([(result[0], result[1], result[2], result[3], result[4])])

		self.dump.general(output, title, columns, rows)
		return len(rows)

	def analyze_specific_return_code(self, output, toplimit):
		"""Find specific return codes"""
		#returncodes = ["22", "-6", "-11", "-15"]
		returncodes = ["-6", "-9", "-11", "-15"]
		title = "Analyze Specific Return Codes: " + ",".join(returncodes) + " - analyze_specific_return_code"
		columns = ["Testcase", "Software", "Type", "OS", "Returncode", "Stdout", "Stderr"]
		if output:
			self.settings['logger'].info(title)

		rows = []
		results = self.settings['db'].analyze_specific_return_code(returncodes)
		for result in results:
			if toplimit is not None and len(rows) >= toplimit:
				break
			rows.append([(result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4], result[5], result[6])])

		self.dump.general(output, title, columns, rows)
		return len(rows)

	def analyze_return_code_same_software_differences(self, output, toplimit):
		"""Find when different return codes are received for the same software using different input forms"""
		title = "Analyze Return Code Same Software Differences - analyze_return_code_same_software_differences"
		columns = ["Testcase", "Software", "Type", "Return Code", "Stdout", "Stderr"]
		if output:
			self.settings['logger'].info(title)

		# First check if there is more than one type of input per software, and save the IDs
		software_ids = []
		software_name = ""
		results = self.settings['db'].list_software()
		for result in results:
			if software_name == result[1]:
				software_ids.append(str(result[0]))
			else:
				software_name = result[1]

		rows = []
		if software_ids:
			original_ids = self.settings['db'].get_software()
			self.settings['db'].set_software(software_ids) # restrict the ids
			software = ""
			software_returncode = ""
			testcase = ""
			outputtmp = []
			results = self.settings['db'].analyze_return_code_differences()
			for result in results:
				if toplimit is not None and len(rows) >= toplimit:
					break
				if testcase == result[0] and software == result[1] and software_returncode != result[3]:
					outputtmp.append([result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4], result[5]])
				else:
					if len(outputtmp) > 1:
						rows.append(outputtmp)
					outputtmp = []
					outputtmp.append([result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4], result[5]])
				testcase = result[0]
				software = result[1]
				software_returncode = result[3]
			self.settings['db'].set_software(original_ids)

		self.dump.general(output, title, columns, rows)
		return len(rows)

	def analyze_return_code_differences(self, output, toplimit):
		"""Find when different return codes are received for the same input"""
		title = "Analyze Return Code Differences - analyze_return_code_differences"
		columns = ["Testcase", "Software", "Type", "Return Code", "Stdout", "Stderr"]
		if output:
			self.settings['logger'].info(title)

		rows = []
		software_returncode = ""
		testcase = ""
		outputtmp = []
		results = self.settings['db'].analyze_return_code_differences()
		for result in results:
			if toplimit is not None and len(rows) >= toplimit:
				break
			if testcase == result[0] and software_returncode != result[3]:
				outputtmp.append([result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4], result[5]])
			else:
				if len(outputtmp) > 1:
					rows.append(outputtmp)
				outputtmp = []
				outputtmp.append([result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4], result[5]])
			testcase = result[0]
			software_returncode = result[3]

		self.dump.general(output, title, columns, rows)
		return len(rows)

	def analyze_username_disclosure(self, output, toplimit, username=None):
		"""Find when a specific username is disclosed in the stdout or in the stderr"""
		if username is None:
			print "Error: extra parameter username has not been defined"
			help()
		title = "Analyze Username Disclosure: " + username + " - analyze_username_disclosure"
		columns = ["Testcase", "Software", "Type", "OS", "Stdout", "Stderr"]
		if output:
			self.settings['logger'].info(title)

		rows = []
		results = self.settings['db'].analyze_string_disclosure(username, excludeme=self.settings['tmp_prefix'])
		for result in results:
			if toplimit is not None and len(rows) >= toplimit:
				break
			rows.append([(result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4], result[5])])

		self.dump.general(output, title, columns, rows)
		return len(rows)

	def analyze_canary_file(self, output, toplimit):
		"""Find canary filenames in the stdout or stderr, even though canary files were not part of the payload"""
		title = "Analyze Presence of Canary Files - analyze_canary_file"
		columns = ["Testcase", "Software", "Type", "OS", "Stdout", "Stderr"]
		if output:
			self.settings['logger'].info(title)

		rows = []
		results = self.settings['db'].analyze_canary_file()
		for result in results:
			if toplimit is not None and len(rows) >= toplimit:
				break
			if result[0].find('canaryfile') == -1:
				rows.append([(result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4], result[5])])

		self.dump.general(output, title, columns, rows)
		return len(rows)

	def analyze_canary_token_file(self, output, toplimit):
		"""Find canary tokens of files in the stdout or in the stderr"""
		title = "Analyze Presence of Canary Tokens File Local - analyze_canary_token_file"
		columns = ["Testcase", "Software", "Type", "OS", "Stdout", "Stderr"]
		if output:
			self.settings['logger'].info(title)

		rows = []
		results = self.settings['db'].analyze_string_disclosure("canarytokenfile")
		for result in results:
			if toplimit is not None and len(rows) >= toplimit:
				break
			rows.append([(result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4], result[5])])

		self.dump.general(output, title, columns, rows)
		return len(rows)

	def analyze_canary_token_code(self, output, toplimit):
		"""Find canary tokens of code executed in the stdout or in the stderr"""
		title = "Analyze Presence of Canary Tokens Code - analyze_canary_token_code"
		columns = ["Testcase", "Software", "Type", "OS", "Stdout", "Stderr"]
		if output:
			self.settings['logger'].info(title)

		rows = []
		results = self.settings['db'].analyze_string_disclosure("canarytokencode")
		for result in results:
			if toplimit is not None and len(rows) >= toplimit:
				break
			rows.append([(result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4], result[5])])

		self.dump.general(output, title, columns, rows)
		return len(rows)

	def analyze_canary_token_command(self, output, toplimit):
		"""Find canary tokens of commands in the stdout or stderr"""
		title = "Analyze Presence of Canary Tokens Command - analyze_canary_token_command"
		columns = ["Testcase", "Software", "Type", "OS", "Stdout", "Stderr"]
		if output:
			self.settings['logger'].info(title)

		rows = []
		results = self.settings['db'].analyze_string_disclosure("canarytokencommand")
		for result in results:
			if toplimit is not None and len(rows) >= toplimit:
				break
			rows.append([(result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4], result[5])])

		self.dump.general(output, title, columns, rows)
		return len(rows)

	def analyze_remote_connection(self, output, toplimit):
		"""Find remote connections made"""
		title = "Analyze Remote Connections - analyze_remote_connection"
		columns = ["Testcase", "Software", "Type", "OS", "Stdout", "Stderr", "Network"]
		if output:
			self.settings['logger'].info(title)

		testcase = ""
		outputtmp = []
		rows = []
		results = self.settings['db'].analyze_remote_connection()
		for result in results:
			if toplimit is not None and rows >= toplimit:
				break
			if testcase != result[0] and outputtmp:
				testcase = result[0]
				rows.append(outputtmp)
				outputtmp = []
			outputtmp.append((result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4], result[5], result[6]))

		if len(outputtmp)>0:
			rows.append(outputtmp)
		self.dump.general(output, title, columns, rows)
		return len(rows)

	def analyze_top_elapsed_killed(self, output, toplimit):
		"""Find which killed tests cases required more time"""
		title = "Analyze Top Time Elapsed (and eventually killed) - analyze_top_elapsed_killed"
		columns = ["Testcase", "Software", "Type", "OS", "Elapsed"]
		if output:
			self.settings['logger'].info(title)

		rows = []
		results = self.settings['db'].analyze_top_elapsed(True)
		for result in results:
			if toplimit is not None and len(rows) >= toplimit:
				break
			rows.append([(result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4])])

		self.dump.general(output, title, columns, rows)
		return len(rows)

	def analyze_top_elapsed_not_killed(self, output, toplimit):
		"""Find which not killed tests cases required more time"""
		title = "Analyze Top Time Elapsed (but not killed) - analyze_top_elapsed_not_killed"
		columns = ["Testcase", "Software", "Type", "OS", "Elapsed"]
		if output:
			self.settings['logger'].info(title)

		rows = []
		results = self.settings['db'].analyze_top_elapsed(False)
		for result in results:
			if toplimit is not None and len(rows) >= toplimit:
				break
			rows.append([(result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4])])

		self.dump.general(output, title, columns, rows)
		return len(rows)

	def analyze_killed_differences(self, output, toplimit):
		"""Find when one piece of software was killed AND another one was not killed for the same input"""
		title = "Analyze Killed Software vs Not Killed Software - analyze_killed_differences"
		columns = ["Testcase", "Software", "Type", "OS", "Kill", "Stdout", "Stderr"]
		if output:
			self.settings['logger'].info(title)

		rows = []
		testcase = kill_status = None
		outputtmp = []
		results = self.settings['db'].analyze_killed_differences()
		for result in results:
			if toplimit is not None and len(rows) >= toplimit:
				break

			if testcase is None or testcase != result[0]:
				testcase = result[0]
				kill_status = result[4]


			if testcase == result[0] and kill_status != result[4]:
				outputtmp.append([result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4], result[5], result[6]])
			else:
				if len(outputtmp) > 1:
					rows.append(outputtmp)
				outputtmp = []
				outputtmp.append([result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4], result[5], result[6]])
			testcase = result[0]
			kill_status = result[4]

		self.dump.general(output, title, columns, rows)
		return len(rows)

	def analyze_same_software(self, output, toplimit):
		"""Find when the same software produces different results when using different inputs (ie, Node CLI vs Node File Input)"""
		title = "Analyze Same Software having a Different Output - analyze_same_software"
		columns = ["Testcase", "Software", "Type", "Stdout"]
		if output:
			self.settings['logger'].info(title)

		# First check if there is more than one type of input per software, and save the IDs
		software_ids = []
		software_name = ""
		results = self.settings['db'].list_software()
		for result in results:
			if software_name == result[1]:
				software_ids.append(str(result[0]))
			else:
				software_name = result[1]

		rows = []
		if software_ids:
			original_ids = self.settings['db'].get_software()
			self.settings['db'].set_software(software_ids) # restrict the ids
			software = ""
			software_stdout = ""
			testcase = ""
			outputtmp = []
			results = self.settings['db'].analyze_same_software()
			for result in results:
				if toplimit is not None and len(rows) >= toplimit:
					break
				if testcase == result[0] and software == result[1] and software_stdout != result[3]:
					outputtmp.append([result[0][:self.settings['testcase_limit']], result[1], result[2], result[3]])
				else:
					if len(outputtmp) > 1:
						rows.append(outputtmp)
					outputtmp = []
					outputtmp.append([result[0][:self.settings['testcase_limit']], result[1], result[2], result[3]])
				testcase = result[0]
				software = result[1]
				software_stdout = result[3]
			if len(outputtmp) > 1:
				rows.append(outputtmp)
			self.dump.general(output, title, columns, rows)
			self.settings['db'].set_software(original_ids)
		return len(rows)

	def analyze_stdout(self, output, toplimit):
		"""Find when different pieces of software produces different results (basic differential testing)"""
		title = "Analyze Stdout for Different Results - analyze_stdout"
		columns = ["Testcase", "Software", "Type", "OS", "Stdout", "ID"]
		if output:
			self.settings['logger'].info(title)

		testcase = ""
		stdout = ""
		tobeprinted = False
		outputtmp = []
		rows = []

		lowerlimit = 0
		upperlimit = 100000
		while True:
			results = self.settings['db'].analyze_stdout(lowerlimit, upperlimit)
			if not results:
				break
			lowerlimit += 100000
			upperlimit += 100000
			for result in results:
				if toplimit is not None and len(rows) >= toplimit:
					break
				if testcase != result[0]:
					testcase = result[0]
					stdout = result[3]
					if outputtmp and tobeprinted:
						rows.append(outputtmp)
					tobeprinted = False
					outputtmp = []
				outputtmp.append([result[0][:self.settings['testcase_limit']], result[1], result[2], result[5], result[3], result[6]])
				if stdout != result[3]:
					tobeprinted = True

		self.dump.general(output, title, columns, rows)
		return len(rows)

	def analyze_same_stdout(self, output, toplimit):
		"""Finds different testcases that produce the same standard output"""
		title = "Analyze Testcases that Produce the Same Stdout - analyze_same_stdout"
		columns = ["Testcase", "Software", "Type", "OS", "Stdout"]
		if output:
			self.settings['logger'].info(title)

		testcase = ""
		outputtmp = []
		rows = []
		countsoftware = self.settings['db'].count_software()
		results = self.settings['db'].analyze_same_stdout()
		for result in results:
			if toplimit is not None and len(rows) >= toplimit:
				break
			if testcase != result[4]:
				if len(outputtmp) != countsoftware:
					rows.append(outputtmp)
				outputtmp = []
				testcase = result[4]
			if not results or results[len(results)-1][0] != result[0] or results[len(outputtmp)-1][1] != result[1]:
				outputtmp.append([result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4]])
		if outputtmp and len(outputtmp) != countsoftware and len(rows) < toplimit:
			rows.append(outputtmp)

		self.dump.general(output, title, columns, rows)
		return len(rows)

	def analyze_file_disclosure(self, output, toplimit):
		"""Find the tmp_prefix in the stdout or in the stderr"""
		title = "Analyze Temp File Disclosure (" + self.settings['tmp_prefix'] + ") - analyze_file_disclosure"
		columns = ["Testcase", "Software", "Type", "OS", "Stdout", "Stderr"]
		if output:
			self.settings['logger'].info(title)

		rows = []
		results = self.settings['db'].analyze_string_disclosure(self.settings['tmp_prefix'])
		for result in results:
			if toplimit is not None and len(rows) >= toplimit:
				break
			rows.append([(result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4], result[5])])

		self.dump.general(output, title, columns, rows)
		return len(rows)

	def analyze_file_disclosure_without_path(self, output, toplimit):
		"""Find the tmp_prefix in the stdout or stderr without the full path"""
		title = "Analyze Temp File Disclosure (" + self.settings['tmp_prefix'] + ") Without Path (" + self.settings['tmp_dir'] + ") - analyze_file_disclosure_without_path"
		columns = ["Test", "Software", "Type", "OS", "Stdout", "Stderr"]
		if output:
			self.settings['logger'].info(title)

		rows = []
		results = self.settings['db'].analyze_string_disclosure(self.settings['tmp_prefix'])
		for result in results:
			if toplimit is not None and len(rows) >= toplimit:
				break
			if result[3].find(self.settings['tmp_dir']) == -1 and result[4].find(self.settings['tmp_dir']) == -1:
				rows.append([(result[0], result[1], result[2], result[3], result[4], result[5])])

		self.dump.general(output, title, columns, rows)
		return len(rows)

	def analyze_path_disclosure(self, output, toplimit):
		"""Find the tmp_dir in the stdout or stderr"""
		title = "Analyze Path Disclosure (" + self.settings['tmp_dir'] + ") - analyze_path_disclosure"
		columns = ["Testcase", "Software", "Type", "OS", "Stdout", "Stderr"]
		if output:
			self.settings['logger'].info(title)

		rows = []
		results = self.settings['db'].analyze_string_disclosure(self.settings['tmp_dir'])
		for result in results:
			if toplimit is not None and len(rows) >= toplimit:
				break
			rows.append([(result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4], result[5])])

		self.dump.general(output, title, columns, rows)
		return len(rows)

	def analyze_path_disclosure_without_file(self, output, toplimit):
		"""Find the tmp_dir in the stdout or stderr, even though the testcase did not have a temporary file"""
		title = "Analyze Path Disclosure (" + self.settings['tmp_dir'] + ") Without Temp File (" + self.settings['tmp_prefix'] + ") - analyze_path_disclosure_without_file"
		columns = ["Testcase", "Software", "Type", "OS", "Stdout", "Stderr"]
		if output:
			self.settings['logger'].info(title)

		software_ids = []
		results = self.settings['db'].get_software_type('CLI')
		for result in results:
			software_ids.append(str(result[0]))

		rows = []
		if software_ids:
			original_ids = self.settings['db'].get_software()
			self.settings['db'].set_software(software_ids) # restrict the ids
			results = self.settings['db'].analyze_string_disclosure(self.settings['tmp_dir'])
			self.settings['db'].set_software(original_ids) # set the ids to the original value
			for result in results:
				if toplimit is not None and len(rows) >= toplimit:
					break
				if result[3].find(self.settings['tmp_prefix']) == -1 and result[4].find(self.settings['tmp_prefix']) == -1:
					rows.append([(result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4], result[5])])
			self.dump.general(output, title, columns, rows)
			self.settings['db'].set_software(original_ids)
		return len(rows)


	def analyze_output_messages(self, output, toplimit, messages='stderr'):
		"""Analize which were the different output messages for each piece of software"""

		title = "Analyze Different " + messages[0].upper() + messages[1:] + " Output Messages - analyze_output_messages"
		columns = ["Software", "Type", "OS", "Return Code", messages[0].upper() + messages[1:]]
		if output:
			self.settings['logger'].info(title)

		total = 0
		rows = []
		results = self.settings['db'].analyze_output_messages(messages)
		for result in results:
			if toplimit is not None and len(rows) >= toplimit:
				break

			output_parsed = result[5]
			if len(result[0]) > 5:
				output_parsed = output_parsed.replace(result[0], "TESTCASE") # if possible, remove the testcase from output
				output_parsed = output_parsed.replace(result[0].encode("utf-8"), "TESTCASE") # if possible, remove the testcase from output
			if output_parsed.find(self.settings['tmp_prefix']) != -1:
				regex = re.compile('[\S]*' + self.settings['tmp_prefix'] + '[\S]*')
				regex_iter = re.finditer(regex, output_parsed)
				for match in regex_iter:
					output_parsed = output_parsed.replace(match.group(0), "TMPFILE")
			test = [result[1], result[2], result[3], result[4], output_parsed]

			flag = False
			for row in rows:
				if [test] == row:
					flag = True
					break
			if not flag:
				rows.append([test])
				total += 1

		rows = sorted(rows)
		self.dump.general(output, title, columns, rows)
		return total

	def analyze_elapsed(self, output, toplimit):
		"""Analize which was the total time required for each piece of software"""
		title = "Analyze Elapsed Time - analyze_elapsed"
		columns = ["Software", "Type", "OS", "Elapsed", "Average per Testcase"]
		if output:
			self.settings['logger'].info(title)

		total = 0
		rows = []
		if self.count_results is None:
			self.count_results = self.settings['db'].count_results(0, None)
		results = self.settings['db'].analyze_elapsed()
		for result in results:
			if toplimit is not None and len(rows) >= toplimit:
				break
			rows.append([[result[0], result[1], result[2], str(datetime.timedelta(seconds=int(result[3]))), str(round(result[3]/self.count_results, 5))]])
			total += result[3]

		self.dump.general(output, title, columns, rows)
		return total

def help(err=""):
	"""Print a help screen and exit"""
	if err:
		print "Error: %s\n" % err
	print "Syntax: "
	print os.path.basename(__file__) + "  -d db.sqlite          Choose the database"
	print                           "\t    [-m methodName]       Method: report (default), analyze_stdout, analyze_specific_return_code, etc"
	print                           "\t    [-e extra_parameter]  Extra parameter used when specifying a for certain methodName (ie, analyze_username_disclosure)"
	print                           "\t    [-o html]             Output: html (default), txt or csv."
	print                           "\t    [-l 20]               Top limit results (default: 20)"
	sys.exit()

def main():
	"""Analyze potential vulnerabilities on a database fuzzing session"""
	try:
		opts, args = getopt.getopt(sys.argv[1:], "hd:e:m:o:l:", ["help", "database=", "extra=", "method=", "output=", "limit="])
	except getopt.GetoptError as err:
		help(err)

	settings = {}
	output_type = "html"# default output type
	method = "report" 	# default method name
	toplimit = 20 		# default top limit
	extra = None
	for o, a in opts:
		if o in ("-h", "--help"):
			help()
		elif o in ("-d", "--database"):
			if os.path.isfile(a):
				settings['db_file'] = a
			else:
				help("Database should be a valid file.")
		elif o in ("-e", "--extra"):
			extra = a
		elif o in ("-m", "--method"):
			method = a
		elif o in ("-o", "--output"):
			output_type = a
		elif o in ("-l", "--limit"):
			try:
				toplimit = int(a)
			except:
				help("Top limit should be an integer.")

	if 'db_file' not in settings:
		help("The database was not specified.")
	settings = classes.settings.load_settings(settings)
	settings["output_type"] = output_type
	analyze = Analyze(settings)
	analyze.dump_results(method, toplimit, extra)

if __name__ == "__main__":
	main()
	#profile.run('analyze.dump_results(method, toplimit)')
