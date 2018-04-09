#!/usr/bin/env python
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
from __future__ import print_function
import datetime
import getopt
import getpass
import inspect
import os
# import profile  # uncomment here for benchmarking and at the bottom
import re
import sys
import time
import classes.settings
from classes.dump import Dump

try:
	reload         # Python 2
except NameError:  # Python 3
	from importlib import reload


class Analyze(object):
	"""Analyzes the fuzzing information for abnormal behaviors"""
	def __init__(self, settings):
		reload(sys)
		try:
			sys.setdefaultencoding('utf8')
		except:
			pass  # Python3
		self.settings = settings
		self.settings['tmp_dir'] = "ramdisk"  # by using this, it will work on multiple directories (ie, /Volumes/ramdisk, /mnt/ramdisk, etc)
		self.dump = Dump(self.settings)
		self.count_results = None

	def check_minimum_risk(self, function_risk, title):
		"""Check if the function has the minum risk required"""
		check = False
		if self.settings['print_risk']:
			print("Function: %s, Risk: %s, Title: %s" % (inspect.stack()[1][3], function_risk, title[:title.find(" - ")]))
		elif function_risk >= self.settings['minimum_risk']:
			check = True
		return check

	def dump_results(self, method, toplimit, extra):
		"""Prints the output of an internal method"""
		success = False
		method_to_call = None
		if self.settings['output_type'] not in ["txt", "csv", "xml", "html"]:
			self.settings['logger'].error("Incorrect output type selected. Valid outputs: txt, csv, xml, html.")
		else:
			if method not in ['dump_results']:
				try:
					method_to_call = getattr(self, method)
				except Exception as e:
					self.settings['logger'].error("Error when executing the method %s: %s", method, e)

		if method_to_call:
			if method != "report":
				self.settings["minimum_risk"] = 0  # set the minimum risk to 0
				self.dump.set_toggle_table(False)
			start_time = time.time()
			self.settings['logger'].info("Dumping: database %s - method %s - output %s" % (self.settings['db_file'], method, self.settings['output_type']))
			self.dump.pre_general(self.settings['output_type'])

			if extra:
				try:
					method_to_call(self.settings['output_type'], toplimit, extra)
					success = True
				except Exception as e:
					self.settings['logger'].error("Error executing the method '%s' with parameter '%s': %s", method, extra, e)
			else:
				try:
					method_to_call(self.settings['output_type'], toplimit)
					success = True
				except Exception as e:
					self.settings['logger'].error("Error executing the method '%s': %s", method, e)
			if success:
				self.dump.post_general(self.settings['output_type'])
				size = ""
				if 'output_file' in self.settings and os.path.isfile(self.settings['output_file']):
					size = ", output file: " + self.settings['output_file'] + " (" + str(int(os.stat(self.settings['output_file']).st_size / 1024)) + " kb)"
				elif 'output_file' in self.settings:
					size = ". No information to be written into the output file."
				finish_time = time.time() - start_time
				self.settings['logger'].info("Time elapsed %s seconds%s" % (str(int(finish_time)), size))
		return success

	def report(self, output, toplimit):
		"""Print several functions in the form of a report (useful for HTML)"""
		# self.settings['db'].set_software(["9", "10"])

		# self.list_summary(output, toplimit)                          # informational
		self.list_software(output, self.settings["max_results"])

		self.analyze_elapsed(output, toplimit)                       # informational
		self.list_results(output, toplimit)

		self.analyze_top_elapsed_killed(output, toplimit)            # informational
		self.analyze_top_elapsed_not_killed(output, toplimit)        # informational

		self.analyze_valgrind(output, toplimit)
		self.analyze_username_disclosure(output, toplimit, username="root")
		if getpass.getuser() != "root":  # do not repeat the information if the root user was the one already used for the execution
			self.analyze_username_disclosure(output, toplimit, username=getpass.getuser())
		self.analyze_canary_token_file(output, toplimit)
		self.analyze_canary_token_code(output, toplimit)
		self.analyze_remote_connection(output, toplimit)
		self.analyze_canary_token_command(output, toplimit)
		self.analyze_canary_file(output, toplimit)

		self.analyze_killed_differences(output, toplimit)            # informational

		self.analyze_return_code(output, toplimit)
		self.analyze_specific_return_code(output, toplimit)
		self.analyze_return_code_differences(output, toplimit)
		self.analyze_return_code_same_software_differences(output, toplimit)

		self.analyze_output_messages(output, toplimit, 'stderr')
		self.analyze_output_messages(output, toplimit, 'stdout')
		self.analyze_error_disclosure(output, toplimit)
		self.analyze_same_software(output, toplimit)                 # low_risk
		self.analyze_stdout(output, toplimit)
		self.analyze_same_stdout(output, toplimit)                   # low_risk

		self.analyze_file_disclosure(output, toplimit)               # low_risk
		self.analyze_file_disclosure_without_path(output, toplimit)  # low_risk
		self.analyze_path_disclosure_stdout(output, toplimit)        # low_risk
		self.analyze_path_disclosure_stderr(output, toplimit)        # low_risk
		self.analyze_path_disclosure_without_file(output, toplimit)  # low_risk

	def list_summary(self, output, toplimit):
		"""Print an quantitative information summary using all the analytic functions from this class"""
		title = "Summary for " + self.settings['db_file']
		columns = ["Information", "Amount"]
		function_risk = 0
		if not self.check_minimum_risk(function_risk, title):
			return False

		if output:
			self.settings['logger'].info(title)
		rows = []

		results = len(self.list_software(None, self.settings["max_results"]))
		rows.append([["Pieces of Software", str(results)]])
		if self.count_results is None:
			self.count_results = self.settings['db'].count_results(0, None)
		rows.append([["Amount of Testcases", str(self.count_results)]])
		rows.append([["Output Top Limit", str(toplimit)]])

		results = len(self.analyze_valgrind(None, self.settings["max_results"]))
		rows.append([["Valgrind References Found", str(results)]])
		results = len(self.analyze_username_disclosure(None, self.settings["max_results"], "root"))
		rows.append([["Username 'root' Disclosure", str(results)]])
		results = len(self.analyze_username_disclosure(None, self.settings["max_results"], getpass.getuser()))
		rows.append([["Username '" + getpass.getuser() + "' Disclosure", str(results)]])
		results = len(self.analyze_canary_token_file(None, self.settings["max_results"]))
		rows.append([["Canary Token File Found", str(results)]])
		results = len(self.analyze_canary_token_code(None, self.settings["max_results"]))
		rows.append([["Canary Token Code Found", str(results)]])
		results = len(self.analyze_canary_token_command(None, self.settings["max_results"]))
		rows.append([["Canary Token Command Found", str(results)]])
		results = len(self.analyze_canary_file(None, self.settings["max_results"]))
		rows.append([["Canary File Found", str(results)]])
		results = len(self.analyze_top_elapsed_killed(None, self.settings["max_results"]))
		rows.append([["Testcases Killed", str(results)]])
		results = len(self.analyze_top_elapsed_not_killed(None, self.settings["max_results"]))
		rows.append([["Testcases not Killed", str(results)]])
		results = len(self.analyze_killed_differences(None, self.settings["max_results"]))
		rows.append([["Software Killed and Not Killed", str(results)]])
		results = len(self.analyze_return_code(None, self.settings["max_results"]))
		rows.append([["Return Code", str(results)]])
		results = len(self.analyze_return_code_differences(None, self.settings["max_results"]))
		rows.append([["Return Code Differences", str(results)]])
		results = len(self.analyze_return_code_same_software_differences(None, self.settings["max_results"]))
		rows.append([["Return Code Same Software Differences", str(results)]])
		results = len(self.analyze_same_software(None, self.settings["max_results"]))
		rows.append([["Same Software having a Different Output", str(results)]])
		results = len(self.analyze_stdout(None, self.settings["max_results"]))
		rows.append([["Stdout for Different Results", str(results)]])
		results = len(self.analyze_output_messages(None, self.settings["max_results"], 'stderr'))
		rows.append([["Different Stderr Messages", str(results)]])
		results = len(self.analyze_output_messages(None, self.settings["max_results"], 'stdout'))
		rows.append([["Different Stdout Messages", str(results)]])
		results = len(self.analyze_error_disclosure(None, self.settings["max_results"]))
		rows.append([["Analyze Error Messages for exceptions", str(results)]])
		results = len(self.analyze_same_stdout(None, self.settings["max_results"]))
		rows.append([["Testcases that Produce the Same Stdout", str(results)]])
		results = len(self.analyze_file_disclosure(None, self.settings["max_results"]))
		rows.append([["Temp File Disclosure", str(results)]])
		results = len(self.analyze_file_disclosure_without_path(None, self.settings["max_results"]))
		rows.append([["Temp File Disclosure (without path)", str(results)]])
		results = len(self.analyze_path_disclosure_stdout(None, self.settings["max_results"]))
		rows.append([["Path Disclosure Stdout", str(results)]])
		results = len(self.analyze_path_disclosure_stderr(None, self.settings["max_results"]))
		rows.append([["Path Disclosure Stderr", str(results)]])
		results = len(self.analyze_path_disclosure_without_file(None, self.settings["max_results"]))
		rows.append([["Path Disclosure (without temp file)", str(results)]])
		results = len(self.analyze_remote_connection(None, self.settings["max_results"]))
		rows.append([["Remote Connections", str(results)]])
		results = self.analyze_elapsed(None, self.settings["max_results"])
		results = datetime.timedelta(seconds=round(results, 0))
		rows.append([["Total Time Elapsed", str(results)]])

		self.dump.general(output, title, columns, rows)

	def list_software(self, output, toplimit):
		"""Print the list of [active] software used with testcases from the database"""
		title = "List Software Tested - list_software "
		columns = ["ID", "Software", "Type", "OS"]
		function_risk = 0
		if not self.check_minimum_risk(function_risk, title):
			return False

		if output:
			self.settings['logger'].info(title)
		rows = []
		results = self.settings['db'].list_software()
		for result in results:
			if toplimit is not None and len(rows) >= toplimit:
				break
			rows.append([result])
		self.dump.general(output, title, columns, rows)
		return rows

	def list_results(self, output, toplimit):
		"""Print the fuzzing results: valuable to see how the software worked with the testcases defined, without using any constrains"""
		lowerlimit = 0
		title = "Analyze the Testcase Results from " + str(int(lowerlimit)) + " to " + str(lowerlimit + toplimit) + " - list_results"
		columns = ["Testcase", "Software", "Type", "OS", "Stdout", "Stderr", "Kill"]
		function_risk = 0
		if not self.check_minimum_risk(function_risk, title):
			return False

		if output:
			self.settings['logger'].info(title)

		rows = []
		testcase = None
		tmpoutput = []
		results = self.settings['db'].list_results(lowerlimit, toplimit * len(self.list_software(None, self.settings["max_results"])))
		for result in results:
			if toplimit is not None and len(rows) >= toplimit:
				break
			if testcase is None:
				testcase = result[0]
			if testcase != result[0]:
				testcase = result[0]
				rows.append(tmpoutput)
				tmpoutput = []
			tmpoutput.append((result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4], result[5], result[6]))
		if len(rows) < toplimit and tmpoutput:
			rows.append(tmpoutput)

		self.dump.general(output, title, columns, rows)
		return rows

	def analyze_valgrind(self, output, toplimit):
		"""Find Valgrind references in case it was used"""
		title = "Analyze Valgrind Output - analyze_valgrind"
		columns = ["Testcase", "Software", "Type", "OS", "Stdout", "Stderr", "Return Code"]
		function_risk = 2
		if not self.check_minimum_risk(function_risk, title):
			return False

		if output:
			self.settings['logger'].info(title)

		rows = []
		results = self.settings['db'].analyze_string_disclosure("== ",)
		for result in results:
			if toplimit is not None and len(rows) >= toplimit:
				break
			if result[5][:10].count('=') == 4:  # Valgrind outputs can be detected because they have 4 equal signs in the first 10 characters
				rows.append([(result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4], result[5], result[6])])
		self.dump.general(output, title, columns, rows)
		return rows

	def list_killed_results(self, output, toplimit):
		"""Print the killed fuzzing results"""
		title = "Analyze the Killed Testcase Results - list_killed_results"
		columns = ["Testcase", "Software", "Type", "OS", "Stdout", "Stderr", "Kill"]
		function_risk = 2
		if not self.check_minimum_risk(function_risk, title):
			return False

		if output:
			self.settings['logger'].info(title)

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
			tmpoutput.append((result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4][:500], result[5][:500], result[6]))
		if len(rows) < toplimit and tmpoutput:
			rows.append(tmpoutput)

		self.dump.general(output, title, columns, rows)
		return rows

	def analyze_return_code(self, output, toplimit):
		"""Get the different return codes for each piece of software"""
		title = "Analyze Different Return Codes per Software - analyze_return_code"
		columns = ["Software", "Type", "OS", "Return Code", "Amount"]
		function_risk = 1
		if not self.check_minimum_risk(function_risk, title):
			return False

		if output:
			self.settings['logger'].info(title)

		rows = []
		results = self.settings['db'].list_return_code_per_software()
		for result in results:
			if toplimit is not None and len(rows) >= toplimit:
				break
			rows.append([(result[0], result[1], result[2], result[3], result[4])])

		self.dump.general(output, title, columns, rows)
		return rows

	def analyze_specific_return_code(self, output, toplimit):
		"""Find specific return codes"""
		returncodes = ["-6", "-9", "-11", "-15"]
		title = "Analyze Specific Return Codes: " + ",".join(returncodes) + " - analyze_specific_return_code"
		columns = ["Testcase", "Software", "Type", "OS", "Returncode", "Stdout", "Stderr"]
		function_risk = 2
		if not self.check_minimum_risk(function_risk, title):
			return False

		if output:
			self.settings['logger'].info(title)

		rows = []
		results = self.settings['db'].analyze_specific_return_code(returncodes)
		for result in results:
			if toplimit is not None and len(rows) >= toplimit:
				break
			rows.append([(result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4], result[5], result[6])])

		self.dump.general(output, title, columns, rows)
		return rows

	def analyze_return_code_same_software_differences(self, output, toplimit):
		"""Find when different return codes are received for the same software using different input forms"""
		title = "Analyze Return Code Same Software Differences - analyze_return_code_same_software_differences"
		columns = ["Testcase", "Software", "Type", "Return Code", "Stdout", "Stderr"]
		function_risk = 2
		if not self.check_minimum_risk(function_risk, title):
			return False

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
			self.settings['db'].set_software(software_ids)  # restrict the ids
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
		return rows

	def analyze_return_code_differences(self, output, toplimit):
		"""Find when different return codes are received for the same input"""
		title = "Analyze Return Code Differences - analyze_return_code_differences"
		columns = ["Testcase", "Software", "Type", "Return Code", "Stdout", "Stderr"]
		function_risk = 2
		if not self.check_minimum_risk(function_risk, title):
			return False

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
		return rows

	def analyze_username_disclosure(self, output, toplimit, username=None):
		"""Find when a specific username is disclosed in the stdout or in the stderr"""
		title = "Analyze Username Disclosure: " + username + " - analyze_username_disclosure"
		columns = ["Testcase", "Software", "Type", "OS", "Stdout", "Stderr"]
		function_risk = 1
		if not self.check_minimum_risk(function_risk, title):
			return False

		if username is None:
			print("Error: extra parameter username has not been defined")
			help()
		if output:
			self.settings['logger'].info(title)

		rows = []
		results = self.settings['db'].analyze_string_disclosure(username, excludeme=self.settings['tmp_prefix'])
		for result in results:
			if toplimit is not None and len(rows) >= toplimit:
				break
			rows.append([(result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4], result[5])])

		self.dump.general(output, title, columns, rows)
		return rows

	def analyze_error_disclosure(self, output, toplimit):
		"""Find canary filenames in the stdout or stderr, even though canary files were not part of the payload"""
		title = "Analyze Presence of Exceptions - analyze_error_disclosure"
		columns = ["Testcase", "Software", "Type", "OS", "Stdout", "Stderr"]
		function_risk = 1
		if not self.check_minimum_risk(function_risk, title):
			return False

		if output:
			self.settings['logger'].info(title)

		rows = []
		for error in self.settings['error_disclosure']:
			results = self.settings['db'].analyze_string_disclosure(error)
			for result in results:
				if toplimit is not None and len(rows) >= toplimit:
					break
				if result[0].find('canaryfile') == -1:
					rows.append([(result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4], result[5])])

		self.dump.general(output, title, columns, rows)
		return rows

	def analyze_canary_file(self, output, toplimit):
		"""Find canary filenames in the stdout or stderr, even though canary files were not part of the payload"""
		title = "Analyze Presence of Canary Files - analyze_canary_file"
		columns = ["Testcase", "Software", "Type", "OS", "Stdout", "Stderr"]
		function_risk = 3
		if not self.check_minimum_risk(function_risk, title):
			return False

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
		return rows

	def analyze_canary_token_file(self, output, toplimit):
		"""Find canary tokens of files in the stdout or in the stderr"""
		title = "Analyze Presence of Canary Tokens File Local - analyze_canary_token_file"
		columns = ["Testcase", "Software", "Type", "OS", "Stdout", "Stderr"]
		function_risk = 3
		if not self.check_minimum_risk(function_risk, title):
			return False

		if output:
			self.settings['logger'].info(title)

		rows = []
		results = self.settings['db'].analyze_string_disclosure("canarytokenfile")
		for result in results:
			if toplimit is not None and len(rows) >= toplimit:
				break
			rows.append([(result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4], result[5])])

		self.dump.general(output, title, columns, rows)
		return rows

	def analyze_canary_token_code(self, output, toplimit):
		"""Find canary tokens of code executed in the stdout or in the stderr"""
		title = "Analyze Presence of Canary Tokens Code - analyze_canary_token_code"
		columns = ["Testcase", "Software", "Type", "OS", "Stdout", "Stderr"]
		function_risk = 3
		if not self.check_minimum_risk(function_risk, title):
			return False

		if output:
			self.settings['logger'].info(title)

		rows = []
		results = self.settings['db'].analyze_string_disclosure("canarytokencode")
		for result in results:
			if toplimit is not None and len(rows) >= toplimit:
				break
			rows.append([(result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4], result[5])])

		self.dump.general(output, title, columns, rows)
		return rows

	def analyze_canary_token_command(self, output, toplimit):
		"""Find canary tokens of commands in the stdout or stderr"""
		title = "Analyze Presence of Canary Tokens Command - analyze_canary_token_command"
		columns = ["Testcase", "Software", "Type", "OS", "Stdout", "Stderr"]
		function_risk = 3
		if not self.check_minimum_risk(function_risk, title):
			return False

		if output:
			self.settings['logger'].info(title)

		rows = []
		results = self.settings['db'].analyze_string_disclosure("canarytokencommand")
		for result in results:
			if toplimit is not None and len(rows) >= toplimit:
				break
			rows.append([(result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4], result[5])])

		self.dump.general(output, title, columns, rows)
		return rows

	def analyze_remote_connection(self, output, toplimit):
		"""Find remote connections made"""
		title = "Analyze Remote Connections - analyze_remote_connection"
		columns = ["Testcase", "Software", "Type", "OS", "Stdout", "Stderr", "Network"]
		function_risk = 3
		if not self.check_minimum_risk(function_risk, title):
			return False

		if output:
			self.settings['logger'].info(title)

		testcase = ""
		outputtmp = []
		rows = []
		results = self.settings['db'].analyze_remote_connection()
		for result in results:
			if toplimit is not None and len(rows) >= toplimit:
				break
			if testcase != result[0] and outputtmp:
				testcase = result[0]
				rows.append(outputtmp)
				outputtmp = []
			outputtmp.append((result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4], result[5], result[6]))

		if outputtmp:
			rows.append(outputtmp)
		self.dump.general(output, title, columns, rows)
		return rows

	def analyze_top_elapsed_killed(self, output, toplimit):
		"""Find which killed tests cases required more time"""
		title = "Analyze Top Time Elapsed (and eventually killed) - analyze_top_elapsed_killed"
		columns = ["Testcase", "Software", "Type", "OS", "Elapsed"]
		function_risk = 1
		if not self.check_minimum_risk(function_risk, title):
			return False

		if output:
			self.settings['logger'].info(title)

		rows = []
		results = self.settings['db'].analyze_top_elapsed(True)
		for result in results:
			if toplimit is not None and len(rows) >= toplimit:
				break
			rows.append([(result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4])])

		self.dump.general(output, title, columns, rows)
		return rows

	def analyze_top_elapsed_not_killed(self, output, toplimit):
		"""Find which not killed tests cases required more time"""
		title = "Analyze Top Time Elapsed (but not killed) - analyze_top_elapsed_not_killed"
		columns = ["Testcase", "Software", "Type", "OS", "Elapsed"]
		function_risk = 1
		if not self.check_minimum_risk(function_risk, title):
			return False

		if output:
			self.settings['logger'].info(title)

		rows = []
		results = self.settings['db'].analyze_top_elapsed(False)
		for result in results:
			if toplimit is not None and len(rows) >= toplimit:
				break
			rows.append([(result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4])])

		self.dump.general(output, title, columns, rows)
		return rows

	def analyze_killed_differences(self, output, toplimit):
		"""Find when one piece of software was killed AND another one was not killed for the same input"""
		title = "Analyze Killed Software vs Not Killed Software - analyze_killed_differences"
		columns = ["Testcase", "Software", "Type", "OS", "Kill", "Stdout", "Stderr"]
		function_risk = 2
		if not self.check_minimum_risk(function_risk, title):
			return False

		if output:
			self.settings['logger'].info(title)

		rows = []
		testcase = kill_status = None
		outputtmp = []
		try:
			results = self.settings['db'].analyze_killed_differences()
		except:
			print("Error when requesting the killed differences")
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
		return rows

	def analyze_same_software(self, output, toplimit):
		"""Find when the same software produces different results when using different inputs (ie, Node CLI vs Node File Input)"""
		title = "Analyze Same Software having a Different Output - analyze_same_software"
		columns = ["Testcase", "Software", "Type", "Stdout"]
		function_risk = 1
		if not self.check_minimum_risk(function_risk, title):
			return False

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
			self.settings['db'].set_software(software_ids)  # restrict the ids
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
		return rows

	def analyze_stdout(self, output, toplimit):
		"""Find when different pieces of software produces different results (basic differential testing)"""
		title = "Analyze Stdout for Different Results (Basic Differential Testing) - analyze_stdout"
		columns = ["Testcase", "Software", "Type", "OS", "Stdout", "ID"]
		function_risk = 1
		if not self.check_minimum_risk(function_risk, title):
			return False

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
		if outputtmp and tobeprinted and len(rows) < toplimit:
			rows.append(outputtmp)

		self.dump.general(output, title, columns, rows)
		return rows

	def analyze_same_stdout(self, output, toplimit):
		"""Finds different testcases that produce the same standard output, but ignore the testcases where ALL the pieces of software match"""
		title = "Analyze Testcases that Produce the Same Stdout - analyze_same_stdout"
		columns = ["Testcase", "Software", "Type", "OS", "Stdout"]
		function_risk = 0
		if not self.check_minimum_risk(function_risk, title):
			return False

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
				if outputtmp and len(outputtmp) != countsoftware:
					rows.append(outputtmp)
				outputtmp = []
				testcase = result[4]
			if not results or results[len(results) - 1][0] != result[0] or results[len(outputtmp) - 1][1] != result[1]:
				outputtmp.append([result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4]])
		#if outputtmp and len(outputtmp) != countsoftware and len(rows) < toplimit:
		#	rows.append(outputtmp)

		self.dump.general(output, title, columns, rows)
		return rows

	def analyze_file_disclosure(self, output, toplimit):
		"""Find the tmp_prefix in the stdout or in the stderr"""
		title = "Analyze Temp File Disclosure (" + self.settings['tmp_prefix'] + ") - analyze_file_disclosure"
		columns = ["Testcase", "Software", "Type", "OS", "Stdout", "Stderr"]
		function_risk = 1
		if not self.check_minimum_risk(function_risk, title):
			return False

		if output:
			self.settings['logger'].info(title)

		rows = []
		results = self.settings['db'].analyze_string_disclosure(self.settings['tmp_prefix'])
		for result in results:
			if toplimit is not None and len(rows) >= toplimit:
				break
			rows.append([(result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4], result[5])])

		self.dump.general(output, title, columns, rows)
		return rows

	def analyze_file_disclosure_without_path(self, output, toplimit):
		"""Find the tmp_prefix in the stdout or stderr without the full path"""
		title = "Analyze Temp File Disclosure (" + self.settings['tmp_prefix'] + ") Without Path (" + self.settings['tmp_dir'] + ") - analyze_file_disclosure_without_path"
		columns = ["Test", "Software", "Type", "OS", "Stdout", "Stderr"]
		function_risk = 1
		if not self.check_minimum_risk(function_risk, title):
			return False

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
		return rows

	def analyze_path_disclosure_stdout(self, output, toplimit):
		"""Find the tmp_dir in the stdout or stderr"""
		title = "Analyze Path Disclosure Stdout (" + self.settings['tmp_dir'] + ") - analyze_path_disclosure_stdout"
		columns = ["Testcase", "Software", "Type", "OS", "Stdout", "Stderr"]
		function_risk = 1
		if not self.check_minimum_risk(function_risk, title):
			return False

		if output:
			self.settings['logger'].info(title)

		rows = []
		results = self.settings['db'].analyze_string_disclosure(self.settings['tmp_dir'], where='stdout')
		for result in results:
			if toplimit is not None and len(rows) >= toplimit:
				break
			rows.append([(result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4], result[5])])

		self.dump.general(output, title, columns, rows)
		return rows

	def analyze_path_disclosure_stderr(self, output, toplimit):
		"""Find the tmp_dir in the stdout or stderr"""
		title = "Analyze Path Disclosure Stderr (" + self.settings['tmp_dir'] + ") - analyze_path_disclosure_stderr"
		columns = ["Testcase", "Software", "Type", "OS", "Stdout", "Stderr"]
		function_risk = 1
		if not self.check_minimum_risk(function_risk, title):
			return False

		if output:
			self.settings['logger'].info(title)

		rows = []
		results = self.settings['db'].analyze_string_disclosure(self.settings['tmp_dir'], where='stderr')
		for result in results:
			if toplimit is not None and len(rows) >= toplimit:
				break
			rows.append([(result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4], result[5])])

		self.dump.general(output, title, columns, rows)
		return rows

	def analyze_path_disclosure_without_file(self, output, toplimit):
		"""Find the tmp_dir in the stdout or stderr, even though the testcase did not have a temporary file"""
		title = "Analyze Path Disclosure (" + self.settings['tmp_dir'] + ") Without Temp File (" + self.settings['tmp_prefix'] + ") - analyze_path_disclosure_without_file"
		columns = ["Testcase", "Software", "Type", "OS", "Stdout", "Stderr"]
		function_risk = 1
		if not self.check_minimum_risk(function_risk, title):
			return False

		if output:
			self.settings['logger'].info(title)

		software_ids = []
		results = self.settings['db'].get_software_type('CLI')
		for result in results:
			software_ids.append(str(result[0]))

		rows = []
		if software_ids:
			original_ids = self.settings['db'].get_software()
			self.settings['db'].set_software(software_ids)  # restrict the ids
			results = self.settings['db'].analyze_string_disclosure(self.settings['tmp_dir'])
			self.settings['db'].set_software(original_ids)  # set the ids to the original value
			for result in results:
				if toplimit is not None and len(rows) >= toplimit:
					break
				if result[3].find(self.settings['tmp_prefix']) == -1 and result[4].find(self.settings['tmp_prefix']) == -1:
					rows.append([(result[0][:self.settings['testcase_limit']], result[1], result[2], result[3], result[4], result[5])])
			self.dump.general(output, title, columns, rows)
			self.settings['db'].set_software(original_ids)
		return rows

	def analyze_output_messages(self, output, toplimit, messages='stderr'):
		"""Analize which were the different output messages for each piece of software"""
		title = "Analyze Different " + messages[0].upper() + messages[1:] + " Output Messages - analyze_output_messages"
		columns = ["Software", "Type", "OS", "Return Code", messages[0].upper() + messages[1:]]
		function_risk = 1
		if not self.check_minimum_risk(function_risk, title):
			return False

		if output:
			self.settings['logger'].info(title)

		rows = []
		results = self.settings['db'].analyze_output_messages(messages)
		for result in results:
			if toplimit is not None and len(rows) >= toplimit:
				break

			output_parsed = result[5]
			if len(result[0]) > 5:
				output_parsed = output_parsed.replace(result[0], "TESTCASE")  # if possible, remove the testcase from output
				output_parsed = output_parsed.replace(str(result[0].encode("utf-8")), "TESTCASE")  # if possible, remove the testcase from output
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
		rows = sorted(rows)
		self.dump.general(output, title, columns, rows)
		return rows

	def analyze_elapsed(self, output, toplimit):
		"""Analize which was the total time required for each piece of software"""
		title = "Analyze Elapsed Time - analyze_elapsed"
		columns = ["Software", "Type", "OS", "Elapsed", "Average per Testcase"]
		function_risk = 0
		if not self.check_minimum_risk(function_risk, title):
			return False

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
			rows.append([[result[0], result[1], result[2], str(datetime.timedelta(seconds=int(result[3]))), str(round(result[3] / self.count_results, 5))]])
			total += result[3]

		self.dump.general(output, title, columns, rows)
		return total


def help(err=""):
	"""Print a help screen and exit"""
	if err:
		print("Error: %s\n" % err)
	print("Syntax: ")
	print(os.path.basename(__file__) + " -d db.sqlite          Choose the database")
	print("\t\t [-D]                  Debug information")
	print("\t\t [-m methodName]       Method: report (default), analyze_stdout, analyze_specific_return_code, etc")
	print("\t\t [-e extra_parameter]  Extra parameter used when specifying a for certain methodName (ie, analyze_username_disclosure)")
	print("\t\t [-o html]             Output: html (default), txt or csv.")
	print("\t\t [-l 20]               Top limit results (default: 20)")
	print("\t\t [-r 3]                Minimum risk (0:informational, 1:low, 2:medium, 3:high (default)")
	sys.exit()


def main():
	"""Analyze potential vulnerabilities on a database fuzzing session"""
	try:
		opts, args = getopt.getopt(sys.argv[1:], "hd:De:m:o:pl:r:", ["help", "database=", "extra=", "method=", "output=", "limit=", "risk="])
	except getopt.GetoptError as err:
		help(err)

	settings = {}
	method = "report"  # default method name
	toplimit = 20  # default top limit
	extra = None
	for o, a in opts:
		if o in ("-d", "--database"):
			if os.path.isfile(a):
				settings['db_file'] = a
			else:
				help("Database should be a valid file.")
		elif o in ("-D"):
			settings['loglevel'] = 'debug'
		elif o in ("-e", "--extra"):
			extra = a
		elif o in ("-h", "--help"):
			help()
		elif o in ("-l", "--limit"):
			try:
				toplimit = int(a)
			except ValueError:
				help("Top limit should be an integer.")
		elif o in ("-m", "--method"):
			method = a
		elif o in ("-o", "--output"):
			settings["output_type"] = a
		elif o in ("-p"):
			settings["print_risk"] = True
		elif o in ("-r", "--risk"):
			try:
				settings["minimum_risk"] = int(a)
			except ValueError:
				help("Risk should be an integer.")

	if 'db_file' not in settings:
		help("The database was not specified.")
	elif 'db_file' not in settings and 'print_risk' not in settings:
		help("The database was not specified and the only functionality without a database -p was not selected. ")
	settings = classes.settings.load_settings(settings)
	if settings['db'].db_connection:
		analyze = Analyze(settings)
		analyze.dump_results(method, toplimit, extra)


if __name__ == "__main__":
	main()
	# profile.run('analyze.dump_results(method, toplimit)')
