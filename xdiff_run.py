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
#
from __future__ import print_function
import getopt
import os
import signal
import sys
import time
import classes.settings


def dfuzz(settings):
	"""Fuzz something based on he settings received"""
	if 'fuzz_category' not in settings:
		help("The category was not specified.")

	settings = classes.settings.load_settings(settings)	 # load the fuzzer settings
	if not settings:
		return False

	if not settings['software']:
		help("There is no software associated to the category selected")

	if not settings['queue'].chdir_tmp():
		return False

	banner = "Starting Fuzzer v%s" % str(settings['version'])
	settings['logger'].info(len(banner) * "-")
	settings['logger'].info(banner)
	settings['logger'].info(len(banner) * "-")
	for key in sorted(settings.iterkeys()):
		settings['logger'].debug("Setting %s: %s" % (key, str(settings[key])))

	settings['queue'].start_web_server()  # load the webserver
	settings['monitor'].check_once()      # check before start if the canaries are in place
	settings['db'].optimize()
	total_testcases = settings['db'].count_testcases()
	current_test = settings['db'].get_latest_id(settings['software'])
	settings['logger'].info("Setting testcases: %s/%s" % (str(current_test), str(total_testcases)))

	elapsed_time = 0
	test_count = 0
	while True:
		start_time = time.time()
		tests = settings['db'].get_test(current_test, settings['db_tests'])
		if not tests:
			settings['logger'].info("Terminated: no more testcases")
			break
		dbinput = settings['queue'].fuzz(tests)
		settings['monitor'].check()  # check free space before saving results
		saved, size = settings['db'].set_results(dbinput)
		finish_time = (time.time() - start_time)
		elapsed_time += finish_time  # Total time elapsed testing
		remaining_tests = total_testcases - (current_test + settings['db_tests'])  # Tests left
		test_count += settings['db_tests']
		rate = test_count / elapsed_time  # Rate per second
		time_left = remaining_tests / rate / 60  # How many hours are left ?
		settings['logger'].info("Tests " + str(current_test) + "-" + str(current_test + settings['db_tests']) + " - Set " + str(saved) + " (" + str(int(size / 1024)) + " kb) - Took " + str(int(finish_time)) + "s - Avg Rate " + str(int(rate) * len(settings['software'])) + " - ETC " + str(int(time_left)) + "'")
		current_test += settings['db_tests']
		# break  # uncomment if you want to run just one cycle of the fuzzer for debugging purposes
	settings['queue'].stop_web_server()


def help(err=""):
	"""Print a help screen and exit"""
	if err:
		print("Error: %s\n" % err)
	print("XDiFF Syntax: ")
	print(os.path.basename(__file__) + " -d db.sqlite       Choose the database")
	print("\t     -c Python          Software category to be fuzzed")
	print("\t     [-D]               Print debugging information")
	print("\t     [-r 0]             Random inputs: radamsa & zzuf without newlines (faster)")
	print("\t     [-r 1]             Random inputs: radamsa & zzuf with newlines (slower)")
	print("\t     [-r 2]             Random inputs: radamsa without newlines (faster)")
	print("\t     [-r 3]             Random inputs: radamsa with newlines (slower)")
	print("\t     [-r 4]             Random inputs: zzuf without newlines (faster)")
	print("\t     [-r 5]             Random inputs: zzuf with newlines (slower)")
	print("\t     [-s software.ini]  Configuration file for software to be fuzzed")
	print("\t     [-t 100]           Threads executed in parallel")
	print("\t     [-T 10]            Timeout per thread")
	print("\t     [-v]               Use valgrind")
	sys.exit()


def main():
	"""Fuzz something FFS!"""
	def signal_handler(signal, frame):
		"""Catch SIGINT and do some cleaning before termination"""
		settings['monitor'].remove_stuff()
		settings['queue'].stop_web_server()
		settings['logger'].info("Program terminated")
		sys.exit(1)
	signal.signal(signal.SIGINT, signal_handler)

	try:
		opts, args = getopt.getopt(sys.argv[1:], "hc:d:Dr:s:t:T:v", ["help", "category=", "database=", "random=", "software=", "threads=", "timeout=", "valgrind"])
	except getopt.GetoptError as err:
		help(err)
	settings = {}
	for o, a in opts:
		if o in ("-h", "--help"):
			help()
		elif o in ("-c", "--category"):
			settings['fuzz_category'] = a
		elif o in ("-d", "--database"):
			settings['db_file'] = os.path.abspath(a)
		elif o in ("-D"):
			settings['loglevel'] = 'debug'
		elif o in ("-r", "--random"):
			settings['generate_tests'] = int(a)
		elif o in ("-s", "--software"):
			settings['software'] = os.path.abspath(a)
		elif o in ("-t", "--threads"):
			settings['db_tests'] = int(a)
		elif o in ("-T", "--timeout"):
			settings['timeout'] = int(a)
		elif o in ("-v", "--valgrind"):
			settings['valgrind'] = True

	if "db_file" not in settings or "fuzz_category" not in settings:
		help("The -d and -c parameters are mandatory")
	else:
		dfuzz(settings)


if __name__ == "__main__":
	main()
