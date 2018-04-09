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
from __future__ import absolute_import
import getpass
import logging
import os
import random
import sys
from xdiff_dbaction import Dbaction
from .queue import Queue
from .dbsqlite import DbSqlite
from .monitor import Monitor


def define_software(settings):
	"""The software gets loaded in a dictionary"""
	software = []
	if "software" in settings and settings['software'] and "fuzz_category" in settings and settings['fuzz_category']:
		Category = None
		if os.path.isfile(settings['software']):
			software_file = open(settings['software'], "r")
			for line in software_file:
				line = line.strip()
				if line[:1] != "#":  # parse lines that are not comments
					if line[:1] == "[" and line[len(line) - 1:len(line)] == "]":  # is this a category?
						Category = line[1:len(line) - 1]
						Type = None
						Suffix = None
						Filename = None
						OS = []
					if Category == settings['fuzz_category']:
						if line[:2] == "OS" or line[:4] == "Type" or line[:6] == "Suffix" or line[:8] == "Filename":
							exec(line)
							if OS is not None and sys.platform not in OS:
								OS = None
						else:
							if line.find('=') != -1 and OS is not None:
								if Type is None:
									Type = ["CLI"]
								if Suffix is None:
									Suffix = [""]
								if Filename is None:
									Filename = [""]
								item = {}
								item['category'] = Category
								item['type'] = Type
								item['suffix'] = Suffix
								item['filename'] = Filename
								item['name'] = line[:line.find('=')].strip()
								if 'valgrind' in settings and settings['valgrind']:
									item['execute'] = eval('["valgrind", "-q", ' + line[line.find('=') + 1:].strip()[1:])
								else:
									item['execute'] = eval(line[line.find('=') + 1:].strip())
								item['softwareid'] = settings['db'].get_software_id(item)
								if item['softwareid']:
									settings['logger'].debug("Software found: %s", str(item))
									software.append(item)
			software_file.close()
		else:
			settings['logger'].error("The settings file %s does not exist", os.path.abspath(settings['software']))
	return software


def set_logger(settings):
	"""Insantiate the logging functionality"""
	logging.basicConfig(filename='fuzz.log', level=logging.INFO, format='%(asctime)s %(levelname)s %(module)s: %(message)s', datefmt='%Y-%m-%d %H.%M.%S')
	console = logging.StreamHandler()
	console.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(module)s: %(message)s'))
	logger = logging.getLogger('fuzzer')
	logger.addHandler(console)
	if 'loglevel' in settings and settings['loglevel'] == 'debug':
		logger.setLevel(logging.DEBUG)
	elif 'loglevel' in settings and settings['loglevel'] == 'critical':
		logger.setLevel(logging.CRITICAL)
	return logger


def load_settings(settings):
	"""Define global settings"""
	settings['logger'] = set_logger(settings)
	# Run
	settings['version'] = "1.2.0 (HITB Edition)"
	settings['soft_limit'] = 250       # maximum limit for the output of stdout & stderr
	settings['soft_bypass'] = ["canarytoken", getpass.getuser(), "root", "/usr", "/bin", "PATH", "== "]  # exceptions for the soft_limit setting
	settings['hard_limit'] = 1024      # maximum hard limit, regardless of the soft_limit & soft_bypass
	# settings['hard_limit_lines'] = 1 # maximum line limit in the output
	settings['tmp_prefix'] = "chkF_"   # prefix for temporary files created

	if sys.platform in ["darwin"]:
		settings['tmp_dir'] = "/Volumes/ramdisk/"
		settings['tmp_dir_howto'] = "diskutil erasevolume HFS+ 'ramdisk' `hdiutil attach -nomount ram://838860`"
	elif sys.platform == "win32":
		settings['tmp_dir'] = "X:\\"
		settings['tmp_dir_howto'] = "imdisk -a -s 512M -m X: -p \"/fs:ntfs /q/y\"; notepad \"C:\Windows\System32\canaryfile.bat\": @echo off; echo canarytokencommand"
	elif sys.platform == "linux2" or sys.platform == "freebsd11":
		settings['tmp_dir'] = "/mnt/ramdisk/"
		settings['tmp_dir_howto'] = "mkdir /mnt/ramdisk; mount -t tmpfs -o size=512m tmpfs /mnt/ramdisk; echo \"tmpfs /mnt/ramdisk tmpfs nodev,nosuid,noexec,nodiratime,size=512M 0 0\" >> /etc/fstab"
	settings['webserver_port'] = random.randrange(10000, 65535)  # dynamic web server port: crashes in the same port may interfere
	# settings['webserver_port'] = 8000                          # sometimes you just need a fixed value
	if "db_file" not in settings:
		settings["db_file"] = None
	settings['db'] = DbSqlite(settings, settings['db_file'])
	if settings['db'].db_connection:
		settings['kill_status'] = {"not_killed": settings['db'].get_constant_value("kill_status", "not killed"), "requested": settings['db'].get_constant_value("kill_status", "requested"), "killed": settings['db'].get_constant_value("kill_status", "killed"), "not_found": settings['db'].get_constant_value("kill_status", "not found")}
	if "db_tests" not in settings:
		settings['db_tests'] = 100  # save the results in the database every X tests
	if "software" not in settings:
		settings['software'] = os.path.abspath("software.ini")  # software definitions
	if "timeout" not in settings:
		settings['timeout'] = 10    # default timeout for threads in seconds

	settings['software'] = define_software(settings)  # load the software and find potential inconsistencies
	settings['queue'] = Queue(settings)               # prepare the fuzzer and the webserver to interact
	settings['monitor'] = Monitor(settings)           # instantiate the monitor object
	settings['dbaction'] = Dbaction(settings)         # instantiate the dbaction object

	# Fuzzer
	if "generate_multiplier" not in settings:
		settings['generate_multiplier'] = 100  # multiply the testcase limit by this number to generate new test cases

	# Monitor
	settings['lowerlimit'] = 200  # minimum free space in megabytes
	settings['canaryfile'] = "canaryfile"
	settings['canaryfiletoken'] = "canarytokenfilelocal"  # contents of settings['canaryfile']
	settings['canaryexec'] = "canaryfile"
	settings['canaryexectoken'] = "canarytokencommand"    # contents of settings['canaryexec']
	settings['canaryhost'] = "127.0.0.1:" + str(settings['webserver_port'])
	settings['canaryfileremote'] = "canarytokenfileremote"

	# Analyze
	settings['output_width'] = 130
	settings['testcase_limit'] = 200  # a low number will help with RAM comsumption when performing queries against big databases
	if "output_type" not in settings:
		settings["output_type"] = "html"  # default output type
	settings["print_risk"] = False    # print the risk?
	if "minimum_risk" not in settings:
		settings["minimum_risk"] = 0      # defaul minimum risk
	settings["max_results"] = 999999999    # ridiculous high number to get all the occurrences of a function
	if settings['db_file']:
		settings['output_file'] = settings['db_file'] + "." + settings['output_type']
	settings['error_disclosure'] = ["Exception", "stack trace", "core dump", "egmentation fault", "Traceback"]
	settings['soft_bypass'].extend(settings['error_disclosure'])

	return settings
