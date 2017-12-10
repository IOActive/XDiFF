from __future__ import print_function
from __future__ import absolute_import
import getpass
import logging
import os
import random
import sys
from queue import Queue
from dbaction import Dbaction
from .dbsqlite import DbSqlite
from .monitor import Monitor


def define_software(settings):
	"""The software gets loaded in a dictionary"""
	software = []
	if "software" in settings and "fuzz_category" in settings:
		Category = None
		software_file = open(settings['software'], "r")
		for line in software_file:
			line = line.strip()
			if line[:1] != "#":  # parse lines that are not comments
				if line[:1] == "[" and line[len(line) - 1:len(line)] == "]":  # is this a category?
					Category = line[1:len(line) - 1]
					Type = Suffix = None
					OS = []
				if Category == settings['fuzz_category']:
					if line[:2] == "OS" or line[:4] == "Type" or line[:6] == "Suffix":
						exec(line)
						if OS is not None and sys.platform not in OS:
							OS = None
					else:
						if line.find('=') != -1 and OS is not None:
							if Type is None:
								Type = ["CLI"]
							if Suffix is None:
								Suffix = [""]
							item = {}
							item['category'] = Category
							item['type'] = Type
							item['suffix'] = Suffix
							item['name'] = line[:line.find('=')].strip()
							if 'valgrind' in settings and settings['valgrind']:
								item['execute'] = eval('["valgrind", "-q", ' + line[line.find('=') + 1:].strip()[1:])
							else:
								item['execute'] = eval(line[line.find('=') + 1:].strip())
							item['softwareid'] = settings['db'].get_software_id(item)
							software.append(item)
	return software


def load_settings(settings):
	"""Define global settings"""
	if "db_file" not in settings:
		print("Error: The database selected is not a valid file")
		sys.exit()

	settings['version'] = "1.1.1"
	logging.basicConfig(filename='fuzz.log', level=logging.INFO, format='%(asctime)s %(levelname)s %(module)s: %(message)s', datefmt='%Y-%m-%d %H.%M.%S')
	console = logging.StreamHandler()
	console.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(module)s: %(message)s'))
	settings['logger'] = logging.getLogger('fuzzer')
	settings['logger'].addHandler(console)

	settings['soft_limit'] = 250       # maximum limit for the output of stdout & stderr
	settings['soft_bypass'] = ["canarytoken", getpass.getuser(), "root", "/usr", "/bin", "PATH", "core dump", "egmentation fault", "== "]  # exceptions for the soft_limit setting
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
	settings['db'] = DbSqlite(settings, settings['db_file'])
	if "db_tests" not in settings:
		settings['db_tests'] = 100  # save the results in the database every X tests
	if "software" not in settings:
		settings['software'] = os.path.abspath("software.ini")  # software definitions
	if "timeout" not in settings:
		settings['timeout'] = 10    # default timeout for threads in seconds
	settings['kill_status'] = {"not_killed": settings['db'].get_constant_value("kill_status", "not killed"), "requested": settings['db'].get_constant_value("kill_status", "requested"), "killed": settings['db'].get_constant_value("kill_status", "killed"), "not_found": settings['db'].get_constant_value("kill_status", "not found")}

	settings['software'] = define_software(settings)  # load the software and find potential inconsistencies
	settings['queue'] = Queue(settings)               # prepare the fuzzer and the webserver to interact
	settings['monitor'] = Monitor(settings)           # instantiate the monitor object
	settings['dbaction'] = Dbaction(settings)         # instantiate the dbaction object

	# Monitor
	settings['canaryfile'] = "canaryfile"
	settings['canaryfiletoken'] = "canarytokenfilelocal"  # contents of settings['canaryfile']
	settings['canaryexec'] = "canaryfile.bat"
	settings['canaryexectoken'] = "canarytokencommand"    # contents of settings['canaryexec']
	settings['canaryhost'] = "127.0.0.1:" + str(settings['webserver_port'])
	settings['canaryfileremote'] = "canarytokenfileremote"

	# Analyze
	settings['output_width'] = 130

	return settings
