import os
import sqlite3
import sys
import time
import db

class DbSqlite(db.Db):
	"""Used in conjunction with the class Db, with supposedly specific SQLite content"""
	def __init__(self, settings, db_file):
		super(DbSqlite, self).__init__(settings)
		self.settings['db_file'] = db_file
		try:
			self.db_connection = sqlite3.connect(self.settings['db_file'])
			self.db_cursor = self.db_connection.cursor()
			self.db_connection.execute("PRAGMA journal_mode = OFF")
			self.db_connection.execute("PRAGMA synchronous = OFF")
			self.db_connection.execute("PRAGMA temp_store = MEMORY")
			self.db_connection.execute("PRAGMA count_changes = OFF")
			#self.db_connection.text_factory = lambda x: x.decode("utf-8", "ignore") # python3
		except Exception as e:
			self.settings['logger'].critical("Exception when initializing the database: %s" % str(e))
			sys.exit()

	def create_table(self):
		"""Create and define initial values for the tables"""
		self.db_cursor.execute('CREATE TABLE IF NOT EXISTS fuzz_software (id INTEGER PRIMARY KEY, name TEXT, type TEXT, suffix TEXT, execute TEXT, os TEXT, category TEXT, UNIQUE(name, type, os))')
		self.db_cursor.execute('CREATE TABLE IF NOT EXISTS fuzz_testcase_result (softwareid INTEGER, testcaseid INTEGER, stdout TEXT, stderr TEXT, network TEXT, returncode TEXT, elapsed TEXT, kill_status TEXT, UNIQUE(softwareid, testcaseid))')
		self.db_cursor.execute('CREATE TABLE IF NOT EXISTS fuzz_constants (id INTEGER PRIMARY KEY, type TEXT, name TEXT)')
		self.db_cursor.execute('CREATE TABLE IF NOT EXISTS fuzz_testcase (id INTEGER PRIMARY KEY, testcase BLOB UNIQUE)')
		self.db_cursor.execute('CREATE TABLE IF NOT EXISTS function (function BLOB UNIQUE)')
		self.db_cursor.execute('CREATE TABLE IF NOT EXISTS value (value BLOB UNIQUE)')
		self.db_cursor.execute("SELECT id FROM fuzz_constants WHERE type = 'kill_status'")
		if self.db_cursor.fetchone() is None:
			self.db_cursor.execute("INSERT INTO fuzz_constants (type, name) VALUES ('kill_status', 'not killed')")
			self.db_cursor.execute("INSERT INTO fuzz_constants (type, name) VALUES ('kill_status', 'requested')")
			self.db_cursor.execute("INSERT INTO fuzz_constants (type, name) VALUES ('kill_status', 'killed')")
			self.db_cursor.execute("INSERT INTO fuzz_constants (type, name) VALUES ('kill_status', 'not found')")
			self.commit()

	def get_software_id(self, piece):
		"""Return the software id using all the data associated to software: name, type, suffix, execution and category"""
		self.db_cursor.execute("select name from sqlite_master where type='table' and name='fuzz_software'")
		if self.db_cursor.fetchone() is None:
			self.settings['logger'].critical("Error: the fuzz_software table was not found. Where the testcases generated with dbaction.py?")
			sys.exit()
		self.db_cursor.execute("INSERT OR IGNORE INTO fuzz_software (name, type, suffix, execute, os, category) VALUES (:name, :type, :suffix, :execute, :os, :category)", {"name": piece['name'], "type": ','.join(piece['type']), "suffix": ','.join(piece['suffix']), "execute": str(piece['execute']), "os": str(sys.platform), "category": piece['category']})
		self.commit()
		self.db_cursor.execute("SELECT id FROM fuzz_software WHERE name=:name AND type=:type AND suffix=:suffix AND execute=:execute AND category=:category", {"name": piece['name'], "type": ','.join(piece['type']), "suffix": ','.join(piece['suffix']), "execute": str(piece['execute']), "category": piece['category']})
		softwareid = self.db_cursor.fetchone()
		# UNIQUE Constraint: fuzz_software.name, fuzz_software.type, fuzz_software.os
		if softwareid is None:
			print "Error: there was no software found. Is there a unique name, type and os for the fuzzed software ?"
			sys.exit()
		return softwareid[0]

	def get_constant_value(self, constant_type, constant_name):
		"""Return constant value for a certain constant type and name"""
		self.db_cursor.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'fuzz_constants'")
		value = self.db_cursor.fetchone()
		if value is None:
			return None # table does not exists
		self.db_cursor.execute("SELECT id FROM fuzz_constants WHERE type=:type AND name=:name", {"type": constant_type, "name": constant_name})
		value = self.db_cursor.fetchone()
		if value is not None:
			value = value[0]
		return value

	def get_latest_id(self, software):
		"""Return the latest testcase id stored in the database"""
		ids = []
		for piece in software:
			ids.append(str(piece['softwareid']))
		try:
			self.db_cursor.execute("SELECT testcaseid FROM fuzz_testcase_result WHERE softwareid IN (" + ",".join(ids) + ") ORDER BY testcaseid DESC LIMIT 1") # lazy sqli everywhere ftw
			latestid = self.db_cursor.fetchone()
		except Exception as e:
			self.settings['logger'].critical("Exception when trying to retrieve the latest id: %s " % str(e))
			sys.exit()
		if latestid is None:
			latestid = 0
		else:
			latestid = latestid[0] + 1
		return latestid

	def get_test(self, latest_id, limit):
		"""compiles test cases for fuzzing"""
		tests = []
		try:
			self.db_cursor.execute("SELECT id, testcase FROM fuzz_testcase WHERE id >= :latest_id LIMIT :limit", {"latest_id": str(latest_id), "limit": str(limit)})
			tests = self.db_cursor.fetchall()
			if not tests and 'generate_tests' in self.settings:
				self.settings['queue'].generate_tests(latest_id, limit)
				tests = self.get_test(latest_id, limit)
		except Exception as e:
			self.settings['logger'].critical("Exception when trying to retrieve information from fuzz_testcase: %s" % str(e))
		return tests

	def set_results(self, results):
		"""save fuzzing results"""
		while True:
			try:
				self.db_cursor.execute("SELECT count(testcaseid) FROM fuzz_testcase_result")
				amount = self.db_cursor.fetchone()
				size = os.stat(self.settings['db_file']).st_size
				break
			except:
				pass
		while True:
			# if you are having concurrency with the sqlite database, things may break apart
			try:
				self.db_cursor.executemany("INSERT OR IGNORE INTO fuzz_testcase_result ('softwareid', 'testcaseid', 'stdout', 'stderr', 'network', 'returncode', 'elapsed', 'kill_status') VALUES (:softwareid, :testcaseid, :stdout, :stderr, :network, :returncode, :elapsed, :kill_status)", results)
				self.commit()
				break
			except sqlite3.OperationalError as e:
				self.settings['logger'].warning("Exception when setting the results: %s" % str(e))
				time.sleep(2)
		self.db_cursor.execute("SELECT count(testcaseid) FROM fuzz_testcase_result")
		current_amount = self.db_cursor.fetchone()
		#size = "{:,}".format(os.stat(self.settings['db_file']).st_size - size)
		size = os.stat(self.settings['db_file']).st_size - size
		# return testcases received, the amount of testcases saved, and the size of them
		return ((current_amount[0] - amount[0]), size)

	def set_testcase(self, testcases):
		"""save tests"""
		self.db_cursor.executemany("INSERT OR IGNORE INTO fuzz_testcase ('testcase') VALUES (?)", testcases)
		self.settings['logger'].debug("Testcases saved %s" % str(len(testcases)))
		self.commit()

	def set_values(self, values):
		"""used by migrate.py to save the values"""
		self.db_cursor.executemany("INSERT OR IGNORE INTO value ('value') VALUES (?)", values)
		self.settings['logger'].debug("Values saved %s " % str(len(values)))
		self.commit()

	def set_functions(self, functions):
		"""used by migrate.py to save the functions"""
		self.db_cursor.executemany("INSERT OR IGNORE INTO function ('function') VALUES (?)", functions)
		self.settings['logger'].debug("Functions saved %s " % str(len(functions)))
		self.commit()

	def get_columns(self, table):
		"""Return a table's columns"""
		try:
			self.db_cursor.execute("SELECT * FROM " + table)
			return list(map(lambda x: x[0], self.db_cursor.description))
		except:
			return None

	def insert_row(self, table, column, row):
		"""Insert a row into a table"""
		while True:
			# if you are having concurrency with the sqlite database, things may break apart
			try:
				self.db_cursor.execute("INSERT OR IGNORE INTO " + table + " (" + ",".join(column) + ") VALUES (" + ','.join('?'*len(column)) + ")", row)
				self.commit()
				break
			except Exception as e:
				self.settings['logger'].warning("Exception when trying to insert a row: %s " % str(e))
				time.sleep(2)
		self.commit()
