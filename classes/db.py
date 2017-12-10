class Db(object):
	"""High level DB class: other databases could used this general set of queries"""
	def __init__(self, settings):
		self.db_connection = None
		self.db_cursor = None
		self.restrict_software = ""
		self.settings = settings

	def commit(self):
		"""Save changes to the database"""
		self.db_connection.commit()

	def get_fuzz_testcase(self):
		"""Get the fuzz testcases """
		results = []
		try:
			self.db_cursor.execute("SELECT testcase FROM fuzz_testcase")
			results = self.db_cursor.fetchall()
			self.settings['logger'].debug("Testcases read: %s " % str(len(results)))
		except Exception as e:
			self.settings['logger'].critical("Exception when trying to retrieve information from fuzz_testcase")
		if len(results) == 0:
			self.settings['logger'].warning("No testcases defined")
		return results

	def get_functions(self):
		"""Get the name of the functions"""
		results = []
		try:
			self.db_cursor.execute("SELECT function FROM function")
			results = self.db_cursor.fetchall()
			self.settings['logger'].debug("Functions read: %s " % str(len(results)))
		except Exception as e:
			self.settings['logger'].critical("Exception when trying to retrieve information from function")
		if len(results) == 0:
			self.settings['logger'].warning("No functions defined")
		return results

	def get_values(self):
		"""Get the fuzzing values"""
		results = []
		try:
			self.db_cursor.execute("SELECT value FROM value")
			results = self.db_cursor.fetchall()
			self.settings['logger'].debug("Values read: %s " % str(len(results)))
		except Exception as e:
			self.settings['logger'].critical("Exception when trying to retrieve information from value: %s" % str(e))
		return results

	def list_software(self, active=None):
		"""Get the list of [active] software used with testcases"""
		results = []
		if active is True:
			active = "WHERE s.id IN (SELECT DISTINCT(r.softwareid) FROM fuzz_testcase_result AS r WHERE 1 = 1 " + self.restrict_software + ")"
		else:
			active = "WHERE 1 = 1 " + self.restrict_software.replace("r.softwareid", "s.id")
		try:
			self.db_cursor.execute("SELECT s.id, s.name, s.type, s.os FROM fuzz_software AS s " + active + " ORDER BY s.name ASC")
			results = self.db_cursor.fetchall()
		except Exception as e:
			self.settings['logger'].critical("Exception when trying to list software")
		return results

	def set_software(self, softwareids):
		"""Restrict the results to certain software ids"""
		if softwareids:
			self.restrict_software = " AND r.softwareid IN (" + ",".join(softwareids) + ") "
		else:
			self.restrict_software = ""

	def get_software(self):
		"""Get the current software ids restriction"""
		return self.restrict_software

	def get_software_type(self, type):
		"""Get the software ids associated to a certain category type"""
		results = []
		try:
			self.db_cursor.execute("SELECT s.id FROM fuzz_software AS s WHERE s.type = '" + type + "' " + self.restrict_software.replace("r.softwareid", "s.id") + " ORDER BY s.name")
			results = self.db_cursor.fetchall()
		except Exception as e:
			self.settings['logger'].critical("Exception when trying to get software type")
		return results

	def list_results(self, lowerlimit=0, toplimit=-1):
		"""Get a list of the fuzzed results"""
		results = []
		if toplimit is None:
			toplimit = -1
		try:
			self.db_cursor.execute("SELECT t.testcase, s.name, s.type, s.os, r.stdout, r.stderr, c.name FROM fuzz_testcase_result AS r, fuzz_software AS s, fuzz_testcase AS t, fuzz_constants AS c WHERE t.id >= " + str(lowerlimit) + " AND r.softwareid = s.id AND r.testcaseid = t.id AND c.type = 'kill_status' AND c.id = r.kill_status " + self.restrict_software + " ORDER BY r.testcaseid LIMIT " + str(int(toplimit)))
			results = self.db_cursor.fetchall()
		except Exception as e:
			self.settings['logger'].critical("Exception when trying to list results")
		return results

	def list_killed_results(self):
		"""Get a list of the killed fuzzed results"""
		self.db_cursor.execute("SELECT t.testcase, s.name, s.type, s.os, r.stdout, r.stderr, c.name FROM fuzz_testcase_result AS r, fuzz_software AS s, fuzz_testcase AS t, fuzz_constants AS c WHERE r.softwareid = s.id AND r.testcaseid = t.id AND c.type = 'kill_status' AND c.id = r.kill_status AND c.name != 'not killed' " + self.restrict_software + " ORDER BY r.testcaseid ")
		return self.db_cursor.fetchall()

	def count_results(self, lowerlimit=0, toplimit=-1):
		"""Get a count of how many testcases where fuzzed"""
		if toplimit is None:
			toplimit = -1
		self.db_cursor.execute("SELECT COUNT(r.testcaseid) FROM fuzz_testcase_result AS r WHERE 1=1 " + self.restrict_software + " ORDER BY r.testcaseid LIMIT " + str(int(toplimit)) + " OFFSET " + str(int(lowerlimit)))
		return self.db_cursor.fetchone()[0]

	def list_return_code_per_software(self):
		"""Get the count of returncodes for each piece of software"""
		results = []
		try:
			self.db_cursor.execute("SELECT s.name, s.type, s.os, r.returncode, COUNT(r.returncode) FROM fuzz_testcase_result AS r, fuzz_testcase AS t, fuzz_software AS s WHERE t.id = r.testcaseid and s.id = r.softwareid AND r.returncode != '' " + self.restrict_software + " GROUP BY r.returncode,s.name ORDER BY s.name, r.returncode;")
			results = self.db_cursor.fetchall()
		except Exception as e:
			self.settings['logger'].critical("Exception when trying to list return code per software")
		return results

	def analyze_specific_return_code(self, returncodes):
		"""Get the testcases that matches the return code"""
		results = []
		returncodes = " AND r.returncode IN (" + ",".join(returncodes) + ") "
		try:
			self.db_cursor.execute("SELECT t.testcase, s.name, s.type, s.os, r.returncode, r.stdout, r.stderr FROM fuzz_testcase_result AS r, fuzz_testcase AS t, fuzz_software AS s WHERE t.id = r.testcaseid and s.id = r.softwareid AND r.returncode != '' " + self.restrict_software + returncodes + " ORDER BY s.name, r.returncode")
			results = self.db_cursor.fetchall()
		except Exception as e:
			self.settings['logger'].critical("Exception when trying to analyze specific return code")
		return results

	def analyze_return_code_differences(self):
		"""Find testcases where the return code was different depending on the input"""
		results = []
		try:
			self.db_cursor.execute("SELECT t.testcase, s.name, s.type, r.returncode, r.stdout, r.stderr FROM fuzz_testcase AS t, fuzz_software AS s, fuzz_testcase_result AS r WHERE r.softwareid = s.id AND r.testcaseid = t.id AND r.returncode != '' " + self.restrict_software + " ORDER BY r.testcaseid")
			results = self.db_cursor.fetchall()
		except Exception as e:
			self.settings['logger'].critical("Exception when trying to analyze the return code differences")
		return results

	def count_software(self):
		"""Count how many different pieces of software have been tested"""
		results = None
		try:
			self.db_cursor.execute("SELECT COUNT(DISTINCT(id)) FROM fuzz_testcase_result AS r, fuzz_software AS s WHERE r.softwareid = s.id")
			results = self.db_cursor.fetchone()[0]
		except Exception as e:
			self.settings['logger'].critical("Exception when trying to count the amount of software: %s" % str(e))
		return results

	def count_testcases(self):
		"""Count how many testcases are available"""
		results = None
		try:
			self.db_cursor.execute("SELECT COUNT(testcase) FROM fuzz_testcase")
			results = self.db_cursor.fetchone()[0]
		except Exception as e:
			self.settings['logger'].critical("Exception when trying to count the amount of test cases: %s" % str(e))
		return results

	def count_reference(self, reference):
		"""Count how many testcases matching the reference are available"""
		self.db_cursor.execute("SELECT COUNT(testcase) FROM fuzz_testcase WHERE testcase LIKE '%" + reference + "%'")
		query = self.db_cursor.fetchone()
		return query[0]

	def analyze_canary_file(self):
		"""Get all stdout/stderr references of canary files that were not originally used on the testcase"""
		results = []
		try:
			self.db_cursor.execute("SELECT t.testcase, s.name, s.type, s.os, r.stdout, r.stderr FROM fuzz_testcase_result AS r, fuzz_software AS s, fuzz_testcase AS t WHERE r.softwareid = s.id AND r.testcaseid = t.id AND t.testcase NOT LIKE '%canaryfile%' AND (r.stdout LIKE '%canaryfile%' OR r.stderr LIKE '%canaryfile%') " + self.restrict_software)
			results = self.db_cursor.fetchall()
		except Exception as e:
			self.settings['logger'].critical("Exception when trying to analyze the canary file")
		return results

	def analyze_top_elapsed(self, killed):
		"""Find which software took more time (whether they were killed or not)"""
		results = []
		if killed is None:
			killed = ""
		elif killed is False:
			killed = " AND c.name = 'not killed' "
		elif killed is True:
			killed = " AND c.name != 'not killed' "
		try:
			self.db_cursor.execute("SELECT t.testcase, s.name, s.type, s.os, r.elapsed FROM fuzz_testcase_result AS r, fuzz_software AS s, fuzz_testcase AS t, fuzz_constants AS c WHERE r.softwareid = s.id AND r.testcaseid = t.id  AND c.type = 'kill_status' AND c.id = r.kill_status " + killed + self.restrict_software + " ORDER BY r.elapsed DESC")
			results = self.db_cursor.fetchall()
		except Exception as e:
			self.settings['logger'].critical("Exception when trying to analyze the top time elapsed")
		return results

	def analyze_killed_differences(self):
		"""Find which testcases were required to be killed AND were also not killed (loop vs no loop for others)"""
		results = []
		try:
			self.db_cursor.execute("SELECT t.testcase, s.name, s.type, s.os, c.name, r.stdout, r.stderr FROM fuzz_testcase AS t, fuzz_software AS s, fuzz_testcase_result AS r, fuzz_constants AS c WHERE r.softwareid = s.id AND r.testcaseid = t.id AND c.type = 'kill_status' AND r.kill_status = c.id " + self.restrict_software + " ORDER BY r.testcaseid")
			results = self.db_cursor.fetchall()
		except Exception as e:
			self.settings['logger'].critical("Exception when trying to analyze differences when killing software")
		return results

	def analyze_same_software(self):
		"""Find testcases when the same software produces different results when using different inputs (ie, Node_CLI vs Node_File) """
		results = []
		try:
			self.db_cursor.execute("SELECT t.testcase, s.name, s.type, r.stdout FROM fuzz_testcase_result AS r, fuzz_software AS s, fuzz_testcase AS t WHERE r.softwareid = s.id AND r.testcaseid = t.id " + self.restrict_software + " ORDER BY r.testcaseid, s.name")
			results = self.db_cursor.fetchall()
		except Exception as e:
			self.settings['logger'].critical("Exception when trying to analyze the same software")
		return results

	def analyze_stdout(self, lowerlimit, upperlimit):
		"""Finds testcases that produce the same output"""
		results = []
		try:
			self.db_cursor.execute("SELECT t.testcase, s.name, s.type, r.stdout, s.category, s.os,t.id FROM fuzz_testcase_result AS r, fuzz_software AS s, fuzz_testcase AS t WHERE r.softwareid = s.id AND r.testcaseid = t.id AND r.stdout != '' AND r.testcaseid >= " + str(lowerlimit) + " AND r.testcaseid <= " + str(upperlimit) + self.restrict_software + " ORDER BY r.testcaseid")
			results = self.db_cursor.fetchall()
		except Exception as e:
			self.settings['logger'].critical("Exception when trying to analyze the stdout")
		return results

	def analyze_same_stdout(self):
		"""Used to analyze when different testcases are producing the same output"""
		results = []
		try:
			self.db_cursor.execute("SELECT t.testcase, s.name, s.type, s.os, r.stdout FROM fuzz_testcase_result AS r, fuzz_testcase AS t, fuzz_software AS s WHERE r.softwareid = s.id AND r.testcaseid = t.id AND r.stdout in (SELECT DISTINCT(r2.stdout) FROM fuzz_testcase_result AS r2, fuzz_testcase AS t2 WHERE r2.testcaseid = t2.id AND r2.stdout != '' ) " + self.restrict_software + " ORDER BY r.stdout, s.name")
			results = self.db_cursor.fetchall()
		except Exception as e:
			self.settings['logger'].critical("Exception when trying to analyze the same stdout")
		return results

	def analyze_string_disclosure(self, searchme, excludeme="", excludecli=""):
		"""Return stdout and stderr values containing a specific string"""
		results = []
		if excludeme != "":
			excludeme = " AND r.stdout NOT LIKE '%" + excludeme + "%' AND r.stderr NOT LIKE '%" + excludeme + "%' "
		if excludecli != "":
			excludecli = " AND s.type = 'File' "
		try:
			self.db_cursor.execute("SELECT t.testcase, s.name, s.type, s.os, r.stdout, r.stderr, r.returncode FROM fuzz_testcase_result AS r, fuzz_software AS s, fuzz_testcase AS t WHERE r.softwareid = s.id AND r.testcaseid = t.id AND (r.stdout LIKE '%" + searchme + "%' OR r.stderr LIKE '%" + searchme + "%' ESCAPE '_')" + excludeme + excludecli + self.restrict_software)
			results = self.db_cursor.fetchall()
		except Exception as e:
			self.settings['logger'].critical("Exception when trying to analyze the string disclosure")
		return results

	def analyze_remote_connection(self, searchme=""):
		"""Get the remote connections established"""
		results = []
		try:
			self.db_cursor.execute("SELECT t.testcase, s.name, s.type, s.os, r.stdout, r.stderr, r.network FROM fuzz_testcase_result AS r, fuzz_software AS s, fuzz_testcase AS t WHERE r.softwareid = s.id AND r.testcaseid = t.id AND r.network !='' AND (r.stdout LIKE '%" + searchme + "%' OR r.stderr LIKE '%" + searchme + "%' ESCAPE '_')" + self.restrict_software)
			results = self.db_cursor.fetchall()
		except Exception as e:
			self.settings['logger'].critical("Exception when trying to analyze remote connections")
		return results

	def analyze_output_messages(self, messages):
		"""Get the results that produced error messages"""
		self.db_cursor.execute("SELECT t.testcase, s.name, s.type, s.os, r.returncode, r." + messages + " FROM fuzz_testcase_result AS r, fuzz_software AS s, fuzz_testcase AS t WHERE r.softwareid = s.id AND r.testcaseid = t.id AND r." + messages + " !='' " + self.restrict_software)  # sqli ftw!
		return self.db_cursor.fetchall()

	def analyze_elapsed(self):
		"""Analize the total time required for each piece of software"""
		results = []
		try:
			self.db_cursor.execute("SELECT s.name, s.type, s.os, SUM(r.elapsed) FROM fuzz_testcase_result AS r, fuzz_software AS s WHERE r.softwareid = s.id GROUP BY r.softwareid")
			results = self.db_cursor.fetchall()
		except Exception as e:
			self.settings['logger'].critical("Exception when trying to analyze time elapsed")
		return results

	def get_rows(self, table):
		"""Return all the rows from a certain given table"""
		results = None
		try:
			self.db_cursor.execute("SELECT * FROM " + table)
			results = self.db_cursor.fetchall()
		except Exception as e:
			self.settings['logger'].critical("Exception when trying to return the rows from the table %s:" % (table, str(e)))
		return results
