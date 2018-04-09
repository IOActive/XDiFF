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
import threading
import os.path
import compat

try:                 # Python 2
	from SimpleHTTPServer import SimpleHTTPRequestHandler
	import BaseHTTPServer
	import urlparse
except ImportError:  # Python 3
	from http.server import SimpleHTTPRequestHandler
	from http.server import BaseHTTPRequestHandler, HTTPServer
	from urllib.parse import urlparse


class BaseHandler(SimpleHTTPRequestHandler):
	"""Changes a few things from SimpleHTTPServer to handle requests"""
	my_class = None  # type:BaseHandler

	def log_message(self, format, *args):
		"""Avoid SimpleHTTPServer logs"""
		pass

	def do_GET(self):
		"""Handle GET requests to parse parameters and save the responses to the corresponding ids"""
		# self.my_class.settings['logger'].debug("URL: %s Query: %s", str(url), str(query))
		data = compat.unicode("GET " + str(self.path) + "\n" + str(self.headers), errors='ignore')
		self.do_REQUEST(data)

	def do_POST(self):
		"""Handle GET requests to parse parameters and save the responses to the corresponding ids"""
		# self.my_class.settings['logger'].debug("URL: %s Query: %s", str(url), str(query))
		data = compat.unicode("POST " + str(self.path) + "\n" + str(self.headers), errors='ignore')
		self.do_REQUEST(data)

	def do_REQUEST(self, data):
		"""Handle GET and POST requests to parse parameters and save the responses to the corresponding ids"""
		url = urlparse.urlparse(self.path)
		query = url.query.split('&')
		self.my_class.settings['logger'].debug("%s", data)
		if len(query) > 1:
			# with tag0 we can identify the testcaseid
			tag0 = query[0].split("=")
			# with tag1 we can identify the softwareid
			tag1 = query[1].split("=")
			if tag0[0] == "tag0" and tag1[0] == "tag1":
				testcaseid = None
				softwareid = None
				try:
					testcaseid = int(tag0[1])
				except Exception as e:
					self.my_class.settings['logger'].warning("Tag0 received, but is not a number: %s",e)
				try:
					softwareid = int(tag1[1])
				except Exception as e:
					self.my_class.settings['logger'].warning("Tag1 received, but is not a number: %s",e)
				# if we found a testcaseid and a software id, we can correlate it to the results
				if testcaseid and softwareid:
					# we don't want dupes, check if the request hasn't been issued before
					flag = False
					for x in range(0, len(self.my_class.ids)):
						if self.my_class.ids[x][0] == testcaseid and self.my_class.ids[x][1] == softwareid and self.my_class.ids[x][2] == data:
							flag = True
							break
					if not flag:
						# can we extract the stdout and elapsed data from the url?
						stdout = None
						elapsed = None
						stderr = None
						for parameter in query:
							parameter = parameter.split('=')
							if len(parameter) == 2:
								if parameter[0] == 'stdout':
									stdout = parameter[1]
								elif parameter[0] == 'elapsed':
									elapsed = parameter[1]
								elif parameter[0] == 'stderr':
									stderr = parameter[1]
						self.my_class.ids.append([testcaseid, softwareid, data, stdout, elapsed, stderr])

		self.send_response(200)
		self.send_header("Content-type", "text/html")
		self.end_headers()
		getfile = url[2][1:].split('?')[0]
		if url.path == "/canaryfile":
			self.wfile.write(self.my_class.settings['canaryfileremote'])
		elif os.path.isfile(getfile):
			content = open(getfile, "r")
			self.wfile.write(content.read())


class WebServer(object):
	"""Used to parse HTTP connections"""
	def __init__(self, settings):
		self.settings = settings
		self.server = None

	def start_web_server(self):
		"""Web server: load simplehttpserver as a thread and continue execution"""
		BaseHandler.my_class = self
		self.server = BaseHTTPServer.HTTPServer(("127.0.0.1", self.settings['webserver_port']), BaseHandler)
		thread = threading.Thread(target=self.server.serve_forever)
		thread.daemon = True
		self.settings['logger'].debug("Loading web server using port %s" % str(self.settings['webserver_port']))
		try:
			thread.start()
		except KeyboardInterrupt:
			self.stop_web_server()

	def stop_web_server(self):
		"""Web server shutdown when closing the fuzzer"""
		if self.server:
			self.settings['logger'].debug("Shutting down Web Server...")
			self.server.shutdown()
