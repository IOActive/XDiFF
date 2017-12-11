import BaseHTTPServer
import SimpleHTTPServer
import threading
import urlparse
import os.path
import sys


# Use str() instead of unicode() for Python 3
if sys.version_info[0] == 3:
	def unicode(value, errors=None):
		return str(value)


class BaseHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
	"""Changes a few things from SimpleHTTPServer to handle requests"""
	my_class = None

	def log_message(self, format, *args):
		"""Avoid SimpleHTTPServer logs"""
		pass

	def do_GET(self):
		"""Handle GET requests to parse parameters and save the responses to the corresponding ids"""
		url = urlparse.urlparse(self.path)
		self.my_class.settings['logger'].debug("Query: %s " % str(url))
		query = url.query.split('&')
		if url.path == "/canaryfile" and url.query == "monitor":
			self.send_response(200)
			self.send_header("Content-type", "text/html")
			self.end_headers()
			self.wfile.write(self.my_class.settings['canaryfileremote'])
			return
		if len(query) > 1:
			testcaseid = query[0].split("=")
			softwareid = query[1].split("=")
			if testcaseid[0] == "tag0" and softwareid[0] == "tag1":
				testcaseid[1] = int(testcaseid[1])
				softwareid[1] = int(softwareid[1])
				data = unicode(str(url), errors='ignore')

				flag = False  # we don't want dupes, check if the request hasn't been issued before
				for x in range(0, len(self.my_class.ids)):
					if self.my_class.ids[x][0] == testcaseid[1] and self.my_class.ids[x][1] == softwareid[1] and self.my_class.ids[x][2] == data:
						flag = True
						break
				if not flag:
					self.my_class.ids.append([testcaseid[1], softwareid[1], data])
					self.my_class.settings['logger'].debug("Query: %s" % str(url.query))

		getfile = url[2][1:].split('?')[0]
		if os.path.isfile(getfile):
			self.send_response(200)
			self.send_header("Content-type", "text/html")
			self.end_headers()
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
		self.settings['logger'].info("Loading web server using port %s" % str(self.settings['webserver_port']))
		try:
			thread.start()
		except KeyboardInterrupt:
			self.stop_web_server()

	def stop_web_server(self):
		"""Web server shutdown when closing the fuzzer"""
		if self.server:
			self.settings['logger'].info("Shutting down Web Server...")
			self.server.shutdown()
