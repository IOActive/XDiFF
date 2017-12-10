from __future__ import absolute_import
from .fuzzer import Fuzzer
from .webserver import WebServer


class Queue(Fuzzer, WebServer):
	"""Used to share information between executions and the webserver"""
	def __init__(self, settings):
		self.ids = []
		Fuzzer.__init__(self, settings, self.ids)
		WebServer.__init__(self, settings)
