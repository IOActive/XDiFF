from __future__ import print_function
from __future__ import absolute_import


# Python 2
try:
	unicode

	unicode = unicode

	import cgi


	def escape(value):
		"""Use cgi.escape for Python 2"""
		return cgi.escape(value)
# Python 3
except NameError:
	import html

	def unicode(value, errors=None):  # Python 3
		"""Just return the string an ignore the errors parameter"""
		return str(value)

	def escape(value):
		"""Use html.escape for Python 3"""
		return html.escape(value)
	
	xrange = range