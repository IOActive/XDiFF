import cgi
import sys

class Dump(object):
	"""Dump the results received in html, txt or csv"""
	def __init__(self, settings):
		self.settings = settings
		self.toggle_table = True

	def get_screen_size(self, columns):
		"""Defines the size of the columns, based on the amount of columns"""
		col0 = 20
		col1 = 9
		size = [None] * len(columns)
		if len(columns) == 1:
			size[0] = self.settings['output_width'] - 3
		elif len(columns) == 2:
			size[0] = col0 # fixed length, meant to be used with the testcase
			size[1] = self.settings['output_width'] - size[0] - 5
		elif len(columns) == 3:
			size[0] = col0 # fixed length, meant to be used with the testcase
			size[1] = col1 # fixed length, meant to be used with the software name
			size[2] = self.settings['output_width'] - size[1] - size[0] - 7
		elif len(columns) == 4:
			size[0] = col0 # fixed length, meant to be used with the testcase
			size[1] = col1 # fixed length, meant to be used with the software name
			size[2] = (self.settings['output_width'] - size[1] - size[0])/2 - 9
			size[3] = self.settings['output_width'] - size[2] - size[1] - size[0] - 9
		elif len(columns) == 5:
			size[0] = col0 # fixed length, meant to be used with the testcase
			size[1] = col1 # fixed length, meant to be used with the software name
			size[2] = (self.settings['output_width'] - size[1] - size[0])/3 - 3
			size[3] = (self.settings['output_width'] - size[1] - size[0])/3 - 3
			size[4] = self.settings['output_width'] - size[3] - size[2] - size[1] - size[0] - 11
		elif len(columns) == 6:
			size[0] = col0 # fixed length, meant to be used with the testcase
			size[1] = col1 # fixed length, meant to be used with the software name
			size[2] = (self.settings['output_width'] - size[1] - size[0])/4 - 3
			size[3] = (self.settings['output_width'] - size[1] - size[0])/4 - 3
			size[4] = (self.settings['output_width'] - size[1] - size[0])/4 - 3
			size[5] = self.settings['output_width'] - size[4] - size[3] - size[2] - size[1] - size[0] - 13
		elif len(columns) == 7:
			size[0] = col0 # fixed length, meant to be used with the testcase
			size[1] = col1 # fixed length, meant to be used with the software name
			size[2] = (self.settings['output_width'] - size[1] - size[0])/5 - 3
			size[3] = (self.settings['output_width'] - size[1] - size[0])/5 - 3
			size[4] = (self.settings['output_width'] - size[1] - size[0])/5 - 3
			size[5] = (self.settings['output_width'] - size[1] - size[0])/5 - 3
			size[6] = self.settings['output_width'] - size[5] - size[4] - size[3] - size[2] - size[1] - size[0] - 15
		elif len(columns) == 8:
			size[0] = col0 # fixed length, meant to be used with the testcase
			size[1] = col1 # fixed length, meant to be used with the software name
			size[2] = (self.settings['output_width'] - size[1] - size[0])/6 - 3
			size[3] = (self.settings['output_width'] - size[1] - size[0])/6 - 3
			size[4] = (self.settings['output_width'] - size[1] - size[0])/6 - 3
			size[5] = (self.settings['output_width'] - size[1] - size[0])/6 - 3
			size[6] = (self.settings['output_width'] - size[1] - size[0])/6 - 3
			size[7] = self.settings['output_width'] - size[6] - size[5] - size[4] - size[3] - size[2] - size[1] - size[0] - 17

		else:
			print "Error: too many columns: ", len(columns)
			sys.exit()
		return size

	def print_text_top_row(self, title, columns):
		"""Print the first row of the table (and then print_text_row and print_text_bottom_row will be used)"""
		size = self.get_screen_size(columns)

		output  = "-" * self.settings['output_width'] + "\n"
		output += "| " + title + " " * (self.settings['output_width']-len(title)-4) + " |\n"
		output += "-" * self.settings['output_width'] + "\n"
		for colid in range(0, len(columns)):
			output += "| {message:{fill}{align}{width}}".format(message=columns[colid][:size[colid]], fill=" ", align='<', width=size[colid])
		output += "|\n"
		output += "-" * self.settings['output_width'] + "\n"
		return output

	def print_text_row(self, columns, results):
		"""Print a row of the table (previously print_text_top_row was used and finally print_text_bottom_row will be used used)"""
		size = self.get_screen_size(columns)

		output = ""
		for result in results:
			if result:
				for row in result:
					for colid in range(0, len(row)):
						message = ""
						if type(row[colid]).__name__ == 'int':
							message = str(row[colid])
						elif type(row[colid]).__name__ == 'buffer':
							message = "<binary>"
						elif type(row[colid]).__name__ != 'NoneType':
							message = row[colid].encode("utf-8")
						output += "| {message:{fill}{align}{width}}".format(message=message.replace('\n', ' ')[:size[colid]], fill=" ", align='<', width=size[colid])
					output += "|\n"
				output += "-" * self.settings['output_width'] + "\n"
		return output

	def print_text_bottom_row(self):
		"""Print the last bottom row of a txt output"""
		return "\n"

	def print_csv_top_row(self, columns):
		"""Print the first row of the csv table (and then print_csv_row will be used)"""
		output = ",".join(columns) + "\n"
		return output

	def print_csv_row(self, results):
		"""Print a row of the table (previously print_text_top_row was used and finally print_text_bottom_row will be used used)"""
		output = ""
		for result in results:
			for row in result:
					for colid in range(0, len(row)):
						if type(row[colid]).__name__ in ['int', 'NoneType']:
							message = str(row[colid])
						else:
							message = (row[colid]).encode("utf-8")
						if colid != 0:
							output += ","
						output += message
					output +="\n"
		return output

	def print_xml_row(self, title, column, results):
		"""Print a row of the table (previously print_text_top_row was used and finally print_text_bottom_row will be used used)"""
		output = "\t<" + "".join(ch for ch in title if ch.isalnum()) + ">\n"
		for result in results:
			for row in result:
				column_id = 0
				for item in row:
					output += "\t\t<" + cgi.escape(column[column_id]) + ">" + cgi.escape(item) + "</" + cgi.escape(column[column_id]) + ">\n"
					column_id += 1
				output += "\n"
		output += "\t</" + "".join(ch for ch in title if ch.isalnum()) + ">\n"
		return output

	def print_html_top_row(self, title, columns):
		"""Print the first row of the HTML table (and then print_html_row will be used)"""
		output = """<table>
	      <tr>
	        <th><a id='""" + "".join(ch for ch in title if ch.isalnum()) + """Link' onclick="toggleTable('""" + "".join(ch for ch in title if ch.isalnum()) + """Table');" href='#""" + "".join(ch for ch in title if ch.isalnum()) + """'>""" + cgi.escape(title) + """</a><a href="#"><div class="arrow-up">top&nbsp;&nbsp;</div></a></th>
	      </tr>
	    </table>
	    <table id='""" + "".join(ch for ch in title if ch.isalnum()) + """Table'>
	      <tr>"""
		for column in columns:
			output += "<th>" + cgi.escape(column) + "</th>"
		output += "</tr>\n"
		return output

	def print_html_row(self, results):
		"""Print a row of the table (previously print_html_top_row was used and finally print_html_bottom_row will be used used)"""
		output = ""
		cont = 1
		for result in results:
			if cont % 2 == 0:
				trclass = " class='gray'"
			else:
				trclass = ""
			for row in result:
				output += "      <tr" + trclass + ">"
				for item in row:
					output += "<td><div style='white-space: pre-wrap;'>" + cgi.escape(str(item)).encode('ascii', 'xmlcharrefreplace') + "</div></td>"
				output += "</tr>\n"
			cont += 1
		return output

	def print_html_bottom_row(self, title):
		"""Print the first row of the HTML table (and then print_html_row will be used)"""
		output = "</table><br/>\n"
		if title.find("Analyze") != -1 and self.toggle_table:
			output += "<script>toggleTable('" + "".join(ch for ch in title if ch.isalnum()) + "Table');</script>\n"
		return output

	def set_toggle_table(self, toggle):
		"""Set a boolean flag to activate/deactivate if a table will be shown in HTML"""
		self.toggle_table = bool(toggle)

	def pre_general(self, output):
		"""Print any previous code or perform tasks required before printing any table"""
		contents = ""

		if output == "xml":
			contents = "<fuzzer>\n"
		elif output == "html":
			contents = """<!DOCTYPE html>
	<html lang="en">
	  <head>
	    <title>Fuzzer Results for """ + cgi.escape(self.settings['db_file']) + """</title>
	    <meta charset="UTF-8">
	    <style>
	      a {
	        transition: color .3s;
	        color: #265C83;
	        font-size: 16px;
	      }
	      table {
	        font-family: arial, sans-serif;
	        border-collapse: collapse;
	        width: 1200px;
	        #table-layout:fixed;
	        margin-left: auto;
	        margin-right: auto;
	      }
	      td {
	        border: 1px solid #dddddd;
	        text-align: left;
	        padding: 4px;
	        font-size: 12px;
	      }
	      th {
	        border: 1px solid #dddddd;
	        text-align: left;
	        padding: 4px;
	        font-size: 14px;
	      }
	      tr.gray {
	        background-color: #dddddd;
	      }
	      pre {
	        text-align: left;
	        padding: 0px;
	        font-size: 12px;
	        white-space: pre-wrap;
	        white-space: -moz-pre-wrap;
	        white-space: -pre-wrap;
	        white-space: -o-pre-wrap;
	        word-wrap: break-word;
	      }
	      .arrow-up {
	        float: right;
	        font-size: 8px;
	        margin-right: 20px;
	      }
	    </style>
	    <script>
	      function toggleTable(id) {
	        var elem = document.getElementById(id);
	        var hide = elem.style.display == "none";
	        if (hide) {
	          elem.style.display = "table";
	        } 
	        else {
	          elem.style.display = "none";
	        }
	      }
	    </script>
	  </head>
	  <body><a id='#'></a>"""

		if "output_file" in self.settings:
			self.write_file(self.settings['output_file'], 'w+', contents)
		else:
			print contents

	def post_general(self, output):
		"""Print any post code required before wrapping up"""
		contents = ""

		if output == "xml":
			contents = "</fuzzer>"
		elif output == "html":
			contents = "  </body>\n</html>"

		if "output_file" in self.settings:
			self.write_file(self.settings['output_file'], 'a+', contents)
		else:
			print contents

	def general(self, output, title, columns, rows):
		"""Main function to dump stuff: from here, you can export in different formats (txt, csv, xml, html) to the screen or files"""
		if not rows:
			return
		contents = ""
		title = title + " (" + str(len(rows)) + " rows)"

		if output is None:
			return
		elif output == "txt":
			contents  = self.print_text_top_row(title, columns)
			contents += self.print_text_row(columns, rows)
			contents += self.print_text_bottom_row()
		elif output == "csv":
			contents  = self.print_csv_top_row(columns)
			contents += self.print_csv_row(rows)
		elif output == "xml":
			contents += self.print_xml_row(title, columns, rows)
		elif output == "html":
			contents += self.print_html_top_row(title, columns)
			contents += self.print_html_row(rows)
			contents += self.print_html_bottom_row(title)
		else:
			print "Error: incorrect output selected"
			sys.exit()

		if "output_file" in self.settings and self.settings['output_file'] is not None:
			self.write_file(self.settings['output_file'], 'a+', contents)
		else:
			print contents

	def write_file(self, output_file, mode, content):
		"""Write the content into a file"""
		try:
			target = open(output_file, mode)
			target.write(content)
			target.close()
		except:
			print "Error: could not write in file '%s'." % output_file
			sys.exit(1)
