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
import compat


class Dump(object):
	"""Dump the results received in html, txt or csv"""
	def __init__(self, settings):
		self.settings = settings
		self.toggle_table = True

	def get_screen_size(self, columns):
		"""Defines the size of the columns, based on the amount of columns"""
		size = [None]
		if isinstance(columns, list):
			col0 = 20
			col1 = 9
			size = size * len(columns)
			if len(columns) == 1:
				size[0] = self.settings['output_width'] - 3
			elif len(columns) == 2:
				size[0] = col0  # fixed length, meant to be used with the testcase
				size[1] = self.settings['output_width'] - size[0] - 5
			elif len(columns) == 3:
				size[0] = col0  # fixed length, meant to be used with the testcase
				size[1] = col1  # fixed length, meant to be used with the software name
				size[2] = self.settings['output_width'] - size[1] - size[0] - 7
			elif len(columns) == 4:
				size[0] = col0  # fixed length, meant to be used with the testcase
				size[1] = col1  # fixed length, meant to be used with the software name
				size[2] = (self.settings['output_width'] - size[1] - size[0]) / 2 - 9
				size[3] = self.settings['output_width'] - size[2] - size[1] - size[0] - 9
			elif len(columns) == 5:
				size[0] = col0  # fixed length, meant to be used with the testcase
				size[1] = col1  # fixed length, meant to be used with the software name
				size[2] = (self.settings['output_width'] - size[1] - size[0]) / 3 - 3
				size[3] = (self.settings['output_width'] - size[1] - size[0]) / 3 - 3
				size[4] = self.settings['output_width'] - size[3] - size[2] - size[1] - size[0] - 11
			elif len(columns) == 6:
				size[0] = col0  # fixed length, meant to be used with the testcase
				size[1] = col1  # fixed length, meant to be used with the software name
				size[2] = (self.settings['output_width'] - size[1] - size[0]) / 4 - 3
				size[3] = (self.settings['output_width'] - size[1] - size[0]) / 4 - 3
				size[4] = (self.settings['output_width'] - size[1] - size[0]) / 4 - 3
				size[5] = self.settings['output_width'] - size[4] - size[3] - size[2] - size[1] - size[0] - 13
			elif len(columns) == 7:
				size[0] = col0  # fixed length, meant to be used with the testcase
				size[1] = col1  # fixed length, meant to be used with the software name
				size[2] = (self.settings['output_width'] - size[1] - size[0]) / 5 - 3
				size[3] = (self.settings['output_width'] - size[1] - size[0]) / 5 - 3
				size[4] = (self.settings['output_width'] - size[1] - size[0]) / 5 - 3
				size[5] = (self.settings['output_width'] - size[1] - size[0]) / 5 - 3
				size[6] = self.settings['output_width'] - size[5] - size[4] - size[3] - size[2] - size[1] - size[0] - 15
			elif len(columns) == 8:
				size[0] = col0  # fixed length, meant to be used with the testcase
				size[1] = col1  # fixed length, meant to be used with the software name
				size[2] = (self.settings['output_width'] - size[1] - size[0]) / 6 - 3
				size[3] = (self.settings['output_width'] - size[1] - size[0]) / 6 - 3
				size[4] = (self.settings['output_width'] - size[1] - size[0]) / 6 - 3
				size[5] = (self.settings['output_width'] - size[1] - size[0]) / 6 - 3
				size[6] = (self.settings['output_width'] - size[1] - size[0]) / 6 - 3
				size[7] = self.settings['output_width'] - size[6] - size[5] - size[4] - size[3] - size[2] - size[1] - size[0] - 17

			else:
				self.settings['logger'].error("Too many columns: ", len(columns))
		else:
			self.settings['logger'].error("Incorrect columns type received")
		return size

	def print_text_top_row(self, title, columns):
		"""Print the first row of the table (and then print_text_row and print_text_bottom_row will be used)"""
		output = None
		if isinstance(title, str) and isinstance(columns, list):
			size = self.get_screen_size(columns)

			output = "-" * self.settings['output_width'] + "\n"
			output += "| " + title + " " * (self.settings['output_width'] - len(title) - 4) + " |\n"
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
		if isinstance(results, list):
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
							try:
								message = message.replace('\n', ' ')           # Python 2
							except:
								message = message.decode().replace('\n', ' ')  # Python 3
							output += "| {message:{fill}{align}{width}}".format(message=message[:size[colid]], fill=" ", align='<', width=size[colid])
						output += "|\n"
					output += "-" * self.settings['output_width'] + "\n"
		return output

	def print_text_bottom_row(self):
		"""Print the last bottom row of a txt output"""
		return "\n"

	def print_csv_top_row(self, columns):
		"""Print the first row of the csv table (and then print_csv_row will be used)"""
		output = ""
		if isinstance(columns, list):
			output = ",".join(columns) + "\n"
		return output

	def print_csv_row(self, results):
		"""Print a row of the table (previously print_text_top_row was used and finally print_text_bottom_row will be used used)"""
		output = ""
		if isinstance(results, list):
			for result in results:
				for row in result:
					for colid in range(0, len(row)):
						if type(row[colid]).__name__ in ['int', 'NoneType']:
							message = str(row[colid])
						else:
							message = (row[colid]).encode("utf-8")
						if colid != 0:
							output += ","
						try:
							output += message           # Python 2
						except:
							output += message.decode()  # Python 3
					output += "\n"
		return output

	def print_xml_row(self, title, column, results):
		"""Print a row of the table (previously print_text_top_row was used and finally print_text_bottom_row will be used used)"""
		output = ""
		if isinstance(title, str) and isinstance(column, list) and isinstance(results, list):
			output = "\t<" + "".join(ch for ch in title if ch.isalnum()) + ">\n"
			for result in results:
				for row in result:
					column_id = 0
					for item in row:
						output += "\t\t<" + str(compat.escape(column[column_id])) + ">" + str(compat.escape(item)) + "</" + str(compat.escape(column[column_id])) + ">\n"
						column_id += 1
					output += "\n"
			output += "\t</" + "".join(ch for ch in title if ch.isalnum()) + ">\n"
		return output

	def print_html_top_row(self, title, columns):
		"""Print the first row of the HTML table (and then print_html_row will be used)"""
		output = ""
		if isinstance(title, str) and isinstance(columns, list):
			output = """<table>
				<tr>
					<th><a id='""" + "".join(ch for ch in title if ch.isalnum()) + """Link' onclick="toggleTable('""" + "".join(ch for ch in title if ch.isalnum()) + """Table');" href='#""" + "".join(ch for ch in title if ch.isalnum()) + """'>""" + str(compat.escape(title)) + """</a><a href="#"><div class="arrow-up">top&nbsp;&nbsp;</div></a></th>
				</tr>
			</table>
			<table id='""" + "".join(ch for ch in title if ch.isalnum()) + """Table'>
				<tr>"""
			for column in columns:
				output += "<th>" + str(compat.escape(column)) + "</th>"
			output += "</tr>\n"
		return output

	def print_html_row(self, results):
		"""Print a row of the table (previously print_html_top_row was used and finally print_html_bottom_row will be used used)"""
		output = ""
		if isinstance(results, list):
			cont = 1
			for result in results:
				if cont % 2 == 0:
					trclass = " class='gray'"
				else:
					trclass = ""
				for row in result:
					output += "      <tr" + trclass + ">"
					for item in row:
						output += "<td><div style='white-space: pre-wrap;'>" + str(compat.escape(str(item)).encode('ascii', 'xmlcharrefreplace')) + "</div></td>"
					output += "</tr>\n"
				cont += 1
		return output

	def print_html_bottom_row(self, title):
		"""Print the first row of the HTML table (and then print_html_row will be used)"""
		output = "</table><br/>\n"
		if isinstance(title, str) and title.find("Analyze") != -1 and self.toggle_table:
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
			<title>Fuzzer Results for """ + str(compat.escape(self.settings['db_file'])) + """</title>
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
			print(contents)

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
			print(contents)

	def general(self, output, title, columns, rows):
		"""Main function to dump stuff: from here, you can export in different formats (txt, csv, xml, html) to the screen or files"""
		if not rows:
			return
		contents = ""
		title = title + " (" + str(len(rows)) + " rows)"

		if output is None:
			return
		elif output == "txt":
			contents = self.print_text_top_row(title, columns)
			contents += self.print_text_row(columns, rows)
			contents += self.print_text_bottom_row()
		elif output == "csv":
			contents = self.print_csv_top_row(columns)
			contents += self.print_csv_row(rows)
		elif output == "xml":
			contents += self.print_xml_row(title, columns, rows)
		elif output == "html":
			contents += self.print_html_top_row(title, columns)
			contents += self.print_html_row(rows)
			contents += self.print_html_bottom_row(title)
		else:
			self.settings['logger'].error("Incorrect output selected")

		if output in ["txt", "csv", "xml", "html"] and contents:
			if "output_file" in self.settings and self.settings['output_file'] is not None:
				self.write_file(self.settings['output_file'], 'a+', contents)
			else:
				print(contents)

	def write_file(self, output_file, mode, content):
		"""Write the content into a file"""
		if content:
			try:
				target = open(output_file, mode)
				target.write(content)
				target.close()
			except:
				self.settings['logger'].error("Could not write in file '%s'.", output_file)
