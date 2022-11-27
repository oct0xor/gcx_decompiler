# GCX/GCL scripts decompiler by oct0xor

import sys, os, struct

class code_info:
	def __init__(self, name, func):
		self.name = name
		self.func = func

class command_info:
	def __init__(self, name, func):
		self.name = name
		self.func = func

class gcx_parser:
	def __init__(self, data, print_header = False, print_debug = False, print_resources = False, dictionary = []):
		self.data = data
		self.pos = 0
		self.print_debug = print_debug
		self.dictionary = dictionary

		self.unknown_strcodes = []
		self.strings = []

		self.version = self.read_u32()

		self.procs = []

		self.proc_table_type = 0

		flag = False
		while(True):

			# Parse proc table type 1 

			proc_value_1 = self.read_u32()
			proc_value_2 = self.read_u32()

			if (proc_value_1 == 0 and proc_value_2 == 0):
				self.proc_table_type = 1
				flag = True
				break

			if (proc_value_1 == 0xFFFFFFFF or proc_value_2 == 0xFFFFFFFF):
				break

			self.procs.append([proc_value_1, proc_value_2])

		if (not flag):

			# Parse proc table type 2

			self.pos = 4
			self.procs = []

			while(True):

				proc_value = self.read_u32()

				if (proc_value == 0xFFFFFFFF):
					self.proc_table_type = 2
					flag = True
					break
	
				self.procs.append([0, proc_value])

		if (not flag):
			print("ERROR! UNABLE TO PARSE PROC TABLE")
			exit(0)

		self.gcl_strres_block_top = self.pos
		
		script_offset = self.read_u32()
		resource_table_offset = self.read_u32()
		string_table_offset = self.read_u32()
		font_data_offset = self.read_u32()
		key = self.read_u32()

		self.gcl_script_proc_body_size = self.read_u32_at_offset(self.gcl_strres_block_top + script_offset)
		self.gcl_script_proc_body_data = self.gcl_strres_block_top + script_offset + 4

		self.gcl_script_main_body_size = self.read_u32_at_offset(self.gcl_script_proc_body_data + self.gcl_script_proc_body_size)
		self.gcl_script_main_body_data = self.gcl_script_proc_body_data + self.gcl_script_proc_body_size + 4

		self.gcl_strres_resource_table = self.gcl_strres_block_top + resource_table_offset
		self.gcl_strres_string_table = self.gcl_strres_block_top + string_table_offset
		self.gcl_strres_font_data = self.gcl_strres_block_top + font_data_offset

		self.script = ""

		if (print_header):
			self.script += "// Timestamp: 0x%X\n" % self.version
			self.script += "//\n"

			self.script += "// Proc Num: 0x%X\n" % len(self.procs)

			for proc in self.procs:
				self.script += "// \tProc: 0x%X 0x%X\n" % (proc[0], proc[1])
			self.script += "//\n"
	
			self.script += "// Resource Block Top: 0x%X\n" % self.gcl_strres_block_top
	
			self.script += "// Script Proc Body: 0x%X (0x%X)\n" % (self.gcl_script_proc_body_data, self.gcl_script_proc_body_size)
			self.script += "// Script Main Body: 0x%X (0x%X)\n" % (self.gcl_script_main_body_data, self.gcl_script_main_body_size)
	
			self.script += "// Resource Table: 0x%X\n" % self.gcl_strres_resource_table
			self.script += "// Resource String Table: 0x%X\n" % self.gcl_strres_string_table
			self.script += "// Resource Font Data: 0x%X\n" % self.gcl_strres_font_data
			self.script += "\n"

		if (print_resources and self.gcl_strres_resource_table != self.gcl_strres_string_table):
	
			count = (self.gcl_strres_string_table - self.gcl_strres_resource_table) / 4

			resources = []
			for i in range(count):
				resources.append(self.gcl_strres_string_table + self.read_u32_at_offset(self.gcl_strres_resource_table + i * 4))

			resource_strings = []
			if (len(resources) > 0):

				# TODO: In MGS3/MGS4 resources are encrypted

				# do
				# {
				#   v11 = v12-- <= 1;
				#   v10 = 0x7D2B89DD * v10 + 0xCF9;
				#   *v8++ ^= v10 >> 15;
				# }
				# while ( !v11 );

				resources.append(self.gcl_strres_font_data)

				for i in range(len(resources) - 1):

					start = resources[i] & 0xFFFFFF
					end = resources[i+1] & 0xFFFFFF
					resource = self.data[start:end]

					#text = ""
					#for c in resource:
					#	if (c in string.printable and c not in ['\n', '\r', '\t']):
					#		text += c
					#	else:
					#		text += "\\x%02X" % (ord(c))

					text = resource.encode('hex')

					resource_strings.append(text)

				resources.pop()

			self.script += "// Resources Num: 0x%X\n" % count

			for i in range(count):
				self.script += "// \tResource: 0x%X - %s\n" % (resources[i], resource_strings[i])
	
			self.script += "\n"

		self.code_types = {
			0:    code_info("End", 				None),
			1:    code_info("Short", 			self.handle_numeric_value),
			2:    code_info("Byte", 			self.handle_numeric_value),
			3:    code_info("Byte", 			self.handle_numeric_value),
			4:    code_info("Byte", 			self.handle_numeric_value),
			6:    code_info("StrCode", 			self.handle_numeric_value),
			7:    code_info("String", 			self.handle_string),
			8:    code_info("StrCode", 			self.handle_numeric_value),
			9:    code_info("Long", 			self.handle_numeric_value),
			0xA:  code_info("Long", 			self.handle_numeric_value),
			0xD:  code_info("Long", 			self.handle_numeric_value),
			0xE:  code_info("StringResource", 	self.handle_string_resource),
			
			0x10: code_info("Var", 				self.handle_0x10_0x20),
			0x20: code_info("VarArray", 		self.handle_0x10_0x20),
			0x30: code_info("Expr", 			self.handle_0x30),
			0x40: code_info("Args", 			self.handle_0x40),
			0x50: code_info("Param", 			self.handle_0x50),
			0x60: code_info("Command", 			self.handle_0x60),
			0x70: code_info("Call", 			self.handle_0x70),
			0x80: code_info("Proc", 			self.handle_0x80),
			0x90: code_info("Local", 			self.handle_0x90),
			0xC0: code_info("Num", 				self.handle_0xC0),
		}

		self.builtin_commands = {
			0xD86:    command_info(".if",      self.handle_if), # strcode("if")
			0xA65DB5: command_info(".switch",  self.handle_switch), # strcode("switch")
			0x34648C: command_info(".eval",    None), # strcode("eval")
			0x3311EC: command_info(".call",    None), # strcode("call")
			0x8BE398: command_info(".return",  None), # strcode("return")
			0x3AB23B: command_info(".print",   None), # strcode("print")
		}

		self.script_commands = {
			0x3822C7: command_info(".mesg",    None), # strcode("mesg")
			0x82BC9:  command_info(".command", None), # strcode("command")
			0x6592A7: command_info(".chara",   None), # strcode("chara")
			0x3BD490: command_info(".trap",    None), # strcode("trap")
			0x37C884: command_info(".load",    None), # strcode("load")
			0x8B3DF5: command_info(".script_command_0x8B3DF5", None),
			0x1C090:  command_info(".map",     None), # strcode("map")
			0x6BB005: command_info(".restart", None), # strcode("restart")
		}

		self.indent_level = 0

		self.pos = self.gcl_script_main_body_data
		size = self.get_block_size()
		end = self.pos + size

		self.decompile(end, "main")

		i = 1
		for proc in self.procs:
			strcode = proc[0]
			pos = proc[1] & 0xFFFFFF

			self.pos = self.gcl_script_proc_body_data + pos

			comment = ""
			if (self.proc_table_type == 1):

				proc_name = ""
				if (strcode in self.dictionary):
					proc_name = "code(\"%s\")" % self.dictionary[strcode]
				elif (strcode not in self.unknown_strcodes):
					self.unknown_strcodes.append(strcode)
	
				if (self.print_debug):
					if (proc_name != ""):
						comment = " // 0x%X - %s" % (self.pos, proc_name)
					else:
						comment = " // 0x%X" % self.pos
				elif (proc_name != ""):
					comment = " // %s" % proc_name

				name = "proc_0x%X" % strcode

			elif (self.proc_table_type == 2):
				
				if (self.print_debug):
					comment = " // 0x%X" % self.pos

				name = "proc_id_%d" % i

			else:
				print("ERROR! UNEXPECTED PROC TABLE TYPE")
				exit(0)

			size = self.get_block_size()
			end = self.pos + size

			self.decompile(end, name, comment)

			i += 1

	def read_u8_at_offset(self, offset):
		value = struct.unpack("<B", self.data[offset:offset+1])[0]
		return value

	def read_u8(self):
		value = self.read_u8_at_offset(self.pos)
		self.pos += 1
		return value

	def read_u16(self):
		value = struct.unpack("<H", self.data[self.pos:self.pos+2])[0]
		self.pos += 2
		return value

	def read_u24(self):
		return (self.read_u8() | (self.read_u16() << 8))

	def read_u32_at_offset(self, offset):
		value = struct.unpack("<L", self.data[offset:offset+4])[0]
		return value

	def read_u32(self):
		value = self.read_u32_at_offset(self.pos)
		self.pos += 4
		return value

	def read_u32be(self):
		value = struct.unpack(">L", self.data[self.pos:self.pos+4])[0]
		self.pos += 4
		return value

	def decompile(self, block_end, func_name, comment = ""):

		self.stop = False

		s = "%s {%s\n\n" % (func_name, comment)

		while (self.pos < block_end):

			code = self.read_u8_at_offset(self.pos)
			type_p = self.decode_type(code)

			value = self.decode_value(block_end)

			if (type_p == 0x30): # Expr, we dont want to have parentheses in this case
				value = self.fix_expr(value)

			s += value

			if (self.stop):
				break

		s += "}\n"

		s = s.replace('\n\n\n', '\n\n')

		self.script += s + '\n'

	def decode_type(self, code):

		code_high = code & 0xF0
		code_low = code & 0xF
		if ((code & 0xC0) == 0xC0):
			return 0xC0
	
		if (code_high != 0):
			if (code_high in [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90]):
				return code_high
		else:
			if (code in [0, 1, 2, 3, 4, 6, 7, 8, 9, 0xA, 0xD, 0xE]):
				return code

		self.stop = True

	def get_block_size(self):
	
		value = self.read_u8() & 0xF
	
		if (value == 13):
			# 2 bytes
			return self.read_u8()
	
		elif (value == 14):
			# 3 bytes
			return self.read_u16()
	
		elif (value == 15):
			# 4 bytes
			return self.read_u24()
	
		return value

	def handle_numeric_value(self, block_end, inline):

		code = self.read_u8()

		if (code == 1): # Short
			return "0x%X" % self.read_u16()
		
		elif (code in [2, 3, 4]): # Byte
			return "0x%X" % self.read_u8()
			#return "Type_%d: 0x%X" % (code, self.read_u8())
		
		elif (code in [6, 8]): # StrCode (24 bits) # TODO: Type_8 is proc_ ?

			strcode = self.read_u24()

			value = ""
			if (strcode in self.dictionary):
				value = "code(\"%s\")" % self.dictionary[strcode]
			else:
				if (strcode not in self.unknown_strcodes):
					self.unknown_strcodes.append(strcode)
				value = "0x%X" % strcode

			return value
			#return "Type_%d: %s" % (code, value)
				
		elif (code in [9, 0xA, 0xD]): # Long
			return "0x%X" % self.read_u32() # TODO: Type_13 is BE?
			#return "Type_%d: 0x%X" % (code, self.read_u32())

	def handle_string(self, block_end, inline):

		self.pos += 1
		size = self.read_u8()

		s = self.data[self.pos:self.pos + size - 1]

		self.pos += size

		if (s not in self.strings):
			self.strings.append(s)

		try:
			s = s.decode("EUC-JP")
		except:
			s = "DECOMPILER: FAILED TO DECODE EUC-JP STRING!"

		return '"' + s + '"'

	def handle_string_resource(self, block_end, inline):

		self.pos += 1
		value = self.read_u16()

		offset = self.read_u32_at_offset(self.gcl_strres_resource_table + value * 4)

		return "resource(0x%X)" % (self.gcl_strres_string_table + offset)

	def handle_0x10_0x20(self, block_end, inline):

		return self.gcl_get_var()

	def handle_0x30(self, block_end, inline):

		size = self.get_block_size()

		end = self.pos + size
		expr = self.gcl_expr(end, inline)
	
		self.pos = end

		return expr

	def handle_0x40(self, block_end, inline):

		code_low = self.read_u8() & 0xF

		if (code_low == 15):
			# 2 bytes
			arg_id = self.read_u8() + 15
		else:
			# 1 byte
			arg_id = code_low
		
		return "$arg%d" % arg_id

	def handle_0x50(self, block_end, inline):

		# Param - tricky case...
		# In original code param_type is packed into type_p (type_p |= self.read_u8() << 16) and passed outside (if_command for example)
	
		size = self.get_block_size()
		pos = self.pos

		# 1 byte = type_p, value
		param_type = self.read_u8()
		param_pos = self.pos

		self.pos = pos + size

		return [param_type, param_pos, self.pos]

	def handle_0x60(self, block_end, inline):

		size = self.get_block_size()
		
		end = self.pos + size
		cmd = self.gcl_command(end, inline)
		
		self.pos = end
	
		return cmd

	def handle_0x70(self, block_end, inline):

		size = self.get_block_size()

		end = self.pos + size
		call = self.gcl_call(end, inline)
	
		self.pos = end

		return call

	def fix_expr(self, value):

		indents = 0
		for c in value:
			if (c == '\t'):
				indents += 1
			else:
				break

		if (value[indents] == '(' and value[-2:] == ")\n"):
			value = "\t" * indents + value[indents+1:-2] + '\n'

		return value

	def handle_0x80(self, block_end, inline):

		size = self.get_block_size()		
		end = self.pos + size

		if (self.print_debug):
			s = "proc_block_0x%X {\n" % self.pos
		else:
			s = "proc {\n"

		while (self.pos < end):

			code = self.read_u8_at_offset(self.pos)
			type_p = self.decode_type(code)

			value = self.decode_value(end, False)

			if (type_p == 0x30): # Expr, we dont want to have parentheses in this case
				value = self.fix_expr(value)

			s += value

			if (self.stop):
				return s

		s += "\t" * self.indent_level + '} ' 

		self.pos = end

		return s

	def handle_0x90(self, block_end, inline):

		return self.gcl_get_local(self.read_u8())

	def handle_0xC0(self, block_end, inline):

		return self.gcl_get_num(self.read_u8())

	def format_param(self, param_type, param_start, param_end, values, inline):

		if (self.print_debug):
			s = "{ Param type = '%s' (0x%X), start = 0x%X, end = 0x%X } {" % (param_type, ord(param_type), param_start, param_end)
		else:
			s = ".param('%s') {" % param_type

		if (len(values) > 0):
			s += '\n'
			for value in values:
				s += value

				if (not s.endswith('\n')):
					#print("ERROR! PARAM NOT ENDS WITH '\\n'")
					#exit(0)
					s += "/* ERROR! PARAM NOT ENDS WITH '\\n' */"

				else:
					s = s[:-1]

				s += ', \n'

			s = s[:-3] + '\n'

		if (not inline):
			s += "\t" * self.indent_level
		s += '}'

		return s

	def decode_value(self, block_end = None, inline = False, param_formatter = None):

		start = self.pos

		code = self.read_u8_at_offset(self.pos)
		type_p = self.decode_type(code)

		if (self.stop):
			print("ERROR! WRONG CODE 0x%X - 0x%X" % (self.pos, code))
			exit(0)

		type_info = self.code_types[type_p]

		type_name = type_info.name
		type_func = type_info.func

		self.indent_level += 1

		value = ""
		if (type_p == 0):
			self.pos += 1
		else:
			value = type_func(block_end, inline)

		if (type_p == 0x50):

			param_type = chr(value[0])
			param_start = value[1]
			param_end = value[2]

			pos_copy = self.pos
			self.pos = param_start

			param_values = []
			while (self.pos < param_end):
				param_values.append(self.decode_value(param_end, inline))
				if (self.stop):
					break

			self.pos = pos_copy

			if (param_formatter):
				value = param_formatter(param_type, param_start, param_end, param_values, inline)
			else:
				value = self.format_param(param_type, param_start, param_end, param_values, inline)

		s = ""
		if (self.print_debug):
			s = "0x%X : " % start + type_name

			if (type_p != 0):
				s += " : "

		s += value

		if (not inline and (self.print_debug or type_p != 0)):
			s = "\t" * self.indent_level + s + "\n"

		self.indent_level -= 1

		if (type_p in [0x60, 0x70]):
			s = '\n' + s

		return s

	def gcl_get_short_size(self):
	
		value = self.read_u8()
	
		if ((value & 0x80) == 0):
			# 1 byte
			return value
		
		else:
			# 2 bytes
			value2 = self.read_u8()
			value = ((value << 8) | (value2)) & 0x7FFF
			return value

	def parse_command(self, name, block_end):

		args = []

		while (self.pos < block_end):
			args.append(self.decode_value(block_end, True))
			if (self.stop):
				break

		s = name + '('
		if (len(args) > 0):
			for arg in args:
				s += arg
				s += ", "

			s = s[:-2]

		s += ')\n'

		return s

	def parse_params(self, block_end, inline, param_formatter = None):

		s = ""

		params = []
		params_start = self.pos
		if (self.stop == False):
			while (self.pos < block_end):
				params.append(self.decode_value(block_end, inline, param_formatter))
				if (self.stop):
					break
	
		if (len(params) > 0):
	
			if (self.print_debug):
				s += "\t" * self.indent_level + "0x%X : " % params_start + "Command line:\n"
		
			for param in params:
				s += param

		return s

	def format_switch_param(self, param_type, param_start, param_end, values, inline):

		if (param_type == 'c'):

			s = "case %s:\n" % values[0].replace('\t', '').replace('\n', '')
			s += values[1]
			s += "\t" * (self.indent_level + 1) + "break" + "\n"
			return s

		if (param_type == 'd'):

			s = "default:\n"
			s += values[0]
			s += "\t" * (self.indent_level + 1) + "break" + "\n"
			return s

		s = self.format_param(param_type, param_start, param_end, values, inline)
		return s

	def handle_switch(self, block_end, inline):

		s = "\t" * self.indent_level + "{" + "\n"
		s += self.parse_params(block_end, inline, self.format_switch_param) + "\n"
		s += "\t" * self.indent_level + "}" + "\n"
		return s

	def format_if_param(self, param_type, param_start, param_end, values, inline):

		s = None
		if (param_type == 'i'):
			s = ".elif("

		elif (param_type == 'e'):
			s = ".else("

		if (s != None):

			if (len(values) > 0):
				for value in values:

					while (value[0] == '\t'):
						value = value[1:]

					s += value[:-1]
					s += ", "
	
				s = s[:-2]
	
			s += ')\n'
	
			return s

		return self.format_param(param_type, param_start, param_end, values, inline)

	def handle_if(self, block_end, inline):

		s = self.parse_params(block_end, inline, self.format_if_param) + "\n"
		return s

	def gcl_command(self, block_end, inline):
	
		s = ""

		if (inline == True):
			#print("ERROR! UNEXPECTED INLINE")
			#exit(0)
			s += "/* ERROR! UNEXPECTED INLINE */"

		command = self.read_u24()
		size = self.gcl_get_short_size()

		name = None
		func = None
		if (command in self.builtin_commands):
			name = self.builtin_commands[command].name
			func = self.builtin_commands[command].func

		elif (command in self.script_commands):
			name = self.script_commands[command].name
			func = self.script_commands[command].func

		elif (command in self.dictionary):
			name = '.' + self.dictionary[command]

		else:
			name = ".unknown_command_0x%X" % command

		s += self.parse_command(name, self.pos + size)

		if (func):
			s += func(block_end, inline)

		else:
			s += self.parse_params(block_end, inline)

		return s

	def gcl_get_num(self, code):
		return "%d" % ((code & 0x3F) - 1)

	def gcl_get_local(self, code):
		return "$local:%d" % (code & 0x0F)

	def gcl_get_var(self):
	
		varcode = self.read_u32be()
		code = varcode >> 0x18
		
		region = "varbuf"
		if ((varcode & 0xF00000) == 0x800000):
			region = "linkvarbuf"
	
		elif ((varcode & 0xF00000) == 0x100000):
			region = "localvarbuf"

		offset = varcode & 0xFFFF
	
		s = "$var:%s_0x%X" % (region, offset)
	
		if ((code & 0xF0) == 0x20):
	
			array_max = self.decode_value(None, True)
			if (self.stop):
				s += array_max
				return s

			array_offset = self.decode_value(None, True)
			if (self.stop):
				s += array_offset
				return s
	
			s += "[%s,%s]" % (array_offset, array_max)
	
		return s

	def gcl_call(self, block_end, inline):
	
		args = []
	
		proc_name = ""

		if (self.proc_table_type == 1):
			proc = self.read_u24()

			if (proc in self.dictionary):
				proc_name = " code(\"%s\")" % self.dictionary[proc]
			elif (proc not in self.unknown_strcodes):
				self.unknown_strcodes.append(proc)

			proc_name = "proc_0x%X%s" % (proc, proc_name)

		elif (self.proc_table_type == 2):
			proc = self.read_u16()

			proc_name = "proc_id_%d" % proc

		else:
			print("ERROR! UNEXPECTED PROC TABLE TYPE")
			exit(0)

		code = self.read_u8_at_offset(self.pos)
		type_p = self.decode_type(code) # TODO: We actually need to have the last decoded

		if (self.stop):
			print("ERROR! WRONG CODE 0x%X - 0x%X" % (self.pos, code))
			exit(0)

		value = self.decode_value(block_end, True)
		if (self.stop):
			return value

		while (type_p != 0):
	
			if (len(args) >= 16):
				print("ERROR! TOO MANY ARGS PROC 0x%X" % proc)
				exit(0)

			args.append(value)
	
			code = self.read_u8_at_offset(self.pos)
			type_p = self.decode_type(code)

			if (self.stop):
				print("ERROR! WRONG CODE 0x%X - 0x%X" % (self.pos, code))
				exit(0)

			value = self.decode_value(block_end, True)
			if (self.stop):
				return value

		s = proc_name + " ("

		if (len(args) > 0):
			for arg in args:
				s += arg + ", "

			s = s[:-2]

		s += ')'

		return s

	def gcl_expr(self, block_end, inline):

		expr_stack = [] # In original code MAX = 8, buffer overflow lol

		while (True):
	
			while (True):
	
				pos = self.pos

				code = self.read_u8_at_offset(self.pos)
				type_p = code & 0xE0
				if (type_p == 0xA0):
					break
	
				value = self.decode_value(block_end, True)
				if (self.stop):
					return value

				expr_stack.append([value, pos])
	
			opcode = code & 0xFFFFFF1F
	
			if (opcode == 0):
				break
					
			value2 = expr_stack.pop()[0]
			value1 = expr_stack.pop()[0]
			value = self.decode_opcode(opcode, value1, value2)
			expr_stack.append(["(" + value + ")", None])

			self.pos += 1

		return expr_stack[0][0]

	def decode_opcode(self, opcode, value1, value2):

		if   (opcode == 0):  return None
		elif (opcode == 1):  return "-" + value2
		elif (opcode == 2):  return value2 + " == 0"
		elif (opcode == 3):  return "~" + value2
		elif (opcode == 4):  return value1 + " + " + value2
		elif (opcode == 5):  return value1 + " - " + value2
		elif (opcode == 6):  return value1 + " * " + value2
		elif (opcode == 7):  return value1 + " / " + value2
		elif (opcode == 8):  return value1 + " % " + value2
		elif (opcode == 9):  return value1 + " << " + value2
		elif (opcode == 10): return value1 + " >> " + value2
		elif (opcode == 11): return value1 + " == " + value2
		elif (opcode == 12): return value1 + " != " + value2
		elif (opcode == 13): return value1 + " < " + value2
		elif (opcode == 14): return value1 + " <= " + value2
		elif (opcode == 15): return value1 + " > " + value2
		elif (opcode == 16): return value1 + " >= " + value2
		elif (opcode == 17): return value1 + " | " + value2
		elif (opcode == 18): return value1 + " & " + value2
		elif (opcode == 19): return value1 + " ^ " + value2
		elif (opcode == 20): return value1 + " || " + value2 
		elif (opcode == 21): return value1 + " && " + value2 
		elif (opcode == 22): return value1 + " = " + value2 
		elif (opcode == 23): return value2
		else:
			print("ERROR! BAD OPCODE: 0x%X" % opcode)
			exit(0)

STRCODES = {}
BAD_STRCODES = []

def read_dictionary(path):

	global STRCODES
	global BAD_STRCODES

	f = open(path, "rb")
	lines = f.readlines()
	f.close()

	for line in lines:
		s = line.split()
		if (len(s) == 2):
			strcode = int(s[0], 16)
			name = s[1].decode()

			if (strcode in STRCODES):
				#print("WARNING! StrCode 0x%X is already present in dictionary! %s - %s" % (strcode, STRCODES[strcode], name))
				BAD_STRCODES.append(strcode)
				continue

			STRCODES[strcode] = name

def clean_dictionary():

	global STRCODES
	global BAD_STRCODES

	temp = {}

	for strcode in STRCODES:
		if (strcode not in BAD_STRCODES):
			temp[strcode] = STRCODES[strcode]

	STRCODES = temp

directory = "dictionaries"

if (os.path.isdir(directory)):
	for entry in os.listdir(directory):
		try:
			read_dictionary(os.path.join(directory, entry))
		except:
			pass
	clean_dictionary()

if (len(sys.argv) == 1):
	print("Usage: %s <input file/folder> <output file/folder>" % os.path.basename(sys.argv[0]))
	exit(0)

input_is_directory = os.path.isdir(sys.argv[1])

output_is_file = False
output_is_directory = False

if (len(sys.argv) > 2):
	output_is_directory = os.path.isdir(sys.argv[2])
	output_is_file = not output_is_directory

paths = []
if (input_is_directory):
	for root, dirs, files in os.walk(sys.argv[1]):
		for file in files:
			path = os.path.join(root, file)

			if (path.endswith(".gcx")):
				paths.append(path)

else:
	paths.append(sys.argv[1])

for path in paths:

	with open(path, "rb") as f:
		data = f.read()
		gcx = gcx_parser(data, dictionary = STRCODES)

		if (output_is_file):
			with open(sys.argv[2], "wb") as o:
				o.write(gcx.script.encode("EUC-JP"))

		elif (output_is_directory):
			output_path = os.path.join(sys.argv[2], "%s_%s_out" % (os.path.basename(os.path.dirname(path)), os.path.basename(path)))
			with open(output_path, "wb") as o:
				o.write(gcx.script.encode("EUC-JP"))

		#else:
		#	if (len(paths) > 1):
		#		print("\t-->\t%s" % path)
		#	print(gcx.script)
