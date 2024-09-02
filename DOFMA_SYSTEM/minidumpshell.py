
import cmd
import logging
from minidump.minidumpfile import *
from minidump.common_structs import hexdump

def args2int(x):
	if isinstance(x, int):
		return x
	elif isinstance(x, str):
		if x[:2].lower() == '0x':
			return int(x[2:], 16)
		elif x[:2].lower() == '0b':
			return int(x[2:], 2)
		else:
			return int(x)

	else:
		raise Exception('Unknown integer format! %s' % type(x))

class MinidumpShell(cmd.Cmd):
	intro  = 'Welcome to the minidump shell.   Type help or ? to list commands.\n'
	prompt = '[minidump] '
	mini   = None
	reader = None
	hexdump_size = 16

	def do_open(self, filename):
		logging.debug(f"Opening minidump file: {filename}")
		"""Opens minidump file"""
		try:
			self.mini = MinidumpFile.parse(filename)
			self.reader = self.mini.get_reader().get_buffered_reader()
		except Exception as e:
			logging.error(f"Failed to open minidump file: {e}")
			raise

	# Write threads to text file
	def do_threads(self, args, filename):
		"""Lists all thread information (if available)"""
		with open(filename, "w") as file:
			if self.mini.threads is not None:
				file.write(str(self.mini.threads) + "\n")
			if self.mini.threads_ex is not None:
				file.write(str(self.mini.threads_ex) + "\n")
			if self.mini.thread_info is not None:
				file.write(str(self.mini.thread_info) + "\n")
		print(f"Thread information written to {filename}")

	# Write memory to text file
	def do_memory(self, args, filename):
		"""Writes all memory segments to a text file"""
		with open(filename, "w") as file:
			if self.mini.memory_segments is not None:
				file.write(str(self.mini.memory_segments) + "\n")
			if self.mini.memory_segments_64 is not None:
				file.write(str(self.mini.memory_segments_64) + "\n")
			if self.mini.memory_info is not None:
				file.write(str(self.mini.memory_info) + "\n")
		print(f"Memory segments information written to {filename}")

	# Write modules to text file
	def do_modules(self, args, filename):
		"""Lists all loaded and unloaded module information (if available)"""
		with open(filename, "w") as file:
			if self.mini.modules is not None:
				file.write(str(self.mini.modules) + "\n")
			if self.mini.unloaded_modules is not None:
				file.write(str(self.mini.unloaded_modules) + "\n")
		print(f"Module information written to {filename}")

	# Write sysinfo to text file
	def do_sysinfo(self, args, filename):
		"""Shows sysinfo (if available)"""
		with open(filename, "w") as file:
			if self.mini.sysinfo is not None:
				file.write(str(self.mini.sysinfo) + "\n")
		print(f"Sysinfo information written to {filename}")

	# Write misc to text file
	def do_misc(self, args, filename):
		"""Lists all miscellaneous info (if available)"""
		with open(filename, "w") as file:
			if self.mini.misc_info is not None:
				file.write(str(self.mini.misc_info) + "\n")
		print(f"Misc information written to {filename}")

def main():
	import argparse

	parser = argparse.ArgumentParser(description='A parser for minidumnp files')
	parser.add_argument('-f', '--minidumpfile', help='path to the minidump file of lsass.exe')
	args = parser.parse_args()

	shell = MinidumpShell()
	if args.minidumpfile:
		shell.do_open(args.minidumpfile)
	shell.cmdloop()

if __name__ == '__main__':
	main()