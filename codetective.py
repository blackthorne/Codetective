#!/usr/bin/env python
# encoding: utf-8
__description__ = 'a simple tool to determine the crypto/encoding algorithm used according to traces from its representation'
__author__ = 'Francisco da Gama Tabanez Ribeiro'
__version__ = '0.1'
__date__ = '2011/12/04'
__license__ = 'WTFPL'

import re,sys

def get_type_of(data):
	results=[]
	if re.match(r"^\b[a-fA-F\d]{32}\b$", data): # lm or ntlm or md4 or md5
		results+=['lm','ntlm', 'md4','md5']
	if re.match(r"^\*\b[a-fA-F\d]{40}\b$", data): # MySQL4+
		results+=['MySQL4+']
	if re.match(r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$", data): # base64
		results.append('base64')
	if re.match(r"^\*:[a-fA-F\d]{32}\b", data): # SAM(*:NTLM)
		results.append('SAM(*:ntlm)')
	if re.match(r"^[a-fA-F\d]{32}:\*\b", data): # SAM(LM:*)
		results.append('SAM(lm:*)')
	if re.match(r"^\b\w+:\d+:[a-fA-F\d]{32}:[a-fA-F\d]{32}\b", data): # SAM(LM:NTLM)
		results.append('SAM(lm:ntlm)')
	if re.match(r"^\b[a-fA-F\d]{80}\b$", data): # RipeMD320
		results.append('RipeMD320')
	if re.match(r"^\b[a-fA-F\d]{40}\b$", data): # sha1
		results+=['sha1']
	if re.match(r"\b[a-fA-F\d]{64}\b", data): # SHA256
		results.append('sha256')
	if re.match(r"\b[a-fA-F\d]{96}\b", data): # SHA384
		results.append('sha384')
	if re.match(r"\b[a-fA-F\d]{128}\b", data): # SHA512 or Whirlpool
		results+=['sha512','whirlpool']
	if re.match(r"^[a-fA-F\d]{16}$", data): # MySQL323
		results.append('mysql323')
	if re.match(r"^0x[a-fA-F\d]{1,16}$", data): # CRC
		results.append('CRC')
	if re.match(r"^\b\w{13}\b$", data): # DES(UNIX)
		results.append('des-unix')
	#@TODO: add shadow files ^\w+:\$1\$[a-zA-Z\d\.]+\$[a-zA-Z\d\.]+:\d+:\d*:\d*:\d*:\d*:\d*: for MD5...
	#@TODO: add web shadow files (phpbb, wordpress, joomla, drupal, ...)
	#@TODO: add filters: web, win, linux, other...
	return results or 'unknown'

def usage(): 
	print """USAGE:
codetective <string>\t# determine algorithm used for <string> according to its hex representation
codetective -f <file>\t# tries to guess type of string for each line of <file>

supports LM, NTLM, MD4, MD5, SHA1, SHA256, base64, MySQL323, MYSQL4+ and DES
"""
		
if __name__ == '__main__':
	if len(sys.argv) == 1 or (len(sys.argv) == 2 and (sys.argv[1] == '-h' or sys.argv[1] == '--help')):
		usage()
	elif len(sys.argv) == 2:
		print get_type_of(sys.argv[1])
	elif len(sys.argv) == 3 and sys.argv[1] == '-f':
		fl = open(sys.argv[2],'r')
		for line in fl.readlines():
			print "%s : %s" % (line.strip('\n'), get_type_of(line))
		fl.close()
	else:
		usage()
