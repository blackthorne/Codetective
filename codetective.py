#!/usr/bin/env python
# encoding: utf-8
__description__ = 'a simple tool to determine the crypto/encoding algorithm used according to traces of its representation'
__author__ = 'Francisco da Gama Tabanez Ribeiro'
__version__ = '0.2'
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
	if re.match(r"^\b[a-fA-F\d]{40}\b$", data): # SHA1
		results.append('sha1')
	if re.match(r"^\b[a-fA-F\d]{56}\b$",data): # SHA224
		results.append('sha224')
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
	if re.match(r"\b[a-zA-Z0-9./]{2}[a-zA-Z0-9./]{11}\b", data): # DES-salt(UNIX)
		results.append('des-salt-unix')
	if re.match(r"sha256\$[a-zA-Z\d\.]+\$[a-zA-Z0-9./]{64}", data): # SHA256(Django)
		results.append('sha256-django')
	if re.match(r"sha384\$[a-zA-Z\d\.]+\$[a-zA-Z\d\.]{96}", data): # SHA384(Django)
		results.append('sha384-django')
	if re.match(r"sha1\$[a-zA-Z\d\.]+\$[a-zA-Z\d\.]{96}", data): # SHA1(Django)
		results.append('sha1-django')
	if re.match(r"\$5\$[a-zA-Z0-9./]{8,16}\$[a-zA-Z0-9./]{43}", data): # SHA256-salt(UNIX)
		results.append('sha256-salt-unix')
	if re.match(r"\$6\$[a-zA-Z0-9./]{8,16}\$[a-zA-Z0-9./]{86}", data): # SHA512-salt(UNIX)
		results.append('sha512-salt-unix')
	if re.match(r"\$1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{22}", data): # MD5-salt(UNIX)
		results.append('md5-salt-unix')
	if re.match(r"\$P\$[a-zA-Z0-9./]{31}$", data):  # MD5(Wordpress)
		results.append('md5-wordpress')
	if re.match(r"\$H\$[a-zA-Z0-9./]{31}$", data):  # MD5(phpBB3)
		results.append('md5-phpBB3')
	if re.match(r"^[a-zA-Z0-9./]{32}:[a-zA-Z0-9./]{32}$", data):  # MD5-salt(joomla2)
		results.append('md5-salt-joomla2')
	if re.match(r"^[a-zA-Z0-9./]{32}:[a-zA-Z0-9./]{16}$", data):  # MD5-salt(joomla1)
		results.append('md5-salt-joomla1')
	if re.match(r"\$2a\$[a-zA-Z0-9./]{2}\$[a-zA-Z0-9./]{53}", data):  # Blowfish(UNIX)
		results.append('blowfish-salt-unix')
	return results or 'unknown'


def usage(): 
	print """USAGE:
codetective <string>\t# determine algorithm used for <string> according to its hex representation
codetective -f <file>\t# tries to guess type of string for each line of <file>
codetective -l\t# lists supported algorithms

"""
		
if __name__ == '__main__':
	if len(sys.argv) == 1 or (len(sys.argv) == 2 and (sys.argv[1] == '-h' or sys.argv[1] == '--help')):
		usage()
	elif len(sys.argv) == 2:
		if sys.argv[1] == '-l':
			print "shadow and SAM files, phpBB3, Wordpress, Joomla, CRC, LM, NTLM, MD4, MD5, SHA1, SHA256, base64, MySQL323, MYSQL4+, DES, RipeMD320, Whirlpool, SHA1, SHA224, SHA256, SHA384, SHA512, Blowfish"
		else:
			print get_type_of(sys.argv[1])		
	elif len(sys.argv) == 3:
		if sys.argv[1] == '-f':
			fl = open(sys.argv[2],'r')
			for line in fl.readlines():
				print "%s : %s" % (line.strip('\n'), get_type_of(line))
				fl.close()
	else:
		usage()

#@TODO: add filters: web, win, linux, other...
#@TODO: add OS fingerprinting from shadow/SAM file parsing
