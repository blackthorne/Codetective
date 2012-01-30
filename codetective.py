#!/usr/bin/env python
# encoding: utf-8
__description__ = 'a simple tool to determine the crypto/encoding algorithm used according to traces of its representation'
__author__ = 'Francisco da Gama Tabanez Ribeiro'
__version__ = '0.3'
__date__ = '2011/12/04'
__license__ = 'WTFPL'

import re,sys,argparse

def show(results):
	for key in results.keys():
		if(len(results[key]) > 0):
			print '%s:' % key,
			print results[key]
	if(len(results['confident']) + len(results['likely']) + len(results['possible']) == 0):
		print 'unknown! ;('

def get_type_of(data, filters):
	results={'confident':[],'likely':[],'possible':[]}
	if re.match(r"^\b[a-fA-F\d]{32}\b$", data) and 'other' in filters: # md4 or md5
		results['likely']+=['md5']
		results['possible']+=['md4']
	if re.match(r"^\b[a-fA-F\d]{32}\b$", data) and 'win' in filters: # lm or ntlm
		results['likely']+=['lm','ntlm']
	if re.match(r"^\*\b[a-fA-F\d]{40}\b$", data) and 'db' in filters: # MySQL4+
		results['confident']+=['MySQL4+']
	if re.match(r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$", data) and 'other' in filters: # base64
		if(data.endswidth('=')):
			results['confident']+=['base64']
		else:
			results['possible']+=['base64']
	if re.match(r"^\*:[a-fA-F\d]{32}\b", data) and 'win' in filters: # SAM(*:NTLM)
		if(all(chr.isupper() for chr in data)):
			results['confident']+=['SAM(*:ntlm)']
		else:
			results['possible']+=['SAM(*:ntlm)']
	if re.match(r"^[a-fA-F\d]{32}:\*\b", data) and 'win' in filters: # SAM(LM:*)
		if(all(chr.isupper() for chr in data)):
			results['confident']+=['SAM(lm:*)']
		else:
			results['possible']+=['SAM(lm:*)']
	if re.match(r"^\b\w+:\d+:[a-fA-F\d]{32}:[a-fA-F\d]{32}\b", data) and 'win' in filters: # SAM(LM:NTLM)
		if(all(chr.isupper() for chr in data)):
			results['confident']+=['SAM(lm:ntlm)']
		else:
			results['possible']+=['SAM(lm:ntlm)']
	if re.match(r"^\b[a-fA-F\d]{80}\b$", data) and 'other' in filters: # RipeMD320
		results['possible'].append('RipeMD320')
	if re.match(r"^\b[a-fA-F\d]{40}\b$", data) and 'other' in filters: # SHA1
		results['likely'].append('sha1')
	if re.match(r"^\b[a-fA-F\d]{56}\b$",data) and 'other' in filters: # SHA224
		results['likely'].append('sha224')
	if re.match(r"\b[a-fA-F\d]{64}\b", data) and 'other' in filters: # SHA256
		results['likely'].append('sha256')
	if re.match(r"\b[a-fA-F\d]{96}\b", data) and 'other' in filters: # SHA384
		results['likely'].append('sha384')
	if re.match(r"\b[a-fA-F\d]{128}\b", data) and 'other' in filters: # SHA512 or Whirlpool
		results['likely']+=['sha512','whirlpool']
	if re.match(r"^[a-fA-F\d]{16}$", data) and 'db' in filters: # MySQL323
		if(filters == ['db']):
			results['confident'].append('mysql323')
		else:
			results['likely'].append('mysql323')
	if re.match(r"^0x[a-fA-F\d]{1,16}$", data) and 'other' in filters: # CRC
		results['possible'].append('CRC')
	if re.match(r"[a-zA-Z0-9./]{2}[a-zA-Z0-9./]{11}", data) and 'unix' in filters: # DES-salt(UNIX)
		if(filters == ['unix']):
			results['confident'].append('des-salt-unix')
		else:
			results['possible'].append('des-salt-unix')
	if re.match(r"sha256\$[a-zA-Z\d\.]+\$[a-zA-Z0-9./]{64}", data) and 'web' in filters: # SHA256(Django)
		if(filters == ['web']):
			results['confident'].append('sha256-django')
		else:
			results['likely'].append('sha256-django')
	if re.match(r"sha384\$[a-zA-Z\d\.]+\$[a-zA-Z\d\.]{96}", data) and 'web' in filters: # SHA384(Django)
		if(filters == ['web']):
			results['confident'].append('sha384-django')
		else:
			results['likely'].append('sha384-django')
	if re.match(r"sha1\$[a-zA-Z\d\.]+\$[a-zA-Z\d\.]{96}", data) and 'web' in filters: # SHA1(Django)
		if(filters == ['web']):
			results['confident'].append('sha1-django')
		else:
			results['likely'].append('sha1-django')
	if re.match(r"\$5\$[a-zA-Z0-9./]{8,16}\$[a-zA-Z0-9./]{43}", data) and 'unix' in filters: # SHA256-salt(UNIX)
		results['confident'].append('sha256-salt-unix')
	if re.match(r"\$6\$[a-zA-Z0-9./]{8,16}\$[a-zA-Z0-9./]{86}", data) and 'unix' in filters: # SHA512-salt(UNIX)
		results['confident'].append('sha512-salt-unix')
	if re.match(r"\$1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{22}", data) and 'unix' in filters: # MD5-salt(UNIX)
		results['confident'].append('md5-salt-unix')
	if re.match(r"\$P\$[a-zA-Z0-9./]{31}$", data) and 'web' in filters:  # MD5(Wordpress)
		results['confident'].append('md5-wordpress')
	if re.match(r"\$H\$[a-zA-Z0-9./]{31}$", data) and 'web' in filters:  # MD5(phpBB3)
		results['confident'].append('md5-phpBB3')
	if re.match(r"^[a-zA-Z0-9./]{32}:[a-zA-Z0-9./]{32}$", data) and 'web' in filters:  # MD5-salt(joomla2)
		if(filters == ['web']):
			results['confident'].append('md5-salt-joomla2')
		else:
			results['likely'].append('md5-salt-joomla2')
	if re.match(r"^[a-zA-Z0-9./]{32}:[a-zA-Z0-9./]{16}$", data) and 'web' in filters:  # MD5-salt(joomla1)
		if(filters == ['web']):
			results['confident'].append('md5-salt-joomla1')
		else:
			results['likely'].append('md5-salt-joomla1')
	if re.match(r"\$2a\$[a-zA-Z0-9./]{2}\$[a-zA-Z0-9./]{53}", data) and 'unix' in filters:  # Blowfish(UNIX)
		results['confident'].append('blowfish-salt-unix')
	return results

		
if __name__ == '__main__':
	parser = argparse.ArgumentParser(description=__description__,
	                                 epilog='use filters for more accurate results')	           
	parser.add_argument('string',type=str,nargs='?',
	                    help='determine algorithm used for <string> according to its data representation')
	parser.add_argument('-t', metavar='filters', default=['win','web','unix','db','other'], type=str, nargs=1,
                   dest='filters', help='filter by source of your string. can be: win, web, db, unix or other')
	parser.add_argument('-f','-file', dest='filename', nargs=1, help='load a file')
	parser.add_argument('-l','-list', dest='list', help='lists supported algorithms', required=False, action='store_true')
	args=parser.parse_args()
	if(args.list): 
		print "shadow and SAM files, phpBB3, Wordpress, Joomla, CRC, LM, NTLM, MD4, MD5, SHA1, SHA256, base64, MySQL323, MYSQL4+, DES, RipeMD320, Whirlpool, SHA1, SHA224, SHA256, SHA384, SHA512, Blowfish"
	elif(args.string is not None):
		results = get_type_of(args.string,args.filters)
		show(results)
	elif(args.filename is not None):
		fl = open(args.filename[0],'r')
		for line in fl.readlines():
			print "%s : %s" % (line.strip('\n'), get_type_of(line, args.filters))
		fl.close()
	else:
		parser.print_help()
		
#@TODO: add OS fingerprinting from shadow/SAM file parsing
#@TODO: analyse option for shadow files