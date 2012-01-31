#!/usr/bin/env python
# encoding: utf-8
__description__ = 'a simple tool to determine the crypto/encoding algorithm used according to traces of its representation'
__author__ = 'Francisco da Gama Tabanez Ribeiro'
__version__ = '0.5'
__date__ = '2011/12/04'
__license__ = 'WTFPL'

import re,sys,argparse,base64

def show(results, result_details, code, analyze=False):
	for key in results.keys():
		if(len(results[key]) > 0):
			print '%s:' % key,results[key]
			for codetype in results[key]:
				if codetype in result_details.keys():
					print '\t',result_details[codetype]
	if(len(results['confident']) + len(results['likely']) + len(results['possible']) == 0):
		print 'unknown! ;('

def get_type_of(data, filters, analyze=False):
	results={'confident':[],'likely':[],'possible':[]}
	result_details={}
	if re.findall(r"\b[a-fA-F\d]{32}\b", data): # md4 or md5
		if(any(x for x in filters if x in ['web','other'])):
			results['confident'].append('md5')
			results['possible'].append('md4')
		else:
			results['likely'].append('md5')
			results['possible'].append('md4')
	if re.findall(r"\b[a-fA-F\d]{32}\b", data) and 'win' in filters: # lm or ntlm
		if(all(chr.isupper() or chr.isdigit() for chr in data)):
			results['confident']+=['lm','ntlm']
		else:
			results['likely']+=['lm','ntlm']
	if re.findall(r"\*\b[a-fA-F\d]{40}\b", data) and 'db' in filters: # MySQL4+
		result_details['MySQL4+']='MySQL v4 or later hash: %s' % re.findall(r"\*(\b[a-fA-F\d]{40})\b", data)
		if(all(chr.isupper() or chr.isdigit() for chr in data)):
			results['confident'].append('MySQL4+')
		else:
			results['likely'].append('MySQL4+')		
	if re.match(r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$", data) and 'other' in filters: # base64
		result_details['base64']='base64 decoded string: %s' % base64.b64decode(data)
		if(data.endswith('=')):
			results['confident']+=['base64']
		else:
			results['possible']+=['base64']
	if re.findall(r"^(\w+:\d+:)?\*:[a-fA-F\d]{32}", data) and 'win' in filters: # SAM(*:NTLM)
		result_details['SAM(*:ntlm)']='hashes in SAM file - NT:not defined\tNTLM:%s' % re.match(r"^\w+:\d+:?\*:([a-fA-F\d]{32})",data).group(1)
		if(all(chr.isupper() for chr in data)):
			results['confident']+=['SAM(*:ntlm)']
		else:
			results['possible']+=['SAM(*:ntlm)']
	if re.findall(r"^(\w+:\d+:)?[a-fA-F\d]{32}:\*", data) and 'win' in filters: # SAM(LM:*)
		result_details['SAM(lm:*)']='hashes in SAM file - LM:%s\tNTLM:not defined' % re.match(r"^\w+:\d+:?([a-fA-F\d]{32}):\*",data).group(1)		
		if(all(chr.isupper() or chr.isdigit() for chr in data)):
			results['confident']+=['SAM(lm:*)']
		elif(re.match(r"^[\w+:]{4,6}", data)):
			results['confident']+=['SAM(lm:*)']
		else:
			results['possible']+=['SAM(lm:*)']
	if re.findall(r"^(\w+:\d+:)?[a-fA-F\d]{32}:[a-fA-F\d]{32}\b", data) and 'win' in filters: # SAM(LM:NTLM)
		result_details['SAM(lm:ntlm)']='hashes in SAM file - LM:%s\tNTLM:%s' % re.match(r"^\w+:\d+:?([a-fA-F\d]{32}):([a-fA-F\d]{32})\b",data).groups()	
		if(all(chr.isupper() or chr.isdigit() or chr == '$' for chr in data)):
			results['confident']+=['SAM(lm:ntlm)']
		elif(re.match(r"^[\w+:]{4}", data)):
			results['confident']+=['SAM(lm:ntlm)']
		else:
			results['possible']+=['SAM(lm:ntlm)']
	if re.findall(r"^\b[a-fA-F\d]{80}\b$", data) and 'other' in filters: # RipeMD320
		results['possible'].append('RipeMD320')
	if re.findall(r"^\b[a-fA-F\d]{40}\b$", data) and 'other' in filters: # SHA1
		results['likely'].append('sha1')
	if re.findall(r"^\b[a-fA-F\d]{56}\b$",data) and 'other' in filters: # SHA224
		results['likely'].append('sha224')
	if re.findall(r"\b[a-fA-F\d]{64}\b", data) and 'other' in filters: # SHA256
		results['likely'].append('sha256')
	if re.findall(r"\b[a-fA-F\d]{96}\b", data) and 'other' in filters: # SHA384
		results['likely'].append('sha384')
	if re.findall(r"\b[a-fA-F\d]{128}\b", data) and 'other' in filters: # SHA512 or Whirlpool
		results['likely']+=['sha512','whirlpool']
	if re.findall(r"\b[a-fA-F\d]{16}\b", data) and 'db' in filters: # MySQL323
		result_details['MySQL323']='MySQL v3.23 or previous hash: %s' % re.findall(r"\b([a-fA-F\d]{16})\b", data)
		if(filters == ['db'] and all(chr.isupper() or chr.isdigit() for chr in data)):
			results['confident'].append('mysql323')
		else:
			results['likely'].append('mysql323')
	if re.findall(r"0x[a-fA-F\d]{1,16}", data) and 'other' in filters: # CRC
		if len(data[2:]) == 1:
			result_details['CRC']='Cyclic redundancy check: CRC1 or CRC-4-ITU'
		elif len(data[2:]) == 2:
			result_details['CRC']='Cyclic redundancy check: CRC-4-ITUCRC-5-ITU, CRC-5-EPC, CRC-5-USB, CRC-6-ITU, CRC-7, CRC-8-CCITT, CRC-8-Dallas/Maxim, CRC-8, CRC-8-SAE J1850, CRC-8-WCDMA'
		elif len(data[2:]) == 3:
			result_details['CRC']='Cyclic redundancy check: CRC-10, CRC-11, CRC-12'
		elif len(data[2:]) == 4:
			result_details['CRC']='Cyclic redundancy check: CRC-15-CAN, CRC-16-IBM, CRC-16-CCITT, CRC-16-T10-DIF, CRC-16-DNP, CRC-16-DECT'
		elif len(data[2:]) == 6:
			result_details['CRC']='Cyclic redundancy check: CRC-24, CRC-24-Radix-64'
		elif len(data[2:]) == 8:
			result_details['CRC']='Cyclic redundancy check: CRC-30, CRC-32, CRC-32C, CRC-32K, CRC-32Q'
		elif len(data[2:]) == 10:
			result_details['CRC']='Cyclic redundancy check: CRC-40-GSM'
		elif len(data[2:]) == 16:
			result_details['CRC']='Cycle redundancy check: CRC-64-ISO, CRC-64-ECMA-182'
		else: 
			result_details['CRC']='invalid CRC? truncated data?'
		results['possible'].append('CRC')
	if re.findall(r"\b(?<!\$)[a-zA-Z0-9./]{13}\b", data) and 'unix' in filters: # DES-salt(UNIX)
		result_details['des-salt-unix']='UNIX shadow file using salted DES - salt:%s\thash:%s' % re.findall(r"(?:\w+:)?([a-zA-Z0-9./]{2})([a-zA-Z0-9./]{11})\b",data)[0]	
		if(filters == ['unix'] or re.match(r'(?:\w+:)[a-zA-Z0-9./]{13}(?::\d*){2}(?::.*?){2}:.*$', data)):
			results['confident'].append('des-salt-unix')
		else:
			results['possible'].append('des-salt-unix')
	if re.findall(r"^(?:sha256|sha1)\$[a-zA-Z\d\.]+\$[a-zA-Z0-9./]{64}$", data) and 'web' in filters: # SHA256-salt(Django)
		result_details['sha256-salt-django']='Django shadow file using salted SHA256 - salt:%s\thash:%s' % re.findall(r"^(?:sha256|sha1)\$([a-zA-Z\d\.]+)\$([a-zA-Z0-9./]{64})$", data)[0]
		if(all(chr.islower() or chr.isdigit() or chr == '$' for chr in data)):
			results['confident'].append('sha256-salt-django')
		else:
			results['likely'].append('sha256-salt-django')
	if re.findall(r"^(?:sha256|sha1)\$\$[a-zA-Z0-9./]{64}$", data) and 'web' in filters: # SHA256(Django)
		result_details['sha256-django']='Django shadow file using SHA256 - hash:%s' % re.findall(r"^(?:sha256|sha1)\$\$([a-zA-Z0-9./]{64})$", data)[0]
		if(all(chr.islower() or chr.isdigit() or chr == '$' for chr in data)):
			results['confident'].append('sha256-django')
		else:
			results['likely'].append('sha256-django')
	if re.findall(r"^sha384\$[a-zA-Z\d\.]+\$[a-zA-Z0-9./]{96}$", data) and 'web' in filters: # SHA384-salt(Django)
		result_details['sha384-salt-django']='Django shadow file using salted SHA384 - salt:%s\thash:%s' % re.findall(r"^sha384\$([a-zA-Z\d\.]+)\$([a-zA-Z0-9./]{96})$", data)[0]
		if(all(chr.islower() or chr.isdigit() or chr == '$' for chr in data)):
			results['confident'].append('sha384-salt-django')
		else:
			results['likely'].append('sha384-salt-django')
	if re.findall(r"^sha384\$\$[a-zA-Z0-9./]{96}$", data) and 'web' in filters: # SHA384(Django)
		result_details['sha384-django']='Django shadow file using SHA384 - hash:%s' % re.findall(r"^sha384\$\$([a-zA-Z0-9./]{96})$", data)[0]
		if(all(chr.islower() or chr.isdigit() or chr == '$' for chr in data)):
			results['confident'].append('sha384-django')
		else:
			results['likely'].append('sha384-django')
	if re.findall(r"\$5\$[a-zA-Z0-9./]{8,16}\$[a-zA-Z0-9./]{43}", data) and 'unix' in filters: # SHA256-salt(UNIX)
		result_details['sha256-salt-unix']='UNIX shadow file using salted SHA256 - salt: %s\thash: %s' % re.findall(r"\$5\$([a-zA-Z0-9./]{8,16})\$([a-zA-Z0-9./]{43})", data)
		results['confident'].append('sha256-salt-unix')
	if re.findall(r"\$6\$[a-zA-Z0-9./]{8,16}\$[a-zA-Z0-9./]{86}", data) and 'unix' in filters: # SHA512-salt(UNIX)
		result_details['sha512-salt-unix']='UNIX shadow file using salted SHA512 - salt: %s\thash: %s' % re.findall(r"\$6\$([a-zA-Z0-9./]{8,16})\$([a-zA-Z0-9./]{86})", data)
		results['confident'].append('sha512-salt-unix')
	if re.findall(r"\$apr1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{22}", data) and 'unix' in filters: # APR1-salt(Apache)
		result_details['apr1-salt-unix']='Apache htpasswd file (MD5x2000)- salt: %s\thash: %s' % re.findall(r"\$apr1\$([a-zA-Z0-9./]{8})\$([a-zA-Z0-9./]{22})", data)[0]
		results['confident'].append('apr1-salt-unix')
	if re.findall(r"[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{22}", data) and 'unix' in filters: # MD5-salt(UNIX)
		result_details['md5-salt-unix']='UNIX shadow file using salted MD5 - salt: %s\thash: %s' % re.findall(r"([a-zA-Z0-9./]{8})\$([a-zA-Z0-9./]{22})", data)[0]
		results['confident'].append('md5-salt-unix')
	if re.findall(r"[a-zA-Z0-9./]{31}$", data) and 'web' in filters:  # MD5(Wordpress)
		result_details['md5-wordpress']='Wordpress MD5 - hash: %s' % re.findall("([a-zA-Z0-9./]{31})$", data)[0]
		if re.match(r"\$P\$[a-zA-Z0-9./]{31}$", data):
			results['confident'].append('md5-wordpress')
		elif filters == ['web'] and data.startswith('$'):
			results['likely'].append('md5-wordpress')
		else:
			results['possible'].append('md5-wordpress')
	if re.findall(r"[a-zA-Z0-9./]{31}$", data) and 'web' in filters:  # MD5(phpBB3)
		result_details['md5-phpBB3']='phpBB3 MD5 - hash: %s' % re.findall("[a-zA-Z0-9./]{31}$", data)[0]
		if re.match(r"\$H\$[a-zA-Z0-9./]{31}$", data):
			results['confident'].append('md5-phpBB3')
		elif filters == ['web'] and data.startswith('$'):
			results['likely'].append('md5-phpBB3')
		else:
			results['possible'].append('md5-phpBB3')
	if re.match(r"\b([a-zA-Z0-9./]{32})(?::[a-zA-Z0-9./]{32}\b)?", data) and 'web' in filters:  # MD5-salt(joomla2)
		if(re.findall(r"\b([a-z0-9./]{32}):([a-zA-Z0-9./]{32})\b", data)):
			result_details['md5-salt-joomla2']='Joomla v2 salted MD5 - hash:%s\tsalt:%s' % re.findall(r"([a-z0-9./]{32}):([a-zA-Z0-9./]{32})", data)[0]
			results['confident'].append('md5-salt-joomla2')
		elif(re.findall(r"\b([a-z0-9./]{32})\b", data)):
			result_details['md5-joomla2']='Joomla v2 MD5 - hash:%s' % re.findall(r"([a-z0-9./]{32})", data)[0]
			results['likely'].append('md5-joomla2')
#		else:
#			results['possible'].append('md5-salt-joomla2')
	if re.findall(r"\b([a-zA-Z0-9./]{32}\b)(?::[a-zA-Z0-9./]{16}\b)?", data) and 'web' in filters:  # MD5-salt(joomla1)
		if(re.findall(r"([a-z0-9./]{32}):([a-zA-Z0-9./]{16})", data)):
			result_details['md5-salt-joomla1']='Joomla v1 salted MD5 - hash:%s\tsalt:%s' % re.findall(r"([a-z0-9./]{32}):([a-zA-Z0-9./]{16})", data)[0]
			results['confident'].append('md5-salt-joomla1')
		elif(re.findall(r"\b([a-z0-9./]{32})\b", data)):
			result_details['md5-joomla1']='Joomla v1 MD5 - hash:%s' % re.findall(r"([a-z0-9./]{32})", data)[0]
			results['likely'].append('md5-joomla1')
#		else:
#			results['possible'].append('md5-salt-joomla1')	
	if re.findall(r"\$(?:2a|2)\$[a-zA-Z0-9./]{2}\$[a-zA-Z0-9./]{53}", data) and 'unix' in filters:  # Blowfish(UNIX)
		result_details['blowfish-salt-unix']='UNIX shadow file using salted Blowfish - salt: %s\thash: %s' % re.findall(r"\$(?:2a|2)\$([a-zA-Z0-9./]{2})\$([a-zA-Z0-9./]{53})", data)[0]
		results['confident'].append('blowfish-salt-unix')
	return results,result_details

		
if __name__ == '__main__':
	parser = argparse.ArgumentParser(description=__description__,
	                                 epilog='use filters for more accurate results')	           
	parser.add_argument('string',type=str,nargs='?',
	                    help='determine algorithm used for <string> according to its data representation')
	parser.add_argument('-t', metavar='filters', default=['win','web','unix','db','other'], type=str, nargs=1,
                   dest='filters', help='filter by source of your string. can be: win, web, db, unix or other')
	parser.add_argument('-a', '-analyze', dest='analyze', help='show more details whenever possible (expands shadow files fields,...)', required=False, action='store_true')
	parser.add_argument('-f','-file', dest='filename', nargs=1, help='load a file')
	parser.add_argument('-l','-list', dest='list', help='lists supported algorithms', required=False, action='store_true')
	args=parser.parse_args()
	if(args.list): 
		print "shadow and SAM files, phpBB3, Wordpress, Joomla, CRC, LM, NTLM, MD4, MD5, Apr, SHA1, SHA256, base64, MySQL323, MYSQL4+, DES, RipeMD320, Whirlpool, SHA1, SHA224, SHA256, SHA384, SHA512, Blowfish"
	elif(args.string is not None):
		results,result_details = get_type_of(args.string, args.filters)
		show(results, result_details, args.string, args.analyze)
	elif(args.filename is not None):
		fl = open(args.filename[0],'r')
		for line in fl.readlines():
			results,result_details = get_type_of(line, args.filters)
			print "%s : %s" % (line.strip('\n'), results)
			print result_details or 'No details available'
		fl.close()
	else:
		parser.print_help()
		
#@TODO: add OS fingerprinting from shadow/SAM file parsing