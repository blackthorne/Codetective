#!/usr/bin/env python3
# encoding: utf-8
"""
Codetective - a tool to identify cryptographic hashes, encodings, and other artifacts in a byte stream according to traces of its representation
"""

__description__ = 'a tool to identify cryptographic hashes, encodings, and other artifacts in a byte stream according to traces of its representation'
__author__ = 'Francisco da G. T. Ribeiro'
__version__ = '0.9.3'
__license__ = 'GPL'

# Configuration constants
MIN_ENTROPY: float = 3.3
MAX_FILE_WINDOW_SIZE: int = 1_000_000  # recommended: 1000000
MAX_OVERLAP_WINDOW_SIZE: int = 5_000
MIN_AV: int = 5
MAX_PREPROCESS_ERRORS: int = 20
BAD_CHARS: str = "\n\r-"  # chars to be ignored by validators

# Standard library imports
import re
import sys
import argparse
import base64
import string
import math
import io
import struct
import os
import fnmatch
import binascii
import json
import time
from collections import Counter
from functools import lru_cache
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Any, Union, Iterator, Callable, Iterable, cast
from urllib.parse import urlparse
from encodings import aliases
from dataclasses import dataclass, field
from pathlib import Path

# Import configuration system
from config.config import ConfigManager, CodetectiveConfig
CONFIG_AVAILABLE = True

########################################################################
@dataclass
class Finding:
	"""
	Represents a potential finding with metadata about the detection.
	"""
	type: str
	payload: Any
	location: Union[int, Tuple[int, Tuple[int, int]], None] = None
	certainty: int = 0
	details: Optional[str] = None
	# datetime.now() is ~2000x slower than time.time() and findings are created by the thousand
	created_ts: float = field(default_factory=time.time, repr=False)
	
	@property
	def created_on(self) -> datetime:
		"""Time the finding was created."""
		return datetime.fromtimestamp(self.created_ts)
	
	def __post_init__(self) -> None:
		"""Initialize computed fields after dataclass initialization."""
		# Normalize certainty to int
		self.certainty = int(self.certainty or 0)
		if isinstance(self.location, tuple):
			# legacy callers provide (base, (start, end))
			base_offset, span = self.location
			start, end = span
			self.location = base_offset + start
			self.size = end - start if end >= start else 0
		else:
			self.location = int(self.location or 0)
			self.size = 0
		self.details = self.details or ""
	
	@property
	def confidence(self) -> str:
		"""Return confidence level based on certainty score."""
		if self.certainty >= 80:
			return 'confident'
		elif self.certainty >= 60:
			return 'likely'
		else:
			return 'possible'	
		
	def __str__(self) -> str:
		"""String representation of the finding."""
		return f"{self.details}  [{self.confidence}]"
	
	def display(self) -> str:
		"""Display formatted finding information."""
		return f"{self.details}\t({self.type}:{self.location}:{self.confidence}[{self.certainty}]:{self.created_on})"

FILTERS: Tuple[str, ...] = ('win', 'web', 'unix', 'db', 'personal', 'crypto', 'other')

SUPPORTED_ALGORITHMS: Dict[str, str] = {
	'win': 'LM, NTLM, SAM (lm:ntlm, lm:*, *:ntlm)',
	'web': 'web cookies, URLs, JWT, Django (sha256/sha384, salted), Joomla v1/v2 MD5 (salted), WordPress/phpBB3 MD5',
	'unix': 'shadow/crypt: DES, MD5, APR1, SHA256, SHA512, Blowfish (bcrypt)',
	'db': 'MySQL323, MySQL4+, MSSQL2000, MSSQL2005',
	'personal': 'phone numbers, credit cards',
	'crypto': 'all hash, encoding and secret detections (every filter above except URLs and personal data), plus secrets in code',
	'other': 'MD4, MD5, SHA1, SHA224, SHA256, SHA384, SHA512, RipeMD320, Whirlpool, base64, UUID, CRC, URLs, phone numbers, credit cards',
}

@lru_cache(maxsize=65536)
def entropy(s: str) -> float:
	"""
	Calculate the Shannon entropy of a string.
	
	Args:
		s: Input string to calculate entropy for
		
	Returns:
		Shannon entropy value
	"""
	if not s:
		return 0.0
		
	p, lns = Counter(s), len(s)
	return -sum(count/lns * math.log(count/lns, 2) for count in p.values())

class PatternMatcher:
	"""Compiled regex patterns for various crypto/encoding algorithm detection."""
	
	def __init__(self):
		"""Initialize all compiled regex patterns with optimization flags."""
		# Use re.VERBOSE for better readability and re.IGNORECASE where appropriate
		# Compile patterns with re.UNICODE for better international support
		compile_flags = re.UNICODE | re.VERBOSE
		
		self.patterns = {
			# Web-related patterns
			'web-cookie': re.compile(r"""
				;?([\w_:|\-\$\&\%\#\@]+?)=([^;\s\n]+)
			""", compile_flags),
			
			'URL': re.compile(r"""
				(?<![a-zA-Z0-9])[a-zA-Z0-9]+://[a-zA-Z0-9./]+\b
			""", compile_flags),
			
			# Hash patterns - optimized for common cases
			'md5': re.compile(r"(?<![a-fA-F0-9])[a-fA-F\d]{32}(?![a-fA-F0-9])", re.UNICODE),
			'md4': re.compile(r"(?<![a-fA-F0-9])[a-fA-F\d]{32}(?![a-fA-F0-9])", re.UNICODE),
			'sha1': re.compile(r"\b[a-fA-F\d]{40}\b", re.UNICODE),
			'sha224': re.compile(r"\b[a-fA-F\d]{56}\b", re.UNICODE),
			'sha256': re.compile(r"\b[a-fA-F\d]{64}\b", re.UNICODE),
			'sha384': re.compile(r"\b[a-fA-F\d]{96}\b", re.UNICODE),
			'sha512': re.compile(r"\b[a-fA-F\d]{128}\b", re.UNICODE),
			'whirlpool': re.compile(r"\b[a-fA-F\d]{128}\b", re.UNICODE),
			'RipeMD320': re.compile(r"\b[a-fA-F\d]{80}\b", re.UNICODE),
			
			# Database patterns
			'mssql2000': re.compile(r"\b(?:0x0100)?[a-fA-F\d]{88}", re.UNICODE),
			'mssql2005': re.compile(r"\b(?:0x0100)?[a-fA-F\d]{48}\b", re.UNICODE),
			'MySQL4+': re.compile(r"\b(?:\*)?[a-fA-F\d]{40}\b", re.UNICODE),
			'MySQL323': re.compile(r"\b[a-fA-F\d]{16}\b", re.UNICODE),
			
			# Windows patterns
			'lm': re.compile(r"(?<![a-fA-F0-9])[a-fA-F\d]{32}(?![a-fA-F0-9])", re.UNICODE),
			'ntlm': re.compile(r"(?<![a-fA-F0-9])[a-fA-F\d]{32}(?![a-fA-F0-9])", re.UNICODE),
			'SAM(*:ntlm)': re.compile(r"^(\w+:\d+:)?\*:([a-fA-F\d]{32})(?![a-fA-F0-9])", re.UNICODE | re.MULTILINE),
			'SAM(lm:*)': re.compile(r"^(\w+:\d+:)?[a-fA-F\d]{32}:\*", re.UNICODE | re.MULTILINE),
			'SAM(lm:ntlm)': re.compile(r"^(\w+:\d+:)?[a-fA-F\d]{32}:[a-fA-F\d]{32}\b", re.UNICODE | re.MULTILINE),
			
			# Personal data patterns
			'phone': re.compile(r"""
				[^\d]\d{3}[-\.\s]??\d{3}[-\.\s]??\d{4}|
				\(\d{3}\)\s*\d{3}[-\.\s]??\d{4}|
				\d{3}[-\.\s]??\d{4}[^\d]
			""", compile_flags),
			
			'credit': re.compile(r"\b(?:\d[ -]*?){13,16}\b", re.UNICODE),
			
			# Encoding patterns
			'base64': re.compile(r"""
				^(?:[A-Za-z0-9+/]{4})*
				(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$
			""", compile_flags),
			
			'jwt': re.compile(r"[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.([a-zA-Z0-9\-_]+)?", re.UNICODE),
			
			# Unix patterns
			'des-salt-unix': re.compile(r"(?<![a-zA-Z0-9./$])[a-zA-Z0-9./]{13}(?![a-zA-Z0-9./])", re.UNICODE),
			'sha256-salt-unix': re.compile(r"\$5\$[a-zA-Z0-9./]{8,16}\$[a-zA-Z0-9./]{43}(?![a-zA-Z0-9./])", re.UNICODE),
			'sha512-salt-unix': re.compile(r"\$6\$[a-zA-Z0-9./]{8,16}\$[a-zA-Z0-9./]{86}(?![a-zA-Z0-9./])", re.UNICODE),
			'apr1-salt-unix': re.compile(r"\$apr1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{22}(?![a-zA-Z0-9./])", re.UNICODE),
			'md5-salt-unix': re.compile(r"(?<![a-zA-Z0-9.])[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{22}(?![a-zA-Z0-9./])", re.UNICODE),
			'blowfish-salt-unix': re.compile(r"\$2[abxy]?\$(\d{2})\$([a-zA-Z0-9./]{22})([a-zA-Z0-9./]{31})(?![a-zA-Z0-9./])", re.UNICODE),
			
			# Web framework patterns
			'sha256-salt-django': re.compile(r"^(?:sha256|sha1)\$[a-zA-Z\d./]+\$[a-zA-Z0-9./]{64}$", re.UNICODE | re.MULTILINE),
			'sha256-django': re.compile(r"^(?:sha256|sha1)\$\$[a-zA-Z0-9./]{64}$", re.UNICODE | re.MULTILINE),
			'sha384-salt-django': re.compile(r"^sha384\$[a-zA-Z\d.]+\$[a-zA-Z0-9./]{96}$", re.UNICODE | re.MULTILINE),
			'sha384-django': re.compile(r"^sha384\$\$[a-zA-Z0-9./]{96}$", re.UNICODE | re.MULTILINE),
			'md5-wordpress': re.compile(r"(?<![a-zA-Z0-9.])[a-zA-Z0-9./]{31}(?![a-zA-Z0-9.=/])", re.UNICODE),
			'md5-phpBB3': re.compile(r"(?<![a-zA-Z0-9.])[a-zA-Z0-9./]{31}(?![a-zA-Z0-9.=/])", re.UNICODE),
			'md5-joomla2': re.compile(r"(?<![a-zA-Z0-9.])([a-zA-Z0-9./]{32})(?::[a-zA-Z0-9./]{32})?(?![a-zA-Z0-9./])", re.UNICODE),
			'md5-salt-joomla2': re.compile(r"(?<![a-zA-Z0-9.])([a-zA-Z0-9./]{32})(?::[a-zA-Z0-9./]{32})?(?![a-zA-Z0-9./])", re.UNICODE),
			'md5-joomla1': re.compile(r"(?<![a-zA-Z0-9.])([a-zA-Z0-9./]{32})(?::[a-zA-Z0-9./]{16})?(?![a-zA-Z0-9./])", re.UNICODE),
			'md5-salt-joomla1': re.compile(r"(?<![a-zA-Z0-9.])([a-zA-Z0-9./]{32})(?::[a-zA-Z0-9./]{16})?(?![a-zA-Z0-9./])", re.UNICODE),
			
			# Other patterns
			'CRC': re.compile(r"0x[a-fA-F\d]{1,16}\b", re.UNICODE),
			'uuid': re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}(?![a-fA-F0-9])", re.UNICODE),
			'secret': re.compile(r"([^=|:]+)", re.UNICODE),
		}
		
		# Pre-compile commonly used patterns for faster access
		self._common_patterns = {
			'hex_32': re.compile(r"[a-fA-F\d]{32}", re.UNICODE),
			'hex_40': re.compile(r"[a-fA-F\d]{40}", re.UNICODE),
			'hex_64': re.compile(r"[a-fA-F\d]{64}", re.UNICODE),
			'hex_128': re.compile(r"[a-fA-F\d]{128}", re.UNICODE),
		}
	
	def find_matches(self, pattern_type: str, data: str) -> Iterator[re.Match]:
		"""Find all matches for a specific pattern type in the data."""
		if pattern_type not in self.patterns:
			raise ValueError(f"Unknown pattern type: {pattern_type}")
		return self.patterns[pattern_type].finditer(data)
	
	def quick_hash_check(self, data: str) -> Optional[str]:
		"""
		Quick check for common hash patterns to avoid expensive regex operations.
		
		Args:
			data: String to check
			
		Returns:
			Hash type if found, None otherwise
		"""
		# Quick length-based checks first using walrus operator
		if len(data) == 32 and (match := self._common_patterns['hex_32'].match(data)):
			return 'md5'  # Could be md4 or md5
		elif len(data) == 40 and (match := self._common_patterns['hex_40'].match(data)):
			return 'sha1'
		elif len(data) == 64 and (match := self._common_patterns['hex_64'].match(data)):
			return 'sha256'
		elif len(data) == 128 and (match := self._common_patterns['hex_128'].match(data)):
			return 'sha512'  # Could be whirlpool
		
		return None

# Global pattern matcher instance
pattern_matcher = PatternMatcher()

def reg_find(reg_type: str, data: str) -> Iterator[re.Match]:
	"""Find all matches for a specific pattern type in the data."""
	return pattern_matcher.find_matches(reg_type, data)

def get_type_of(sub_text: str, filters: List[str], base_location: int = 0, analyze: bool = False) -> List[Finding]:
	"""
	Analyze text for various crypto/encoding patterns based on provided filters.
	
	Args:
		sub_text: Text to analyze
		filters: List of filter types to apply
		base_location: Base location offset for findings
		analyze: Whether to show detailed analysis
		
	Returns:
		List of Finding objects
	"""
	results = []
	
	for filter_combination, detection_functions in DETECTION_GROUPS.items():
		if any(f in filters for f in filter_combination):
			for detection_func in detection_functions:
				results.extend(detection_func(sub_text, base_location))
		
	return results

def _detect_jwt(sub_text: str, base_location: int) -> List[Finding]:
	"""Detect JWT tokens in the text."""
	results = []
	
	for finding in reg_find('jwt', sub_text):
		data, location = finding.group(), (base_location, finding.span())
		parts = data.split('.')
		# A JWT header is base64url JSON, so it always starts with '{"' -> 'eyJ'
		if len(parts) != 3 or not parts[0].startswith('eyJ'):
			continue
		try:
			header = json.loads(_b64url_decode(parts[0]))
			payload = _b64url_decode(parts[1]).decode('utf-8', errors='replace')
		except (ValueError, binascii.Error):
			continue
		if not isinstance(header, dict) or 'alg' not in header:
			continue
		
		results.append(Finding(
			'jwt',
			data,
			location,
			85,
			f'JWT Token\theader: {json.dumps(header)}\tpayload: {payload}\tsignature: {parts[2]}'
		))
	
	return results

def _b64url_decode(segment: str) -> bytes:
	"""Decode unpadded base64url, as used by JWT segments."""
	return base64.urlsafe_b64decode(segment + '=' * (-len(segment) % 4))

def _detect_secrets(sub_text: str, base_location: int) -> List[Finding]:
	"""Detect potential secrets in the text."""
	results = []
	line_start = 0
	
	for line in sub_text.splitlines(keepends=True):
		lowered = line.lower()
		if any(keyword in lowered for keyword in SECRET_KEYWORDS):
			# The first segment is the key name ('password' in 'password = x'); values follow a separator
			for finding in list(reg_find('secret', line))[1:]:
				value = finding.group().strip()
				stripped_secret = value.strip('"').strip("'").strip()
				if not stripped_secret:
					continue
				start, end = finding.span()
				secret_find = Finding('secret', value, (base_location + line_start, (start, end)), 45, f'Secret: {value}')
				if stripped_secret.lower().startswith(SECRET_FALSE_POSITIVE_PREFIXES):
					secret_find.certainty -= 25
				if entropy(value) > MIN_ENTROPY:
					secret_find.certainty += 40
				results.append(secret_find)
		line_start += len(line)
	
	return results

SECRET_KEYWORDS: Tuple[str, ...] = ('pass', 'key', 'security')
SECRET_FALSE_POSITIVE_PREFIXES: Tuple[str, ...] = ('/', '-', 'keystore_', '{{', '$', 'secret', 'configmap', '[', 'true', 'false')

def _detect_web_cookies(sub_text: str, base_location: int) -> List[Finding]:
	"""Detect web cookies in the text."""
	results = []
	known_cookies = ['_Utm', 'APSESSION', 'sessionID', 'Web_session']
	
	for finding in reg_find('web-cookie', sub_text):
		data, location = finding.group(), (base_location, finding.span())
		if len(data) > 2:
			cookie_find = Finding(
				'web-cookie', 
				finding.groups(), 
				location, 
				45, 
				f'Web cookie name: {finding.groups()[0]}\n\t\tvalue: {finding.groups()[1]}'
			)
			if (any(cookie for cookie in known_cookies if cookie.lower() in finding.groups()[0].lower()) and 
				entropy(finding.groups()[1]) > MIN_ENTROPY):
				cookie_find.certainty += 40
			results.append(cookie_find)
	
	return results

def _detect_urls(sub_text: str, base_location: int) -> List[Finding]:
	"""Detect URLs in the text."""
	results = []
	
	for finding in reg_find('URL', sub_text):
		data, location = finding.group(), (base_location, finding.span())
		parsed_url = urlparse(data)
		
		if parsed_url.scheme and parsed_url.netloc:
			url_find = Finding('URL', data, location, 70, f"URL: {data}\n\t{parsed_url}")
			if parsed_url.path:
				url_find.certainty += 20
			results.append(url_find)
	
	return results

def _detect_phone_numbers(sub_text: str, base_location: int) -> List[Finding]:
	"""Detect phone numbers in the text."""
	results = []
	# The patterns overlap; they all end on the last digit, so key occurrences by it
	seen_ends = set()
	
	# More restrictive phone number patterns with word boundaries
	phone_patterns = [
		r'\b\+?1?[-\.\s]?\(?[2-9]\d{2}\)?[-\.\s]?[2-9]\d{2}[-\.\s]?\d{4}\b',  # US format
		r'\(\d{3}\)\s*\d{3}[-\.\s]?\d{4}',  # (XXX) XXX-XXXX format
		r'\b\d{3}[-\.\s]?\d{3}[-\.\s]?\d{4}\b'  # XXX-XXX-XXXX format
	]
	
	for pattern in phone_patterns:
		for match in re.finditer(pattern, sub_text):
			phone_number = match.group().strip()
			# Remove all non-digit characters to check length
			digits_only = re.sub(r'\D', '', phone_number)
			
			# Validate phone number length (7-15 digits is reasonable for phone numbers)
			# Also exclude credit card patterns (16 digits)
			if 7 <= len(digits_only) <= 15 and len(digits_only) != 16:
				if match.end() not in seen_ends:
					seen_ends.add(match.end())
					location = (base_location, match.span())
					phone_find = Finding('phone', phone_number, location, 40, f'Phone number: {phone_number}')
					
					# Increase certainty for well-formatted numbers
					if re.match(r'^\+?1?[-\.\s]?\(?[2-9]\d{2}\)?[-\.\s]?[2-9]\d{2}[-\.\s]?\d{4}$', phone_number):
						phone_find.certainty += 15
					
					results.append(phone_find)
	
	return results

def _detect_credit_cards(sub_text: str, base_location: int) -> List[Finding]:
	"""Detect credit card numbers in the text."""
	results = []
	
	for finding in reg_find('credit', sub_text):
		data, location = finding.group(), (base_location, finding.span())
		digits = re.sub(r'[ -]', '', data)
		brand = next((name for name, pattern in CARD_BRANDS if pattern.fullmatch(digits)), None)
		
		details = f'Credit card number: {data}'
		certainty = 45
		if brand:
			details += f'\n\tCredit card type: {brand}'
		else:
			certainty -= 30
		# The Luhn checksum rejects ~90% of random digit runs
		if luhn_valid(digits):
			certainty += 30
			details += '\n\tLuhn checksum: valid'
		else:
			certainty -= 30
		
		results.append(Finding('credit', data, location, certainty, details))
	
	return results

CARD_BRANDS: List[Tuple[str, re.Pattern]] = [
	('Visa', re.compile(r"4\d{12}(?:\d{3})?")),
	('Mastercard', re.compile(r"(?:5[1-5]\d{2}|222[1-9]|22[3-9]\d|2[3-6]\d{2}|27[01]\d|2720)\d{12}")),
	('American Express', re.compile(r"3[47]\d{13}")),
	('Diners Club', re.compile(r"3(?:0[0-5]|[68]\d)\d{11}")),
	('Discover', re.compile(r"6(?:011|5\d{2})\d{12}")),
	('JCB', re.compile(r"(?:2131|1800|35\d{3})\d{11}")),
]

def luhn_valid(digits: str) -> bool:
	"""Check a card number's Luhn (mod 10) checksum."""
	if not digits.isdigit():
		return False
	total = 0
	for index, char in enumerate(reversed(digits)):
		value = int(char)
		if index % 2:
			value *= 2
			if value > 9:
				value -= 9
		total += value
	return total % 10 == 0

# Plain hex digests: (pattern key, [(finding type, label, base certainty, bonus if high entropy)])
HEX_DIGESTS: List[Tuple[str, List[Tuple[str, str, int, int]]]] = [
	('sha1', [('sha1', 'SHA1', 15, 50)]),
	('sha224', [('sha224', 'SHA224', 15, 50)]),
	('sha256', [('sha256', 'SHA256', 15, 50)]),
	('RipeMD320', [('RipeMD320', 'RipeMD320', 10, 0)]),
	('sha384', [('sha384', 'SHA384', 15, 50)]),
	('sha512', [('sha512', 'SHA512', 15, 50), ('whirlpool', 'Whirlpool', 5, 15)]),
]

def _detect_hashes(sub_text: str, base_location: int) -> List[Finding]:
	"""Detect various hash types in the text."""
	results = []
	
	for pattern_key, variants in HEX_DIGESTS:
		for finding in reg_find(pattern_key, sub_text):
			digest, location = finding.group(), (base_location, finding.span())
			high_entropy = entropy(digest) > MIN_ENTROPY
			for finding_type, label, certainty, bonus in variants:
				results.append(Finding(finding_type, digest, location,
				                       certainty + (bonus if high_entropy else 0), f'{label} hash: {digest}'))
	
	# MD5/MD4 detection
	for finding in reg_find('md5', sub_text):
		potential_hash, location = finding.group(), (base_location, finding.span())
		
		md5_find = Finding('md5', potential_hash, location, 40, f'MD5 hash: {potential_hash}')
		md4_find = Finding('md4', potential_hash, location, 20, f'MD4 hash: {potential_hash}')
		
		if entropy(potential_hash) > MIN_ENTROPY:
			md5_find.certainty += 40
			md4_find.certainty += 10
		else:
			md5_find.certainty -= 30
			md4_find.certainty -= 10
		
		results.extend([md4_find, md5_find])
	
	return results

def _detect_database_hashes(sub_text: str, base_location: int) -> List[Finding]:
	"""Detect database-related hashes in the text."""
	results = []
	
	# MSSQL 2005 hash detection
	for finding in reg_find('mssql2005', sub_text):
		data, location = finding.group(), (base_location, finding.span())
		hash_matches = re.findall(r"(?:0x0100)?([a-fA-F\d]{8})([a-fA-F\d]{40})", data)
		
		if hash_matches:
			salt, hash_value = hash_matches[0]
			mssql2005_find = Finding(
				'mssql2005', 
				(salt, hash_value), 
				location, 
				55, 
				f'Microsoft SQL Server 2005\n\t\theader: 0x0100\n\t\tsalt: {salt}\n\t\tmixed case hash (SHA1): {hash_value}'
			)
			
			if re.match(r"\b0x0100[a-fA-F\d]{48}\b", data):
				mssql2005_find.certainty += 40
			elif re.match(r"\b[a-fA-F\d]{48}\b", data) and entropy(hash_value) > MIN_ENTROPY:
				mssql2005_find.certainty += 20
			
			results.append(mssql2005_find)
	
	# MSSQL 2000 hash detection
	for finding in reg_find('mssql2000', sub_text):
		data, location = finding.group(), (base_location, finding.span())
		hash_matches = re.findall(r"(?:0x0100)?([a-fA-F\d]{8})([a-fA-F\d]{40})([a-fA-F\d]{40})", data)
		
		if hash_matches:
			salt, mixed_hash, upper_hash = hash_matches[0]
			mssql2000_find = Finding(
				'mssql2000', 
				(salt, mixed_hash, upper_hash), 
				location, 
				55, 
				f'Microsoft SQL Server 2000\n\t\theader: 0x0100\n\t\tsalt: {salt}\n\t\tmixed case hash (SHA1): {mixed_hash}\n\t\tupper case hash (SHA1): {upper_hash}'
			)

			if re.match(r"\b0x0100[a-fA-F\d]{88}\b", data):
				mssql2000_find.certainty += 40
			elif re.match(r"\b[a-fA-F\d]{88}\b", data) and entropy(mixed_hash) > MIN_ENTROPY:
				mssql2000_find.certainty += 20
			
			results.append(mssql2000_find)
	
	# MySQL4+ hash detection
	for finding in reg_find('MySQL4+', sub_text):
		data, location = finding.group(), (base_location, finding.span())
		hash_matches = re.findall(r"\b(?:\*)?([a-fA-F\d]{40})\b", data)
		
		if hash_matches:
			potential_hash = hash_matches[0]
			mysql4_find = Finding('MySQL4+', potential_hash, location, 50, f'MySQL v4 or later hash: {potential_hash}')
			
			if (all(c.isupper() or c.isdigit() for c in potential_hash) and 
				data.startswith('*') and entropy(potential_hash) > MIN_ENTROPY):
				mysql4_find.certainty += 30
			
			results.append(mysql4_find)
	
	# MySQL323 hash detection
	for finding in reg_find('MySQL323', sub_text):
		data, location = finding.group(), (base_location, finding.span())
		hash_matches = re.findall(r"\b([a-fA-F\d]{16})\b", data)
		
		if hash_matches:
			potential_hash = hash_matches[0]
			mysql3_find = Finding('MySQL323', potential_hash, location, 40, f'MySQL v3.23 or previous hash: {potential_hash}')
			
			if (all(c.isupper() or c.isdigit() for c in data) and entropy(potential_hash) > MIN_ENTROPY):
				mysql3_find.certainty += 30
			
			results.append(mysql3_find)
	
	return results

def _detect_windows_hashes(sub_text: str, base_location: int) -> List[Finding]:
	"""Detect Windows-related hashes in the text."""
	results = []
	
	# LM/NTLM hash detection
	for finding in reg_find('lm', sub_text):
		data, location = finding.group(), (base_location, finding.span())
		hash_matches = re.findall(r"(?<![a-fA-F0-9])([a-fA-F\d]{32})(?![a-fA-F0-9])", data)
		
		if hash_matches:
			potential_hash = hash_matches[0]
			lm_find = Finding('lm', potential_hash, location, 50, f'LM hash: {potential_hash}')
			ntlm_find = Finding('ntlm', potential_hash, location, 50, f'NTLM hash: {potential_hash}')
			
			if all(c.isupper() or c.isdigit() for c in data):
				if entropy(potential_hash) > MIN_ENTROPY:
					lm_find.certainty += 30
					ntlm_find.certainty += 30
				else:
					lm_find.certainty += 10
					ntlm_find.certainty += 10
			
			results.extend([lm_find, ntlm_find])
	
	return results

def _detect_sam_hashes(sub_text: str, base_location: int) -> List[Finding]:
	"""Detect SAM file hashes in the text."""
	results = []
	
	# SAM(*:NTLM) detection
	for finding in reg_find('SAM(*:ntlm)', sub_text):
		location = (base_location, finding.span())
		hash_matches = re.findall(r"\*:([a-fA-F\d]{32})\b", finding.group())
		if hash_matches:
			potential_hash = hash_matches[0]
			sam_ntlm_find = Finding('SAM(*:ntlm)', potential_hash, location, 40, f'hashes in SAM file - LM: not defined\tNTLM: {potential_hash}')
			
			if (all(c.isupper() or c.isdigit() for c in potential_hash) and 
				entropy(potential_hash) > MIN_ENTROPY):
				sam_ntlm_find.certainty += 30
				if re.findall(r"^(\w+:\d+:)\*:([a-fA-F\d]{32})(?![a-fA-F0-9])", finding.group()):
					sam_ntlm_find.certainty += 15
			
			results.append(sam_ntlm_find)
	
	# SAM(LM:*) detection
	for finding in reg_find('SAM(lm:*)', sub_text):
		data, location = finding.group(), (base_location, finding.span())
		hash_matches = re.findall(r"([a-fA-F\d]{32}):\*", data)
		
		if hash_matches:
			potential_hash = hash_matches[0]
			sam_lm_find = Finding('SAM(lm:*)', potential_hash, location, 40, f'hashes in SAM file - LM: {potential_hash}\tNTLM: not defined')
			
			if (all(c.isupper() or c.isdigit() for c in potential_hash) and 
				entropy(potential_hash) > MIN_ENTROPY):
				sam_lm_find.certainty += 30
			elif re.match(r"^[\w+:]{4,6}", data) and entropy(potential_hash) > MIN_ENTROPY:
				sam_lm_find.certainty += 45
			
			results.append(sam_lm_find)
	
	# SAM(LM:NTLM) detection
	for finding in reg_find('SAM(lm:ntlm)', sub_text):
		data, location = finding.group(), (base_location, finding.span())
		hash_matches = re.findall(r"^(?:\w+:\d+:)?([a-fA-F\d]{32}):([a-fA-F\d]{32})\b", data)
		
		if hash_matches:
			lm, ntlm = hash_matches[0]
			sam_lm_ntlm_find = Finding('SAM(lm:ntlm)', (lm, ntlm), location, 50, f'hashes in SAM file - LM: {lm}\tNTLM: {ntlm}')
			
			if (re.findall(r"^(\w+:\d+:)", data) and entropy(lm) > MIN_ENTROPY and 
				entropy(ntlm) > MIN_ENTROPY):
				sam_lm_ntlm_find.certainty += 30
				if all(c.isupper() or c.isdigit() for c in lm + ntlm):
					sam_lm_ntlm_find.certainty += 10
			
			results.append(sam_lm_ntlm_find)
	
	return results

def _detect_base64(sub_text: str, base_location: int) -> List[Finding]:
	"""Detect Base64 encoded strings in the text."""
	results = []
	
	for finding in reg_find('base64', sub_text):
		data, location = finding.group(), (base_location, finding.span())
		try:
			decoded = base64.b64decode(data).decode('utf-8', errors='ignore')
			base64_find = Finding('base64', data, location, 40, f'base64 decoded string: {decoded}')
			
			if data.endswith('='):
				base64_find.certainty += 40
			
			results.append(base64_find)
		except (UnicodeDecodeError, ValueError):
			pass
	
	return results

def _detect_uuids(sub_text: str, base_location: int) -> List[Finding]:
	"""Detect UUIDs in the text."""
	results = []
	
	for finding in reg_find('uuid', sub_text):
		data, location = finding.group(), (base_location, finding.span())
		uuid_matches = re.findall(r"(?<![a-fA-F0-9])([a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})(?![a-fA-F0-9])", data)
		
		if uuid_matches:
			number = uuid_matches[0]
			version_matches = re.findall(r"(?<![a-fA-F0-9])[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-([a-fA-F0-9])[a-fA-F0-9]{3}-([a-fA-F0-9])[a-fA-F0-9]{3}-[a-fA-F0-9]{12}(?![a-fA-F0-9])", data)
			
			if version_matches:
				version, subversion = version_matches[0]
				uuid = Finding('uuid', number, location, 75, None)
				
				# UUID version descriptions
				uuid_versions = {
					'1': 'Version 1 (MAC address)',
					'2': 'Version 2 (DCE Security)',
					'3': 'Version 3 (MD5 hash)',
					'4': 'Version 4 (random)' if subversion.upper() in ['8', '9', 'A', 'B'] else f'Version 4 (unknown variant {subversion})',
					'5': 'Version 5 (SHA-1 hash)'
				}
				
				version_desc = uuid_versions.get(version, f'Unknown version {version}')
				uuid.details = f'Universally Unique identifier (UUID) - {version_desc}: {number}'
				
				if version not in uuid_versions:
					uuid.certainty = 5
				
				results.append(uuid)
	
	return results

def _detect_unix_hashes(sub_text: str, base_location: int) -> List[Finding]:
	"""Detect Unix-related hashes in the text."""
	results = []
	
	# DES-salt(UNIX) detection
	for finding in reg_find('des-salt-unix', sub_text):
		data, location = finding.group(), (base_location, finding.span())
		hash_matches = re.findall(r"(?:\w+:)?([a-zA-Z0-9./]{2})([a-zA-Z0-9./]{11})", data)
		
		if hash_matches:
			salt, hash_value = hash_matches[0]
			des_salt_find = Finding(
				'des-salt-unix', 
				(salt, hash_value), 
				location, 
				55, 
				f'UNIX shadow file using salted DES - salt: {salt}\thash: {hash_value}'
			)
			
			if (re.match(r'(?:\w+:)[a-zA-Z0-9./]{13}(?::\d*){2}(?::.*?){2}:.*$', data) and 
				entropy(hash_value) > MIN_ENTROPY):
				des_salt_find.certainty += 25
			
			results.append(des_salt_find)
	
	for pattern_key, extract, certainty, bonus, label in SALTED_UNIX_HASHES:
		results.extend(_salted_hash_findings(sub_text, base_location, pattern_key, extract,
		                                     certainty, bonus, label))
	
	# Blowfish/bcrypt: $2a$<cost>$<22 char salt><31 char hash>
	for finding in reg_find('blowfish-salt-unix', sub_text):
		cost, salt, hash_value = finding.groups()
		blowfish_find = Finding(
			'blowfish-salt-unix',
			(salt, hash_value),
			(base_location, finding.span()),
			55,
			f'UNIX shadow file using salted Blowfish (bcrypt, cost {cost}) - salt: {salt}\thash: {hash_value}'
		)
		if entropy(hash_value) > MIN_ENTROPY:
			blowfish_find.certainty += 30
		results.append(blowfish_find)
	
	return results

# (pattern key, regex extracting (salt, hash), base certainty, bonus if high entropy, description)
SALTED_UNIX_HASHES: List[Tuple[str, str, int, int, str]] = [
	('sha256-salt-unix', r"\$5\$([a-zA-Z0-9./]{8,16})\$([a-zA-Z0-9./]{43})", 55, 25, 'UNIX shadow file using salted SHA256'),
	('sha512-salt-unix', r"\$6\$([a-zA-Z0-9./]{8,16})\$([a-zA-Z0-9./]{86})", 55, 25, 'UNIX shadow file using salted SHA512'),
	('apr1-salt-unix', r"\$apr1\$([a-zA-Z0-9./]{8})\$([a-zA-Z0-9./]{22})", 45, 35, 'Apache htpasswd file (MD5x2000)'),
	('md5-salt-unix', r"([a-zA-Z0-9./]{8})\$([a-zA-Z0-9./]{22})", 45, 35, 'UNIX shadow file using salted MD5'),
]

def _salted_hash_findings(sub_text: str, base_location: int, pattern_key: str, extract: str,
                          certainty: int, bonus: int, label: str,
                          condition: Optional[Callable[[str], bool]] = None) -> List[Finding]:
	"""
	Shared logic for '<prefix><salt>$<hash>' style formats: match `pattern_key`, pull
	(salt, hash) or just (hash,) out with `extract`, and add `bonus` certainty when the hash
	has high entropy (and `condition(matched_text)` holds, if given).
	"""
	results = []
	extract_re = _compiled(extract)
	for finding in reg_find(pattern_key, sub_text):
		data = finding.group()
		match = extract_re.search(data)
		if not match:
			continue
		parts = match.groups()
		hash_value = parts[-1]
		if len(parts) == 2:
			payload: Any = parts
			details = f'{label} - salt: {parts[0]}\thash: {hash_value}'
		else:
			payload = hash_value
			details = f'{label} - hash: {hash_value}'
		salted_find = Finding(pattern_key, payload, (base_location, finding.span()), certainty, details)
		if entropy(hash_value) > MIN_ENTROPY and (condition is None or condition(data)):
			salted_find.certainty += bonus
		results.append(salted_find)
	return results

@lru_cache(maxsize=None)
def _compiled(pattern: str) -> re.Pattern:
	"""Compile (once) a helper regex used inside detectors."""
	return re.compile(pattern)

# (pattern key, regex extracting (salt, hash) or (hash,), description)
DJANGO_HASHES: List[Tuple[str, str, str]] = [
	('sha256-salt-django', r"^(?:sha256|sha1)\$([a-zA-Z\d.]+)\$([a-zA-Z0-9./]{64})$", 'Django shadow file using salted SHA256'),
	('sha256-django', r"^(?:sha256|sha1)\$\$([a-zA-Z0-9./]{64})$", 'Django shadow file using SHA256'),
	('sha384-salt-django', r"^sha384\$([a-zA-Z\d.]+)\$([a-zA-Z0-9./]{96})$", 'Django shadow file using salted SHA384'),
	('sha384-django', r"^sha384\$\$([a-zA-Z0-9./]{96})$", 'Django shadow file using SHA384'),
]

def _is_lowercase_hash(data: str) -> bool:
	return all(c.islower() or c.isdigit() or c == '$' for c in data)

def _detect_web_framework_hashes(sub_text: str, base_location: int) -> List[Finding]:
	"""Detect web framework-related hashes in the text."""
	results = []
	
	for pattern_key, extract, label in DJANGO_HASHES:
		results.extend(_salted_hash_findings(sub_text, base_location, pattern_key, extract, 65, 20, label,
		                                     condition=_is_lowercase_hash))
	
	# WordPress MD5 detection
	for finding in reg_find('md5-wordpress', sub_text):
		data, location = finding.group(), (base_location, finding.span())
		hash_matches = re.findall(r"([a-zA-Z0-9./]{31})", data)
		
		if hash_matches:
			hash_value = hash_matches[0]
			md5_wordpress = Finding('md5-wordpress', hash_value, location, 45, f'Wordpress MD5 - hash: {hash_value}')
			
			if re.match(r"\$P\$[a-zA-Z0-9./]{31}$", data) and entropy(hash_value) > MIN_ENTROPY:
				md5_wordpress.certainty += 40
			elif data.startswith('$'):
				md5_wordpress.certainty += 20
			
			results.append(md5_wordpress)
	
	# phpBB3 MD5 detection
	for finding in reg_find('md5-phpBB3', sub_text):
		data, location = finding.group(), (base_location, finding.span())
		hash_matches = re.findall(r"[a-zA-Z0-9./]{31}", data)
		
		if hash_matches:
			hash_value = hash_matches[0]
			md5_phpbb3 = Finding('md5-phpBB3', hash_value, location, 45, f'phpBB3 MD5 - hash: {hash_value}')
			
			if re.match(r"\$H\$[a-zA-Z0-9./]{31}$", data) and entropy(hash_value) > MIN_ENTROPY:
				md5_phpbb3.certainty += 40
			elif data.startswith('$'):
				md5_phpbb3.certainty += 20
			
			results.append(md5_phpbb3)
	
	# Joomla2 MD5 detection
	for finding in reg_find('md5-joomla2', sub_text):
		data, location = finding.group(), (base_location, finding.span())
		
		if re.findall(r"(?<![a-zA-Z0-9.])([a-z0-9./]{32}):([a-zA-Z0-9./]{32})\b", data) and entropy(re.findall(r"(?<![a-zA-Z0-9.])([a-z0-9./]{32}):([a-zA-Z0-9./]{32})\b", data)[0]) > MIN_ENTROPY:
			hash_matches = re.findall(r"([a-z0-9./]{32}):([a-zA-Z0-9./]{32})", data)
			if hash_matches:
				hash_value, salt = hash_matches[0]
				results.append(Finding(
					'md5-salt-joomla2', 
					(hash_value, salt), 
					location, 
					85, 
					f'Joomla v2 salted MD5 - hash: {hash_value}\tsalt: {salt}'
				))
		elif re.findall(r"(?<![a-zA-Z0-9.])([a-z0-9./]{32})\b", data):
			hash_matches = re.findall(r"([a-z0-9./]{32})", data)
			if hash_matches:
				hash_value = hash_matches[0]
				results.append(Finding('md5-joomla2', hash_value, location, 50, f'Joomla v2 MD5 - hash: {hash_value}'))
	
	# Joomla1 MD5 detection
	for finding in reg_find('md5-joomla1', sub_text):
		data, location = finding.group(), (base_location, finding.span())
		
		if re.findall(r"(?<![a-zA-Z0-9.])([a-z0-9./]{32}):([a-zA-Z0-9./]{16}(?![a-zA-Z0-9./]))", data) and entropy(re.findall(r"(?<![a-zA-Z0-9.])([a-z0-9./]{32}):([a-zA-Z0-9./]{16}(?![a-zA-Z0-9./]))", data)[0]) > MIN_ENTROPY:
			hash_matches = re.findall(r"([a-z0-9./]{32}):([a-zA-Z0-9./]{16})", data)
			if hash_matches:
				hash_value, salt = hash_matches[0]
				results.append(Finding(
					'md5-salt-joomla1', 
					(hash_value, salt), 
					location, 
					85, 
					f'Joomla v1 salted MD5 - hash: {hash_value}\tsalt: {salt}'
				))
		elif re.findall(r"(?<![a-zA-Z0-9.])([a-z0-9./]{32})(?![a-zA-Z0-9./])", data):
			hash_matches = re.findall(r"([a-z0-9./]{32})", data)
			if hash_matches:
				hash_value = hash_matches[0]
				results.append(Finding('md5-joomla1', hash_value, location, 45, f'Joomla v1 MD5 - hash: {hash_value}'))
	
	return results

def _detect_crc(sub_text: str, base_location: int) -> List[Finding]:
	"""Detect CRC values in the text."""
	results = []
	
	for finding in reg_find('CRC', sub_text):
		data, location = finding.group(), (base_location, finding.span())
		crc_matches = re.findall(r"0x([a-fA-F\d]{1,16})\b", data)
		
		if crc_matches:
			potential_crc = crc_matches[0]
			crc_find = Finding('CRC', potential_crc, location, 25, None)
			
			length = len(data[2:])
			if length == 1:
				crc_find.details = f'Cyclic redundancy check - CRC1 or CRC-4-ITU: {potential_crc}'
			elif length == 2:
				crc_find.details = f'Cyclic redundancy check - CRC-4-ITUCRC-5-ITU, CRC-5-EPC, CRC-5-USB, CRC-6-ITU, CRC-7, CRC-8-CCITT, CRC-8-Dallas/Maxim, CRC-8, CRC-8-SAE J1850, CRC-8-WCDMA: {potential_crc}'
			elif length == 3:
				crc_find.details = f'Cyclic redundancy check - CRC-10, CRC-11, CRC-12: {potential_crc}'
			elif length == 4:
				crc_find.details = f'Cyclic redundancy check - CRC-15-CAN, CRC-16-IBM, CRC-16-CCITT, CRC-16-T10-DIF, CRC-16-DNP, CRC-16-DECT: {potential_crc}'
			elif length == 6:
				crc_find.details = f'Cyclic redundancy check - CRC-24, CRC-24-Radix-64: {potential_crc}'
			elif length == 8:
				crc_find.details = f'Cyclic redundancy check - CRC-30, CRC-32, CRC-32C, CRC-32K, CRC-32Q: {potential_crc}'
			elif length == 10:
				crc_find.details = f'Cyclic redundancy check - CRC-40-GSM: {potential_crc}'
			elif length == 16:
				crc_find.details = f'Cycle redundancy check - CRC-64-ISO, CRC-64-ECMA-182: {potential_crc}'
			else:
				crc_find.details = f'invalid CRC? truncated data? {potential_crc}'
				crc_find.certainty -= 15
			
			crc_find.certainty -= 10
			results.append(crc_find)
	
	return results

# Detectors run when any filter in their key is active
DETECTION_GROUPS: Dict[Tuple[str, ...], List[Callable[[str, int], List[Finding]]]] = {
	('web', 'crypto', 'secrets'): [
		_detect_jwt,
		_detect_web_cookies,
		_detect_web_framework_hashes
	],
	('crypto', 'secrets'): [
		_detect_secrets
	],
	('web', 'other'): [
		_detect_urls
	],
	('personal', 'other'): [
		_detect_phone_numbers,
		_detect_credit_cards
	],
	('crypto', 'other'): [
		_detect_hashes,
		_detect_base64,
		_detect_uuids,
		_detect_crc
	],
	('db', 'crypto'): [
		_detect_database_hashes
	],
	('win', 'crypto'): [
		_detect_windows_hashes,
		_detect_sam_hashes
	],
	('unix', 'crypto'): [
		_detect_unix_hashes
	]
}

def generator(data: Union[str, bytes], mode: str) -> Dict[str, str]:
	"""
	Generate various encodings/decodings of the input data.
	
	Args:
		data: Input data to encode/decode
		mode: Mode ('encode', 'decode', or 'both')
		
	Returns:
		Dictionary of encoding/decoding results
	"""
	gen_results: Dict[str, str] = {}
	
	# Normalize input types
	data_bytes: bytes = data if isinstance(data, bytes) else str(data).encode('utf-8', errors='ignore')
	data_str: str = data.decode('utf-8', errors='ignore') if isinstance(data, bytes) else str(data)

	# Courtesy of monkeynut
	for encoding in set(aliases.aliases.values()):
		try:
			if mode in ['both', 'decode']:
				gen_results[f'decoding {encoding}'] = data_bytes.decode(encoding, errors='ignore')
			if mode in ['both', 'encode']:
				gen_results[f'encoding {encoding}'] = data_str.encode(encoding, errors='ignore').decode('latin-1', errors='ignore')
		except (UnicodeDecodeError, UnicodeEncodeError, LookupError):
			continue
	
	return gen_results

VALIDATOR_CHECKS: Dict[str, Callable[[str], bool]] = {
	'NUMERIC': str.isdigit,
	'ALPHA': str.isalpha,
	'LOWER': str.islower,
	'UPPER': str.isupper,
	'ALPHANUMERIC': str.isalnum,
	'SYMBOL': lambda c: not c.isalnum(),
}

def _finding_payload(finding: Finding) -> str:
	"""Flatten a finding's payload into the string validators operate on."""
	if isinstance(finding.payload, tuple):
		payload = "".join(str(item) for item in finding.payload)
	else:
		payload = str(finding.payload) if finding.payload else ""
	return re.sub(f'[{BAD_CHARS}]', '', payload)

def _build_validator(validator: str) -> Optional[Callable[[str], bool]]:
	"""
	Turn 'ALL:UPPER', 'HAS:NUMERIC' or 'SEARCH:<regex>' into a predicate over a payload.
	Returns None (after printing why) for invalid validators.
	"""
	mode, sep, argument = validator.partition(':')
	mode = mode.lower()
	if not sep or not argument:
		print(f"Invalid validator '{validator}': expected ALL:<function>, HAS:<function> or SEARCH:<regex>")
		return None
	
	if mode == 'search':
		try:
			pattern = re.compile(argument)
		except re.error as e:
			print(f"Invalid validator '{validator}': bad regular expression ({e})")
			return None
		return lambda payload: bool(pattern.search(payload))
	
	if mode not in ('all', 'has'):
		print(f"Invalid validator '{validator}': predicate must be ALL, HAS or SEARCH")
		return None
	check = VALIDATOR_CHECKS.get(argument.upper())
	if check is None:
		print(f"Invalid validator '{validator}': function must be one of {', '.join(VALIDATOR_CHECKS)}")
		return None
	quantifier = all if mode == 'all' else any
	return lambda payload: bool(payload) and quantifier(check(c) for c in payload)

def run_validators(results: List[Finding], validators: List[str]) -> List[Finding]:
	"""
	Keep only the findings that satisfy every validator (validators are combined with AND).
	Invalid validators are reported and ignored.
	
	Args:
		results: List of findings to validate
		validators: List of validator strings
		
	Returns:
		Filtered list of findings
	"""
	predicates = [p for p in (_build_validator(v) for v in validators) if p is not None]
	if not predicates:
		return results
	return [finding for finding in results
	        if all(predicate(_finding_payload(finding)) for predicate in predicates)]

def deduplicate_findings(results: List[Finding]) -> List[Finding]:
	"""
	Drop repeated findings (same type, location and payload), e.g. the same hash
	reported by two detectors that share a pattern.
	"""
	seen = set()
	unique = []
	for finding in results:
		key = (finding.type, finding.location, str(finding.payload))
		if key not in seen:
			seen.add(key)
			unique.append(finding)
	return unique
	
def show_results(results: List[Finding], show_details: bool, validators: List[str], min_certainty: int) -> None:
	"""
	Display the results in a formatted way.
	
	Args:
		results: List of findings to display
		show_details: Whether to show detailed information
		validators: List of validators to apply
		min_certainty: Minimum certainty level to display
	"""
	results = deduplicate_findings(results)
	
	if min_certainty > 0:
		results = [finding for finding in results if (finding.certainty or 0) >= min_certainty] 
	
	if validators:
		results = run_validators(results, validators)
	
	for finding in results:
		print(finding.display() if show_details else finding.details)

def unpack(stream: io.BytesIO, fmt: str, verbose: bool = False) -> Optional[Tuple]:
	"""
	Unpack binary data from a stream using the given format.
	
	Args:
		stream: Binary stream to read from
		fmt: Format string for struct.unpack
		verbose: Whether to print error messages
		
	Returns:
		Unpacked data or None if error
	"""
	size = struct.calcsize(fmt)
	buf = stream.read(size)
	unpacked_struct = None
	
	try:
		unpacked_struct = struct.unpack(fmt, buf)
	except struct.error as e:
		if verbose:
			print(f"Error unpacking data: {e}")
	
	return unpacked_struct

def ensure_finished(stream: io.BytesIO, struct_fmt_string: str) -> str:
	"""
	Ensure we have enough data to unpack and return as string.
	
	Args:
		stream: Binary stream to read from
		struct_fmt_string: Format string for struct.unpack
		
	Returns:
		Unpacked data as string
	"""
	unpacked_data = unpack(stream, struct_fmt_string, verbose=False)
	return str(unpacked_data[0]) if unpacked_data else ""

def pre_process(data: bytes, struct_fmt_string: str) -> str:
	"""
	Pre-process binary data using struct format string or special formats.
	
	Args:
		data: Binary data to process
		struct_fmt_string: Format string for struct.unpack or special format ('hex', 'base64')
		
	Returns:
		Processed content as string
	"""
	# Handle special formats
	if struct_fmt_string == "hex":
		try:
			# Decode hex string to bytes, then to string
			hex_string = data.decode('utf-8')
			decoded_bytes = bytes.fromhex(hex_string)
			return decoded_bytes.decode('utf-8', errors='ignore')
		except (ValueError, UnicodeDecodeError):
			return ""
	
	elif struct_fmt_string == "base64":
		try:
			# Decode base64 string to bytes, then to string
			decoded_bytes = base64.b64decode(data)
			return decoded_bytes.decode('utf-8', errors='ignore')
		except (ValueError, UnicodeDecodeError):
			return ""
	
	# Handle regular struct format strings
	stream = io.BytesIO(data)
	processed_content = ''
	
	while True:
		try:	
			# Check if we're at the end of the stream
			if stream.tell() >= len(data):
				break
			
			result = ensure_finished(stream, struct_fmt_string)
			if not result:  # If no more data to process, break
				break
			processed_content += result
		except (TypeError, struct.error):
			break

	return processed_content

def test_encoding(data: str, filters: List[str], analyze: bool, validators: List[str], 
			 verbose: bool, mode: str, min_certainty: int) -> None:
	"""
	Test various encodings/decodings on the data.
	
	Args:
		data: Data to test
		filters: List of filters to apply
		analyze: Whether to show detailed analysis
		validators: List of validators to apply
		verbose: Whether to show verbose output
		mode: Mode ('encode', 'decode', or 'both')
		min_certainty: Minimum certainty level to display
	"""
	transforms = generator(data, mode)
	unchanged = 0
	with_findings = 0
	for codec_name, transformed in sorted(transforms.items()):
		if transformed == data:
			unchanged += 1
			continue
		results = get_type_of(transformed, filters)
		if not results:
			continue
		
		with_findings += 1
		print(f'after {codec_name}:')
		show_results(results, analyze, validators, min_certainty)
	
	if verbose or not with_findings:
		print(f'{len(transforms)} codecs tried: {unchanged} left the data unchanged, '
		      f'{with_findings} exposed findings')

def enumerate_files(root_path: str, pattern: str, recursive: bool = True) -> List[str]:
	"""
	Enumerate files matching the pattern in the given path.
	
	Args:
		root_path: Root directory to search
		pattern: File pattern to match
		recursive: Whether to search recursively
		
	Returns:
		List of matching file paths
	"""
	file_list = []
	
	if recursive:
		print("Enumerating files...")
		root_path_obj = Path(root_path)
		for file_path in root_path_obj.rglob(pattern):
			if file_path.is_file():
				file_list.append(str(file_path))
	else:
		root_path_obj = Path(root_path)
		file_list = [str(f) for f in root_path_obj.glob(pattern) if f.is_file()]
	
	return file_list

def process_file(filename: str, args, validators: List[str], min_certainty: int) -> None:
	"""
	Scan a file (or a pipe such as /dev/stdin) window by window so memory stays bounded.
	
	Args:
		filename: Path to the file to process
		args: Command line arguments
		validators: List of validators to apply
		min_certainty: Minimum certainty level to display
	"""
	window_size = getattr(args, 'window_size', MAX_FILE_WINDOW_SIZE)
	overlap_size = min(getattr(args, 'overlap_size', MAX_OVERLAP_WINDOW_SIZE), window_size // 2)
	try:
		path = Path(filename)
		# Pipes and devices report st_size 0 but still have data
		file_size = path.stat().st_size if path.is_file() else 0
		if path.is_file() and file_size == 0:
			return
		with open(filename, 'rb') as stream:
			_scan_windows(stream, file_size, window_size, overlap_size, filename, args, validators, min_certainty)
	except FileNotFoundError:
		print(f"Error: File '{filename}' not found.")
	except PermissionError:
		print(f"Error: Permission denied accessing file '{filename}'.")
	except OSError as e:
		print(f"Error: OS error accessing file '{filename}': {e}")

def _record_size(preprocessor: str) -> int:
	"""Size of one packed record for a -p struct format (1 for the text formats hex/base64)."""
	if preprocessor in ('hex', 'base64'):
		return 1
	try:
		return max(1, struct.calcsize(preprocessor))
	except struct.error:
		return 1

def _utf8_start(content: bytes, cut: int) -> int:
	"""Move `cut` back (at most 3 bytes) so it doesn't land inside a UTF-8 sequence."""
	for _ in range(3):
		if 0 < cut < len(content) and 0x80 <= content[cut] < 0xC0:
			cut -= 1
	return cut

def _window_boundary(content: bytes, overlap_size: int, record_size: int = 1) -> int:
	"""
	Offset (relative to the window) where this window's findings end and the next window's
	begin. It lies between `overlap_size` and `overlap_size // 2` bytes before the end, so
	anything starting before it has at least `overlap_size // 2` bytes to finish in this
	window: after the last newline, else after the last space/tab, else a cut that doesn't
	split a UTF-8 sequence. Packed records (-p) are never split.
	"""
	end = len(content)
	if record_size > 1:
		return end - end % record_size
	low, high = end - overlap_size, end - overlap_size // 2
	if low >= high:
		return _utf8_start(content, end)
	cut = content.rfind(b'\n', low, high)
	if cut == -1:
		cut = max(content.rfind(b' ', low, high), content.rfind(b'\t', low, high))
	return cut + 1 if cut != -1 else _utf8_start(content, high)

def _window_start(content: bytes, boundary: int, lead_size: int) -> int:
	"""
	Where the next window starts: the beginning of the line holding `boundary` (looking
	back at most `lead_size` bytes), so the text right after the boundary is analysed with
	the same leading context in both windows.
	"""
	low = max(0, boundary - lead_size)
	newline = content.rfind(b'\n', low, boundary)
	return newline + 1 if newline != -1 else _utf8_start(content, low)

def _scan_windows(stream: io.BufferedIOBase, file_size: int, window_size: int, overlap_size: int,
                  filename: str, args, validators: List[str], min_certainty: int) -> None:
	"""
	Read the stream sequentially in windows of `window_size` bytes. Consecutive windows
	share a boundary (preferably a line break) and overlap by up to `overlap_size` bytes
	around it: the earlier window keeps reading past the boundary and the later one starts
	at the beginning of the boundary's line.
	
	Each window reports only the findings that *start* in its own stretch, between the
	previous boundary and its own. Anything shorter than `overlap_size // 2` is therefore
	reported exactly once, whole, and with the same context as in a single pass: no partial
	matches (e.g. the first 40 hex digits of a SHA256 posing as a SHA1), no repeats, and no
	need to remember past findings. The -p/-g transforms don't preserve offsets, so for them
	the windows don't overlap and are only cut at boundaries.
	"""
	record_size = _record_size(args.preprocessor[0]) if args.preprocessor else 1
	disjoint = bool(args.preprocessor or args.generator)
	position = 0  # file offset of content[0]
	lead = 0      # bytes at the start of content that belong to the previous window
	carry = b''
	while True:
		wanted = window_size - len(carry)
		try:
			fresh = stream.read(wanted)
		except (OSError, ValueError) as e:
			print(f"Warning: error reading {filename} at position {position + len(carry)}: {e}")
			fresh = b''
		content = carry + fresh
		if not content:
			break
		last = len(fresh) < wanted  # buffered reads only come back short at EOF
		boundary = len(content) if last else _window_boundary(content, overlap_size, record_size)
		
		if disjoint:
			process_chunk(content[:boundary], args, validators, min_certainty, position)
			next_start = boundary
		else:
			process_chunk(content, args, validators, min_certainty, position,
			              report_limit=None if last else boundary, report_from=lead)
			next_start = boundary if last else _window_start(content, boundary, overlap_size // 2)
		
		lead = boundary - next_start
		position += next_start
		carry = content[next_start:]
		if args.verbose:
			done = position + lead
			total = max(file_size, done)
			progress = f'{done * 100 // total}%' if file_size else f'{done} bytes'
			print(f'progress: {progress}\tlocation: [{done}/{file_size or "?"}]')
		if last:
			break

# Each undecodable byte becomes one U+FFFD, so character offsets still map 1:1 onto it
_UNDECODABLE_BYTES = {code: '\ufffd' for code in range(0xDC80, 0xDD00)}

def _decode_window(content: bytes) -> Tuple[str, Optional[str]]:
	"""
	Decode file bytes as UTF-8. Returns the text to analyse and, when it isn't plain
	ASCII, the surrogate-escaped decoding used to turn character offsets into byte offsets.
	"""
	if content.isascii():
		return content.decode('ascii'), None
	raw = content.decode('utf-8', errors='surrogateescape')
	return raw.translate(_UNDECODABLE_BYTES), raw

def _to_byte_offsets(results: List[Finding], raw: str) -> None:
	"""Convert finding locations from character offsets in `raw` to byte offsets."""
	char_pos = byte_pos = 0
	for finding in sorted(results, key=lambda f: cast(int, f.location)):
		offset = cast(int, finding.location)
		byte_pos += len(raw[char_pos:offset].encode('utf-8', errors='surrogateescape'))
		char_pos = offset
		finding.location = byte_pos

def analyze_data(data: Union[str, bytes], args, validators: List[str], min_certainty: int,
                 position: int = 0, report_limit: Optional[int] = None, report_from: int = 0) -> None:
	"""
	Identify artifacts in one piece of input (a string, a stdin line or a file chunk):
	apply the -p preprocessor, then either the -g generator or plain identification.
	`position` is the byte offset of `data` in the file, so file locations are absolute
	byte offsets. Only findings starting in data[report_from:report_limit] are shown; the
	rest belong to the neighbouring, overlapping, windows.
	"""
	raw: Optional[str] = None
	if args.preprocessor:
		text = pre_process(data if isinstance(data, bytes) else data.encode(), args.preprocessor[0])
	elif isinstance(data, bytes):
		text, raw = _decode_window(data)
	else:
		text = data
	
	if args.generator:
		test_encoding(text, args.filters, args.analyze, validators, args.verbose, args.generator[0], min_certainty)
		return
	
	results = get_type_of(text, args.filters)
	if raw is not None:
		_to_byte_offsets(results, raw)
	if report_from or report_limit is not None:
		limit = len(data) if report_limit is None else report_limit
		results = [finding for finding in results if report_from <= cast(int, finding.location) < limit]
	for finding in results:
		finding.location = cast(int, finding.location) + position
	show_results(results, args.analyze, validators, min_certainty)

def process_chunk(content: bytes, args, validators: List[str], min_certainty: int, position: int,
                  report_limit: Optional[int] = None, report_from: int = 0) -> None:
	"""Analyse one file chunk; errors are reported (with -v) instead of aborting the scan."""
	try:
		analyze_data(content, args, validators, min_certainty, position, report_limit, report_from)
	except Exception as e:
		if args.verbose:
			print(f"Warning: Error processing chunk at position {position}: {e}")

def crack_cipher(data: str, args) -> None:
	"""
	Try to decode/decrypt data with the crypto_toolkit auto-solver (encodings,
	classical ciphers and chains of them) and print the best candidates.
	"""
	import contextlib
	import time
	try:
		from crypto_toolkit import solve_challenge
	except ImportError as e:
		print(f"Error: crack mode requires crypto_toolkit.py next to codetective.py ({e})")
		return
	
	data = data.strip()
	if not data:
		print("Error: nothing to crack (empty input)")
		return
	
	print(f"Cracking {len(data)} characters (depth {args.crack_depth}, min score {args.crack_min_score})...")
	if not args.verbose:
		print("This can take a while at depth 3+. Use -v to see solver progress.")
	
	start = time.time()
	solver_output = contextlib.nullcontext() if args.verbose else contextlib.redirect_stdout(io.StringIO())
	with solver_output:
		results = solve_challenge(
			data,
			max_depth=args.crack_depth,
			max_results=args.crack_top,
			min_score=args.crack_min_score,
			regex_filter=args.crack_regex,
			num_cores=args.crack_cores,
		)
	elapsed = time.time() - start
	
	print(f"\nFinished in {elapsed:.1f}s - {len(results)} candidate(s)\n")
	if not results:
		print("No plausible decoding found. Try a higher -crack-depth or a lower -crack-min-score.")
		return
	
	for rank, result in enumerate(results, 1):
		analysis = result.get('analysis', {})
		decoded = result['decoded'] if isinstance(result['decoded'], str) else repr(result['decoded'])
		print(f"{rank}. [{result['score']}/100] {result.get('method') or ' -> '.join(result.get('chain', []))}")
		print(f"   decoded:  {decoded[:200]}{'...' if len(decoded) > 200 else ''}")
		if analysis.get('segmented'):
			print(f"   reads as: {analysis['segmented'][:200]}")
		if analysis.get('flag'):
			print(f"   flag:     {analysis['flag']}")
		print()
	
	best = results[0]['score']
	if best >= 80:
		print("High confidence in result #1.")
	elif best >= 60:
		print("Result #1 looks plausible - review it.")
	else:
		print("Low confidence - results may need manual review.")

def show_version() -> None:
	"""Display version information."""
	print(f'Codetective v{__version__}')
	print(__author__)

def load_configuration(config_file: Optional[str] = None) -> CodetectiveConfig:
	"""Load configuration from file and environment."""
	if CONFIG_AVAILABLE:
		manager = ConfigManager(config_file)
		return manager.get_config()
	else:
		# Return default configuration if config module not available
		return CodetectiveConfig()

def main() -> None:
	"""Main function to handle command line arguments and execute the tool."""
	try:
		parser = argparse.ArgumentParser(
			description=__description__,
			epilog='use filters for more accurate results. Report bugs, ideas, feedback to: blackthorne@ironik.org'
		)
		
		parser.add_argument('string', type=str, nargs='?',
	                    help='determine algorithm used for <string> according to its data representation')
		parser.add_argument('-t', metavar='filters', 
		                   default=list(FILTERS), type=str, nargs=1, dest='filters',
		                   help=f'filter by source of your string: one or more (comma separated) of {", ".join(FILTERS)}. e.g. -t win,db')
		parser.add_argument('-a', '-analyze', dest='analyze', 
		                   help='show more details whenever possible (expands shadow files fields,...)', 
		                   required=False, action='store_true')
		parser.add_argument('-v', '-verbose', dest='verbose', 
		                   help='verbose mode shows progress status (useful for large files) and time taken', 
		                   required=False, action='store_true')
		parser.add_argument('-m', '-minimum-certainty', dest='min_certainty', nargs=1, 
		                   help='specify the minimum acceptable certainty level for displayed results (0 - 100)', 
		                   type=int)
		parser.add_argument('-p', '--preprocessor', dest='preprocessor', type=str, 
		                   help='<struct format string> interpret bytes as packed binary data. Unpacks contents from different data and endianess types according to format strings patterns as specified on: https://docs.python.org/3/library/struct.html', 
		                   required=False, nargs=1)
		parser.add_argument('-g', '-generator', dest='generator', type=str, nargs=1, 
		                   choices=['encode', 'decode', 'both'],
		                   help='find encoding/decoding algorithm that exposes interesting artifacts (choose: \'encode\', \'decode\', \'both\')')
		parser.add_argument('-v1', '-validator1', dest='validator1', nargs=1, required=False, type=str, 
		                   help='applies validator 1')
		parser.add_argument('-v2', '-validator2', dest='validator2', nargs=1, required=False, type=str, 
		                   help='applies validator 2')
		parser.add_argument('-v3', '-validator3', dest='validator3', nargs=1, required=False, type=str, 
		                   help='applies validator 3')
		parser.add_argument('-r', '-recursive', dest='recursive', 
		                   help='sets recursive mode upon specified directory (current workdir by default). Consider using it with min_certainty option', 
		                   required=False, action='store_true')
		parser.add_argument('-f', '-file', dest='filename', nargs=1, help='load a specified file')
		parser.add_argument('-d', '-directory', dest='directory', nargs=1, help='load a specified directory')
		parser.add_argument('-fp', '-file-pattern', dest='file_pattern', nargs=1, 
		                   help='specified which file pattern to be used with directory (default: \'*\')')
		parser.add_argument('-l', '-list', dest='list', help='lists supported algorithms', 
		                   required=False, action='store_true')
		parser.add_argument('-s', '-stdin', dest='stdin', help='read data from standard input', 
		                   action='store_true')
		parser.add_argument('-ver', '-version', dest='version', help='displays software version', 
		                   action='store_true')
		parser.add_argument('--config', dest='config_file', help='configuration file path', 
		                   type=str)
		
		crack = parser.add_argument_group('crack mode', 'auto-decode encodings and classical ciphers '
		                                  '(base64, hex, Caesar, Vigenere, Bacon, XOR, rail fence, ...) and chains of them')
		crack.add_argument('-c', '-crack', '--crack', dest='crack', action='store_true',
		                   help='try to decode/decrypt the input (string, -f file or -s stdin) instead of identifying it')
		crack.add_argument('-cd', '-crack-depth', dest='crack_depth', type=int, default=2,
		                   help='maximum number of chained layers to try (default: 2; 3 is much slower)')
		crack.add_argument('-ct', '-crack-top', dest='crack_top', type=int, default=5,
		                   help='number of candidates to show (default: 5)')
		crack.add_argument('-cm', '-crack-min-score', dest='crack_min_score', type=int, default=25,
		                   help='minimum plausibility score 0-100 (default: 25)')
		crack.add_argument('-cr', '-crack-regex', dest='crack_regex', type=str, default=None,
		                   help='regex that the answer should match, e.g. "HTB\\{.*\\}" (boosts matching candidates)')
		crack.add_argument('-cc', '-crack-cores', dest='crack_cores', type=int, default=None,
		                   help='worker processes to use (default: all cores but one; 1 = no multiprocessing)')
		
		args = parser.parse_args()
		
		# -t accepts 'win,db' as well as 'win'
		if args.filters is not None and len(args.filters) == 1 and args.filters != list(FILTERS):
			args.filters = [f.strip().lower() for f in args.filters[0].split(',') if f.strip()]
			unknown = [f for f in args.filters if f not in FILTERS]
			if unknown:
				parser.error(f"unknown filter(s): {', '.join(unknown)} (choose from {', '.join(FILTERS)})")
		
		# Load configuration
		config = load_configuration(args.config_file)
		args.window_size = max(1024, config.detection.max_file_window_size)
		args.overlap_size = max(0, config.detection.max_overlap_window_size)
		
		# Command-line -m wins over the configuration file
		if args.min_certainty:
			min_certainty = args.min_certainty[0]
		else:
			min_certainty = config.detection.min_certainty
		validators = [args.__dict__[val][0] for val in ['validator1', 'validator2', 'validator3'] 
		             if args.__dict__[val] is not None]
		file_pattern = '*' if not args.file_pattern else args.file_pattern[0]
		recursive_mode = True if args.recursive else False
		target_directory = args.directory[0] if args.directory else os.getcwd()
		
		# Validate min_certainty range
		if min_certainty < 0 or min_certainty > 100:
			print("Error: Minimum certainty must be between 0 and 100.")
			return
		
		if args.list:
			print("Identification (by filter):")
			for filter_name, algorithms in SUPPORTED_ALGORITHMS.items():
				print(f"  {filter_name:<9} {algorithms}")
			print("Crack mode (-c): base64/32/85, hex, binary, Morse, URL and 25+ other encodings; Caesar/ROT,")
			print("  Vigenere, Beaufort, autokey, Gronsfeld, Porta, affine, Atbash, Bacon, rail fence,")
			print("  columnar/scytale transposition, single-byte XOR and chains of them")
		
		# Crack mode: decode the whole input rather than scanning it for artifacts
		elif args.crack:
			if args.string is not None:
				crack_cipher(args.string, args)
			elif args.filename is not None:
				try:
					with open(args.filename[0], 'r', encoding='utf-8', errors='replace') as f:
						crack_cipher(f.read(), args)
				except OSError as e:
					print(f"Error reading file '{args.filename[0]}': {e}")
			elif args.stdin:
				crack_cipher(sys.stdin.read(), args)
			else:
				print("Error: -crack needs input: a string argument, -f <file> or -s (stdin)")
		
		# String mode
		elif args.string is not None:
			try:
				analyze_data(args.string, args, validators, min_certainty)
			except Exception as e:
				print(f"Error processing string: {e}")
		
		# File mode
		elif args.filename is not None:
			process_file(args.filename[0], args, validators, min_certainty)
		
		# Directory mode
		elif args.directory or recursive_mode:
			try:
				file_list = enumerate_files(target_directory, file_pattern, recursive_mode)
				if not file_list:
					print(f"No files found matching pattern '{file_pattern}' in directory '{target_directory}'")
					return
				for file in file_list:
					print(f"== file: {file}")
					process_file(file, args, validators, min_certainty)
			except OSError as e:
				print(f"Error accessing directory '{target_directory}': {e}")
		
		# Stdin mode
		elif args.stdin:
			line_num = 0
			try:
				for line_num, data in enumerate(sys.stdin, 1):
					analyze_data(data, args, validators, min_certainty)
			except KeyboardInterrupt:
				print("\nInterrupted by user.")
			except Exception as e:
				print(f"Error processing stdin at line {line_num}: {e}")
		
		elif args.version:
			show_version()
		
		else:
			parser.print_help()

	except KeyboardInterrupt:
		print("\nInterrupted by user.")
	except Exception as e:
		print(f"Unexpected error: {e}")
		if '-v' in sys.argv or '-verbose' in sys.argv:
			import traceback
			traceback.print_exc()

if __name__ == '__main__':
	main()
