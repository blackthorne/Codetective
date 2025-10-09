#!/usr/bin/env python3
# encoding: utf-8
"""
Codetective - a tool to identify cryptographic hashes, encodings, and other artifacts in a byte stream according to traces of its representation
"""

__description__ = 'a tool to identify cryptographic hashes, encodings, and other artifacts in a byte stream according to traces of its representation'
__author__ = 'Francisco da G. T. Ribeiro'
__version__ = '0.9.0'
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
from collections import Counter
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Any, Union, Iterator
from urllib.parse import urlparse
from encodings import aliases
from dataclasses import dataclass, field
from pathlib import Path

# Import configuration system
try:
    from config import ConfigManager, CodetectiveConfig, ConfigFormat
    CONFIG_AVAILABLE = True
except ImportError:
    CONFIG_AVAILABLE = False
    # Fallback configuration class
    @dataclass
    class CodetectiveConfig:
        min_entropy: float = 3.3
        max_file_window_size: int = 1_000_000
        max_overlap_window_size: int = 5_000
        min_av: int = 5
        max_preprocess_errors: int = 20
        bad_chars: str = "\n\r-"

########################################################################
@dataclass
class Finding:
	"""
	Represents a potential finding with metadata about the detection.
	"""
	type: str
	payload: Any
	location: Optional[Tuple[int, Tuple[int, int]]] = None
	certainty: Optional[int] = None
	details: Optional[str] = None
	created_on: datetime = field(default_factory=datetime.now)
	
	def __post_init__(self) -> None:
		"""Initialize computed fields after dataclass initialization."""
		if self.location:
			# Safely unpack (base_offset, (start, end)) and compute absolute location and size
			base_offset, span = self.location
			start, end = span
			self.location = base_offset + start
			self.size = end - start if end >= start else 0
		else:
			self.location = 0
			self.size = 0
		self.certainty = self.certainty or 0
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
			'md5': re.compile(r"[a-fA-F\d]{32}", re.UNICODE),
			'md4': re.compile(r"[a-fA-F\d]{32}", re.UNICODE),
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
			'SAM(*:ntlm)': re.compile(r"^(\w+:\d+:)?:([a-fA-F\d]{32})(?![a-fA-F0-9])", re.UNICODE),
			'SAM(lm:*)': re.compile(r"^(\w+:\d+:)?[a-fA-F\d]{32}:\*", re.UNICODE),
			'SAM(lm:ntlm)': re.compile(r"^(\w+:\d+:)?[a-fA-F\d]{32}:[a-fA-F\d]{32}\b", re.UNICODE),
			
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
			'blowfish-salt-unix': re.compile(r"[a-zA-Z0-9./]{2}\$[a-zA-Z0-9./]{53}(?![a-zA-Z0-9./])", re.UNICODE),
			
			# Web framework patterns
			'sha256-salt-django': re.compile(r"^(?:sha256|sha1)\$[a-zA-Z\d./]+\$[a-zA-Z0-9./]{64}$", re.UNICODE),
			'sha256-django': re.compile(r"^(?:sha256|sha1)\$\$[a-zA-Z0-9./]{64}$", re.UNICODE),
			'sha384-salt-django': re.compile(r"^sha384\$[a-zA-Z\d.]+\$[a-zA-Z0-9./]{96}$", re.UNICODE),
			'sha384-django': re.compile(r"^sha384\$\$[a-zA-Z0-9./]{96}$", re.UNICODE),
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
	
	# Group detections by filter combinations
	detection_groups = {
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
	
	# Execute detections based on active filters
	for filter_combination, detection_functions in detection_groups.items():
		if any(f in filters for f in filter_combination):
			for detection_func in detection_functions:
				results.extend(detection_func(sub_text, base_location))
		
	return results

def _detect_jwt(sub_text: str, base_location: int) -> List[Finding]:
	"""Detect JWT tokens in the text."""
	results = []
	printable_set = set(string.printable)
	
	for finding in reg_find('jwt', sub_text):
		data, location = finding.group(), (base_location, finding.span())
		potential_jwt_parts = finding.group().split('.')
		
		try:
			if (len(potential_jwt_parts) == 3 and
				all(reg_find('base64', part) for part in potential_jwt_parts) and
				set(base64.b64decode(potential_jwt_parts[0].encode())).issubset(printable_set) and
				potential_jwt_parts[0].startswith('eyJ')):
				
				header = potential_jwt_parts[0]
				payload = base64.b64decode(potential_jwt_parts[1].encode()).decode('utf-8', errors='ignore')
				signature = potential_jwt_parts[2]
				
				jwt_find = Finding(
					'jwt', 
					finding.group(), 
					location, 
					85, 
					f'JWT Token\theader: {header}\tpayload: {payload}\tsignature: {signature}'
				)
				results.append(jwt_find)
		except (TypeError, UnicodeDecodeError, ValueError):
			pass
	
	return results

def _detect_secrets(sub_text: str, base_location: int) -> List[Finding]:
	"""Detect potential secrets in the text."""
	results = []
	
	for line in sub_text.replace("\\n", "\n").splitlines():
		for finding in reg_find('secret', line):
			data, location = finding.group(), (base_location, finding.span())
			
			for keyword in ['pass', 'key', 'security']:
				if keyword and keyword in line.lower():
					secret_find = Finding('secret', finding.group(), location, 45, f'Secret: {finding.group()}')
					stripped_secret = finding.group().strip('"').strip("'").strip()
					
					# Check for common false positives
					common_false_positives = ['/', '-', 'keystore_', '{{', '$', 'secret', 'ConfigMap', '[', 'true', 'false']
					for false_positive in common_false_positives:
						if stripped_secret.lower().startswith(false_positive.lower()):
							secret_find.certainty -= 25
					
					if entropy(finding.group()) > MIN_ENTROPY:
						secret_find.certainty += 40
					
					results.append(secret_find)
	
	return results

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
	seen_numbers = set()  # Track seen numbers to avoid duplicates
	
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
				# Avoid duplicate detections
				if phone_number not in seen_numbers:
					seen_numbers.add(phone_number)
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
		credit_find = Finding('credit', None, location, 45, None)
		
		# Visa
		if re.findall(r"4[0-9]{12}(?:[0-9]{3})?", data):
			credit_find.payload = re.findall(r"(?:4[0-9]{12})(?:[0-9]{3})?", data)[0]
			credit_find.details = f'Credit card number: {credit_find.payload}\n\tCredit card type: Visa'
		# Mastercard
		elif re.findall(r"5[1-5][0-9]{14}", data):
			credit_find.payload = re.findall(r"5[1-5][0-9]{14}", data)[0]
			credit_find.details = f'Credit card number: {credit_find.payload}\n\tCredit card type: Mastercard'
		# American Express
		elif re.findall(r"3[47][0-9]{13}", data):
			credit_find.payload = re.findall(r"3[47][0-9]{13}", data)[0]
			credit_find.details = f'Credit card number: {credit_find.payload}\n\tCredit card type: American Express'
		# Diners Club
		elif re.findall(r"3(?:0[0-5]|[68][0-9])[0-9]{11}", data):
			credit_find.payload = re.findall(r"3(?:0[0-5]|[68][0-9])[0-9]{11}", data)[0]
			credit_find.details = f'Credit card number: {credit_find.payload}\n\tCredit card type: Diners Club'
		# Discover
		elif re.findall(r"6(?:011|5[0-9]{2})[0-9]{12}", data):
			credit_find.payload = re.findall(r"6(?:011|5[0-9]{2})[0-9]{12}", data)[0]
			credit_find.details = f'Credit card number: {credit_find.payload}\n\tCredit card type: Discover'
		# JCB
		elif re.findall(r"(?:2131|1800|35\d{3})\d{11}", data):
			credit_find.payload = re.findall(r"(?:2131|1800|35\d{3})\d{11}", data)[0]
			credit_find.details = f'Credit card number: {credit_find.payload}\n\tCredit card type: JCB'
		else:
			credit_find.payload = re.findall(r"\b(?:\d[ -]*?){13,16}\b", data)[0]
			credit_find.details = f'Credit card number: {credit_find.payload}'
			credit_find.certainty -= 30
		
		results.append(credit_find)
	
	return results

def _detect_hashes(sub_text: str, base_location: int) -> List[Finding]:
	"""Detect various hash types in the text."""
	results = []
	
	# MD5/MD4 detection
	for finding in reg_find('md5', sub_text):
		data, location = finding.group(), (base_location, finding.span())
		potential_hash = re.findall(r"[a-fA-F\d]{32}", data)[0]
		
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
	
	# SAM file hash detection
	results.extend(_detect_sam_hashes(sub_text, base_location))
	
	return results

def _detect_sam_hashes(sub_text: str, base_location: int) -> List[Finding]:
	"""Detect SAM file hashes in the text."""
	results = []
	
	# SAM(*:NTLM) detection
	for finding in reg_find('SAM(*:ntlm)', sub_text):
		hash_matches = re.findall(r"\*:([a-fA-F\d]{32})\b", finding.group())
		if hash_matches:
			potential_hash = hash_matches[0]
			sam_ntlm_find = Finding('SAM(*:ntlm)', potential_hash, None, 40, f'hashes in SAM file - LM: not defined\tNTLM: {potential_hash}')
			
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
	
	# SHA256-salt(UNIX) detection
	for finding in reg_find('sha256-salt-unix', sub_text):
		data, location = finding.group(), (base_location, finding.span())
		hash_matches = re.findall(r"\$5\$([a-zA-Z0-9./]{8,16})\$([a-zA-Z0-9./]{43})", data)
		
		if hash_matches:
			salt, hash_value = hash_matches[0]
			sha256_salt_unix = Finding(
				'sha256-salt-unix', 
				(salt, hash_value), 
				location, 
				55, 
				f'UNIX shadow file using salted SHA256 - salt: {salt}\thash: {hash_value}'
			)
			
			if entropy(hash_value) > MIN_ENTROPY:
				sha256_salt_unix.certainty += 25
			
			results.append(sha256_salt_unix)
	
	# SHA512-salt(UNIX) detection
	for finding in reg_find('sha512-salt-unix', sub_text):
		data, location = finding.group(), (base_location, finding.span())
		hash_matches = re.findall(r"\$6\$([a-zA-Z0-9./]{8,16})\$([a-zA-Z0-9./]{86})", data)
		
		if hash_matches:
			salt, hash_value = hash_matches[0]
			sha512_salt_unix = Finding(
				'sha512-salt-unix', 
				(salt, hash_value), 
				location, 
				55, 
				f'UNIX shadow file using salted SHA512 - salt: {salt}\thash: {hash_value}'
			)
			
			if entropy(hash_value) > MIN_ENTROPY:
				sha512_salt_unix.certainty += 25
			
			results.append(sha512_salt_unix)
	
	# APR1-salt(Apache) detection
	for finding in reg_find('apr1-salt-unix', sub_text):
		data, location = finding.group(), (base_location, finding.span())
		hash_matches = re.findall(r"\$apr1\$([a-zA-Z0-9./]{8})\$([a-zA-Z0-9./]{22})", data)
		
		if hash_matches:
			salt, hash_value = hash_matches[0]
			apr1_salt_unix = Finding(
				'apr1-salt-unix', 
				(salt, hash_value), 
				location, 
				45, 
				f'Apache htpasswd file (MD5x2000)- salt: {salt}\thash: {hash_value}'
			)
			
			if entropy(hash_value) > MIN_ENTROPY:
				apr1_salt_unix.certainty += 35
			
			results.append(apr1_salt_unix)
	
	# MD5-salt(UNIX) detection
	for finding in reg_find('md5-salt-unix', sub_text):
		data, location = finding.group(), (base_location, finding.span())
		hash_matches = re.findall(r"([a-zA-Z0-9./]{8})\$([a-zA-Z0-9./]{22})", data)
		
		if hash_matches:
			salt, hash_value = hash_matches[0]
			md5_salt_unix = Finding(
				'md5-salt-unix', 
				(salt, hash_value), 
				location, 
				45, 
				f'UNIX shadow file using salted MD5 - salt: {salt}\thash: {hash_value}'
			)
			
			if entropy(hash_value) > MIN_ENTROPY:
				md5_salt_unix.certainty += 35
			
			results.append(md5_salt_unix)
	
	# Blowfish(UNIX) detection
	for finding in reg_find('blowfish-salt-unix', sub_text):
		data, location = finding.group(), (base_location, finding.span())
		hash_matches = re.findall(r"\$(?:2a|2)\$([a-zA-Z0-9./]{2})\$([a-zA-Z0-9./]{53})", data)
		
		if hash_matches:
			salt, hash_value = hash_matches[0]
			blowfish_salt_unix = Finding(
				'blowfish-salt-unix', 
				(salt, hash_value), 
				location, 
				55, 
				f'UNIX shadow file using salted Blowfish - salt: {salt}\thash: {hash_value}'
			)
			
			if (re.findall(r"\$(?:2a|2)\$[a-zA-Z0-9./]{2}\$([a-zA-Z0-9./]{53})\$?", data) and 
				entropy(hash_value) > MIN_ENTROPY):
				blowfish_salt_unix.certainty += 30
			
			results.append(blowfish_salt_unix)
	
	return results

def _detect_web_framework_hashes(sub_text: str, base_location: int) -> List[Finding]:
	"""Detect web framework-related hashes in the text."""
	results = []
	
	# Django SHA256-salt detection
	for finding in reg_find('sha256-salt-django', sub_text):
		data, location = finding.group(), (base_location, finding.span())
		hash_matches = re.findall(r"^(?:sha256|sha1)\$([a-zA-Z\d.]+)\$([a-zA-Z0-9./]{64})$", data)
		
		if hash_matches:
			salt, hash_value = hash_matches[0]
			sha256_salt_django = Finding(
				'sha256-salt-django', 
				(salt, hash_value), 
				location, 
				65, 
				f'Django shadow file using salted SHA256 - salt: {salt}\thash: {hash_value}'
			)
			
			if (all(c.islower() or c.isdigit() or c == '$' for c in data) and 
				entropy(hash_value) > MIN_ENTROPY):
				sha256_salt_django.certainty += 20
			
			results.append(sha256_salt_django)
	
	# Django SHA256 detection
	for finding in reg_find('sha256-django', sub_text):
		data, location = finding.group(), (base_location, finding.span())
		hash_matches = re.findall(r"^(?:sha256|sha1)\$\$([a-zA-Z0-9./]{64})$", data)
		
		if hash_matches:
			hash_value = hash_matches[0]
			sha256_django = Finding(
				'sha256-django', 
				hash_value, 
				location, 
				65, 
				f'Django shadow file using SHA256 - hash: {hash_value}'
			)
			
			if (all(c.islower() or c.isdigit() or c == '$' for c in data) and 
				entropy(hash_value) > MIN_ENTROPY):
				sha256_django.certainty += 20
			
			results.append(sha256_django)
	
	# Django SHA384-salt detection
	for finding in reg_find('sha384-salt-django', sub_text):
		data, location = finding.group(), (base_location, finding.span())
		hash_matches = re.findall(r"^sha384\$([a-zA-Z\d.]+)\$([a-zA-Z0-9./]{96})$", data)
		
		if hash_matches:
			salt, hash_value = hash_matches[0]
			sha384_salt_django = Finding(
				'sha384-salt-django', 
				(salt, hash_value), 
				location, 
				65, 
				f'Django shadow file using salted SHA384 - salt: {salt}\thash: {hash_value}'
			)
			
			if (all(c.islower() or c.isdigit() or c == '$' for c in data) and 
				entropy(hash_value) > MIN_ENTROPY):
				sha384_salt_django.certainty += 20
			
			results.append(sha384_salt_django)
	
	# Django SHA384 detection
	for finding in reg_find('sha384-django', sub_text):
		data, location = finding.group(), (base_location, finding.span())
		hash_matches = re.findall(r"^sha384\$\$([a-zA-Z0-9./]{96})$", data)
		
		if hash_matches:
			hash_value = hash_matches[0]
			sha384_django = Finding(
				'sha384-django', 
				hash_value, 
				location, 
				65, 
				f'Django shadow file using SHA384 - hash: {hash_value}'
			)
			
			if (all(c.islower() or c.isdigit() or c == '$' for c in data) and 
				entropy(hash_value) > MIN_ENTROPY):
				sha384_django.certainty += 20
			
			results.append(sha384_django)
	
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

def run_validators(results: List[Finding], validators: List[str]) -> List[Finding]:
	"""
	Run validators on the results to filter them.
	
	Args:
		results: List of findings to validate
		validators: List of validator strings
		
	Returns:
		Filtered list of findings
	"""
	final_results = []
	
	for validator in validators:
		validator_func = None
		validator_type = None
		mode = validator.split(':')[0].lower()
		
		if mode == 'all':
			validator_func = all
		elif mode == 'has':
			validator_func = any
		elif mode == 'search':
			validator_func = re.compile(validator.split(':')[1])
		else:
			print('Invalid validator provided.')
			continue
		
		validator_type = validator.split(':')[1].upper()
		
		for result in results:
			payload = None
			
			if isinstance(result.payload, tuple):
				payload = "".join(str(item) for item in result.payload)
			else:
				payload = str(result.payload) if result.payload else ""
			
			payload = re.sub(f'[{BAD_CHARS}]', '', payload)
			
			if validator_type == 'NUMERIC':
				if validator_func(c.isdigit() for c in payload):
					final_results.append(result)
			elif validator_type == 'ALPHA':
				if validator_func(c.isalpha() for c in payload):
					final_results.append(result)
			elif validator_type == 'LOWER':
				if validator_func(c.islower() for c in payload):
					final_results.append(result)
			elif validator_type == 'UPPER':
				if validator_func(c.isupper() for c in payload):
					final_results.append(result)
			elif validator_type == 'ALPHANUMERIC':
				if validator_func(c.isalnum() for c in payload):
					final_results.append(result)
			elif validator_type == 'SYMBOL':
				if validator_func(not c.isalnum() for c in payload):
					final_results.append(result)
			else:
				if validator_func.search(payload):
					final_results.append(result)
	
	return final_results

def show_results(results: List[Finding], show_details: bool, validators: List[str], min_certainty: int) -> None:
	"""
	Display the results in a formatted way.
	
	Args:
		results: List of findings to display
		show_details: Whether to show detailed information
		validators: List of validators to apply
		min_certainty: Minimum certainty level to display
	"""
	if min_certainty > 0:
		results = [finding for finding in results if finding.certainty >= min_certainty]
	
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
	print(repr(generator(data, mode).items()))
	
	for element in generator(data, mode).items():
		results = get_type_of(element[1], filters)
		
		if validators:
			results = run_validators(results, validators)
		
		if verbose:
			print(f'after {element[0]}:')
		
		show_results(results, analyze, validators, min_certainty)

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
	Process a single file for analysis with optimized memory usage.
	
	Args:
		filename: Path to the file to process
		args: Command line arguments
		validators: List of validators to apply
		min_certainty: Minimum certainty level to display
	"""
	try:
		file_size = Path(filename).stat().st_size
		
		# Optimize window size based on file size
		if file_size <= MAX_OVERLAP_WINDOW_SIZE:
			file_window_size = file_size
			overlap_window_size = 0
		else:
			file_window_size = min(MAX_FILE_WINDOW_SIZE, file_size)
			overlap_window_size = MAX_OVERLAP_WINDOW_SIZE
		
		# Use memory mapping for large files to reduce memory usage
		if file_size > 100 * 1024 * 1024:  # 100MB
			process_large_file_mmap(filename, args, validators, min_certainty, file_window_size, overlap_window_size)
		else:
			process_file_streaming(filename, args, validators, min_certainty, file_window_size, overlap_window_size)
					
	except FileNotFoundError:
		print(f"Error: File '{filename}' not found.")
	except PermissionError:
		print(f"Error: Permission denied accessing file '{filename}'.")
	except OSError as e:
		print(f"Error: OS error accessing file '{filename}': {e}")
	except Exception as e:
		print(f"Error: Unexpected error processing file '{filename}': {e}")

def process_file_streaming(filename: str, args, validators: List[str], min_certainty: int, 
                          file_window_size: int, overlap_window_size: int) -> None:
	"""Process file using streaming approach for medium-sized files."""
	with open(filename, 'rb') as fl:
		file_size = Path(filename).stat().st_size
		
		if args.verbose:
			print(f'progress: 0%\tlocation: [0/{file_size}]')
		
		position = 0
		while position < file_size:
			try:
				fl.seek(position)
				content = fl.read(file_window_size)
				current_position = fl.tell()
				
				if not content:
					break
				
				# Process the chunk
				process_chunk(content, args, validators, min_certainty, position)
				
				# Move to next position with overlap
				if current_position < file_size:
					position = current_position - overlap_window_size
					if position < 0:
						position = 0
				else:
					break
				
				if args.verbose:
					progress = (current_position * 100) // file_size
					print(f'progress: {progress}%\tlocation: [{current_position}/{file_size}]')
					
			except (UnicodeDecodeError, ValueError) as e:
				if args.verbose:
					print(f"Warning: Failed to decode content at position {position}: {e}")
				position += file_window_size // 2  # Skip problematic area
				continue
			except Exception as e:
				if args.verbose:
					print(f"Warning: Unexpected error processing file {filename} at position {position}: {e}")
				position += file_window_size // 2
				continue

def process_large_file_mmap(filename: str, args, validators: List[str], min_certainty: int,
                           file_window_size: int, overlap_window_size: int) -> None:
	"""Process large files using memory mapping for better memory efficiency."""
	import mmap
	
	with open(filename, 'rb') as fl:
		with mmap.mmap(fl.fileno(), 0, access=mmap.ACCESS_READ) as mmapped_file:
			file_size = len(mmapped_file)
			
			if args.verbose:
				print(f'Using memory mapping for large file: {file_size} bytes')
			
			position = 0
			while position < file_size:
				try:
					# Extract chunk from memory-mapped file
					chunk_end = min(position + file_window_size, file_size)
					content = mmapped_file[position:chunk_end]
					
					if not content:
						break
					
					# Process the chunk
					process_chunk(content, args, validators, min_certainty, position)
					
					# Move to next position with overlap
					if chunk_end < file_size:
						position = chunk_end - overlap_window_size
						if position < 0:
							position = 0
					else:
						break
					
					if args.verbose:
						progress = (chunk_end * 100) // file_size
						print(f'progress: {progress}%\tlocation: [{chunk_end}/{file_size}]')
						
				except (UnicodeDecodeError, ValueError) as e:
					if args.verbose:
						print(f"Warning: Failed to decode content at position {position}: {e}")
					position += file_window_size // 2
					continue
				except Exception as e:
					if args.verbose:
						print(f"Warning: Unexpected error processing file {filename} at position {position}: {e}")
					position += file_window_size // 2
					continue

def process_chunk(content: bytes, args, validators: List[str], min_certainty: int, position: int) -> None:
	"""Process a single chunk of data."""
	try:
		if args.preprocessor and len(args.preprocessor) == 1:
			try:
				content = pre_process(content, args.preprocessor[0])
			except (struct.error, ValueError) as e:
				if args.verbose:
					print(f"Warning: Failed to preprocess data: {e}")
				return
		
		# Decode content with error handling
		try:
			text_content = content.decode('utf-8', errors='ignore')
		except UnicodeDecodeError:
			# Try with different encodings
			for encoding in ['latin-1', 'cp1252', 'iso-8859-1']:
				try:
					text_content = content.decode(encoding, errors='ignore')
					break
				except UnicodeDecodeError:
					continue
			else:
				text_content = content.decode('utf-8', errors='replace')
		
		if args.generator:
			test_encoding(text_content, args.filters, args.analyze, validators, 
			             args.verbose, args.generator[0], min_certainty)
		else:
			results = get_type_of(text_content, args.filters)
			show_results(results, args.analyze, validators, min_certainty)
			
	except Exception as e:
		if args.verbose:
			print(f"Warning: Error processing chunk at position {position}: {e}")

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
		                   default=['win', 'web', 'unix', 'db', 'personal', 'crypto', 'other'], 
		                   type=str, nargs=1, dest='filters',
		                   help='filter by source of your string. can be: win, web, db, unix or other')
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
		
		args = parser.parse_args()
		
		# Load configuration
		config = load_configuration(args.config_file)
		
		# Set defaults from configuration
		min_certainty = config.min_certainty if hasattr(config, 'min_certainty') else (0 if not args.min_certainty else args.min_certainty[0])
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
			print("shadow and SAM files, URLs, phpBB3, Wordpress, Joomla, CRC, LM, NTLM, MD4, MD5, Apr, SHA1, SHA256, base64, MySQL323, MYSQL4+, MSSQL2000, MSSQL2005, DES, RipeMD320, Whirlpool, SHA1, SHA224, SHA256, SHA384, SHA512, Blowfish, UUID, phone numbers, credit cards, web cookies")
		
		# String mode
		elif args.string is not None:
			try:
				data = args.string
				
				if args.preprocessor and len(args.preprocessor) == 1:
					data = pre_process(data.encode(), args.preprocessor[0])
				
				if args.generator:
					test_encoding(data, args.filters, args.analyze, validators, args.verbose, args.generator[0], min_certainty)
				else:
					results = get_type_of(data, args.filters)
					show_results(results, args.analyze, validators, min_certainty)
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
			try:
				for line_num, data in enumerate(sys.stdin, 1):
					if args.preprocessor and len(args.preprocessor) == 1:
						data = pre_process(data.encode(), args.preprocessor[0])
					
					if args.generator:
						test_encoding(data, args.filters, args.analyze, validators, args.verbose, args.generator[0], min_certainty)
					else:
						results = get_type_of(data, args.filters)
						show_results(results, args.analyze, validators, min_certainty)
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
		if args.verbose:
			import traceback
			traceback.print_exc()

if __name__ == '__main__':
	main()
