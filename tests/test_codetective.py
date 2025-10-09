#!/usr/bin/env python3
"""
Unit tests for Codetective - A tool to determine crypto/encoding algorithms.

This test suite covers the main functionality of the codetective tool,
including pattern matching, entropy calculation, and various detection algorithms.
"""

import unittest
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, mock_open
import sys

# Add the current directory to the path so we can import codetective
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from codetective import (
    Finding, entropy, PatternMatcher, reg_find, get_type_of,
    process_chunk, pre_process, test_encoding, show_results,
    MIN_ENTROPY, MAX_FILE_WINDOW_SIZE, MAX_OVERLAP_WINDOW_SIZE
)


class TestFinding(unittest.TestCase):
    """Test cases for the Finding dataclass."""
    
    def test_finding_creation(self):
        """Test basic Finding creation."""
        finding = Finding(
            type="md5",
            payload="d41d8cd98f00b204e9800998ecf8427e",
            location=(0, (0, 32)),
            certainty=80,
            details="MD5 hash found"
        )
        
        self.assertEqual(finding.type, "md5")
        self.assertEqual(finding.payload, "d41d8cd98f00b204e9800998ecf8427e")
        self.assertEqual(finding.certainty, 80)
        self.assertEqual(finding.details, "MD5 hash found")
        self.assertIsNotNone(finding.created_on)
    
    def test_finding_confidence_levels(self):
        """Test confidence level calculation."""
        # High confidence
        finding = Finding("test", "data", certainty=85)
        self.assertEqual(finding.confidence, "confident")
        
        # Medium confidence
        finding = Finding("test", "data", certainty=70)
        self.assertEqual(finding.confidence, "likely")
        
        # Low confidence
        finding = Finding("test", "data", certainty=50)
        self.assertEqual(finding.confidence, "possible")
    
    def test_finding_display(self):
        """Test finding display methods."""
        finding = Finding(
            type="sha1",
            payload="da39a3ee5e6b4b0d3255bfef95601890afd80709",
            location=(0, (0, 40)),
            certainty=90,
            details="SHA1 hash detected"
        )
        
        self.assertIn("SHA1 hash detected", str(finding))
        self.assertIn("confident", str(finding))
        self.assertIn("sha1", finding.display())


class TestEntropy(unittest.TestCase):
    """Test cases for entropy calculation."""
    
    def test_entropy_empty_string(self):
        """Test entropy calculation for empty string."""
        self.assertEqual(entropy(""), 0.0)
    
    def test_entropy_single_character(self):
        """Test entropy calculation for single character."""
        self.assertEqual(entropy("a"), 0.0)
    
    def test_entropy_repeated_characters(self):
        """Test entropy calculation for repeated characters."""
        self.assertEqual(entropy("aaaa"), 0.0)
    
    def test_entropy_random_string(self):
        """Test entropy calculation for random string."""
        # A random string should have higher entropy
        random_string = "abcdefghijklmnopqrstuvwxyz"
        entropy_value = entropy(random_string)
        self.assertGreater(entropy_value, 0)
        self.assertLessEqual(entropy_value, 5.0)  # Maximum entropy for 26 characters
    
    def test_entropy_hex_string(self):
        """Test entropy calculation for hex string."""
        hex_string = "d41d8cd98f00b204e9800998ecf8427e"
        entropy_value = entropy(hex_string)
        self.assertGreater(entropy_value, 0)
        self.assertLessEqual(entropy_value, 5.0)


class TestPatternMatcher(unittest.TestCase):
    """Test cases for the PatternMatcher class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.matcher = PatternMatcher()
    
    def test_pattern_matcher_initialization(self):
        """Test PatternMatcher initialization."""
        self.assertIsInstance(self.matcher.patterns, dict)
        self.assertIsInstance(self.matcher._common_patterns, dict)
        self.assertIn('hex_32', self.matcher._common_patterns)
        self.assertIn('hex_40', self.matcher._common_patterns)
        self.assertIn('hex_64', self.matcher._common_patterns)
        self.assertIn('hex_128', self.matcher._common_patterns)
    
    def test_quick_hash_check_md5(self):
        """Test quick hash check for MD5."""
        md5_hash = "d41d8cd98f00b204e9800998ecf8427e"
        result = self.matcher.quick_hash_check(md5_hash)
        self.assertEqual(result, "md5")
    
    def test_quick_hash_check_sha1(self):
        """Test quick hash check for SHA1."""
        sha1_hash = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        result = self.matcher.quick_hash_check(sha1_hash)
        self.assertEqual(result, "sha1")
    
    def test_quick_hash_check_sha256(self):
        """Test quick hash check for SHA256."""
        sha256_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        result = self.matcher.quick_hash_check(sha256_hash)
        self.assertEqual(result, "sha256")
    
    def test_quick_hash_check_sha512(self):
        """Test quick hash check for SHA512."""
        sha512_hash = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        result = self.matcher.quick_hash_check(sha512_hash)
        self.assertEqual(result, "sha512")
    
    def test_quick_hash_check_invalid(self):
        """Test quick hash check for invalid data."""
        invalid_data = "not_a_hash"
        result = self.matcher.quick_hash_check(invalid_data)
        self.assertIsNone(result)
    
    def test_find_matches(self):
        """Test find_matches method."""
        data = "d41d8cd98f00b204e9800998ecf8427e"
        matches = list(self.matcher.find_matches('md5', data))
        self.assertGreater(len(matches), 0)


class TestDetectionFunctions(unittest.TestCase):
    """Test cases for detection functions."""
    
    def test_detect_md5(self):
        """Test MD5 hash detection."""
        md5_hash = "d41d8cd98f00b204e9800998ecf8427e"
        results = get_type_of(md5_hash, ['crypto'])
        
        # Should find MD5 hash
        md5_findings = [r for r in results if r.type == 'md5']
        self.assertGreater(len(md5_findings), 0)
        
        # Check finding properties
        finding = md5_findings[0]
        self.assertEqual(finding.payload, md5_hash)
        self.assertGreater(finding.certainty, 0)
    
    def test_detect_sha1(self):
        """Test SHA1 hash detection."""
        sha1_hash = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        results = get_type_of(sha1_hash, ['crypto'])
        
        # Should find SHA1 hash (or related hash types)
        hash_findings = [r for r in results if 'sha' in r.type.lower() or 'mysql' in r.type.lower()]
        self.assertGreater(len(hash_findings), 0)
    
    def test_detect_base64(self):
        """Test Base64 detection."""
        base64_data = "SGVsbG8gV29ybGQ="  # "Hello World" in base64
        results = get_type_of(base64_data, ['crypto'])
        
        # Should find Base64
        base64_findings = [r for r in results if r.type == 'base64']
        self.assertGreater(len(base64_findings), 0)
    
    def test_detect_uuid(self):
        """Test UUID detection."""
        uuid_data = "550e8400-e29b-41d4-a716-446655440000"
        results = get_type_of(uuid_data, ['other'])
        
        # Should find UUID
        uuid_findings = [r for r in results if r.type == 'uuid']
        self.assertGreater(len(uuid_findings), 0)
    
    def test_detect_credit_card(self):
        """Test credit card detection."""
        cc_data = "4111111111111111"  # Test Visa number
        results = get_type_of(cc_data, ['personal'])
        
        # Should find credit card
        cc_findings = [r for r in results if r.type == 'credit']
        self.assertGreater(len(cc_findings), 0)
    
    def test_detect_phone_number(self):
        """Test phone number detection."""
        phone_data = "+1-555-123-4567"
        results = get_type_of(phone_data, ['personal'])
        
        # Should find phone number
        phone_findings = [r for r in results if r.type == 'phone']
        self.assertGreater(len(phone_findings), 0)
    
    def test_detect_url(self):
        """Test URL detection."""
        url_data = "https://www.example.com/path?param=value"
        results = get_type_of(url_data, ['web'])
        
        # Should find URL (case insensitive)
        url_findings = [r for r in results if r.type.lower() == 'url']
        self.assertGreater(len(url_findings), 0)


class TestUtilityFunctions(unittest.TestCase):
    """Test cases for utility functions."""
    
    def test_pre_process_hex(self):
        """Test pre-processing of hex data."""
        hex_data = b"48656c6c6f20576f726c64"  # "Hello World" in hex
        result = pre_process(hex_data, "hex")
        self.assertEqual(result, "Hello World")
    
    def test_pre_process_base64(self):
        """Test pre-processing of base64 data."""
        base64_data = b"SGVsbG8gV29ybGQ="  # "Hello World" in base64
        result = pre_process(base64_data, "base64")
        self.assertEqual(result, "Hello World")
    
    def test_pre_process_invalid_hex(self):
        """Test pre-processing of invalid hex data."""
        invalid_hex = b"invalid_hex_data"
        result = pre_process(invalid_hex, "hex")
        self.assertEqual(result, "")  # Should return empty string for invalid hex
    
    def test_pre_process_invalid_base64(self):
        """Test pre-processing of invalid base64 data."""
        invalid_base64 = b"invalid_base64_data"
        result = pre_process(invalid_base64, "base64")
        self.assertEqual(result, "")  # Should return empty string for invalid base64


class TestFileProcessing(unittest.TestCase):
    """Test cases for file processing functions."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.temp_dir, "test.txt")
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_process_chunk_with_findings(self):
        """Test process_chunk with findings."""
        test_data = b"d41d8cd98f00b204e9800998ecf8427e"  # MD5 hash
        
        # Create a mock args object
        class MockArgs:
            verbose = False
            analyze = False
            generator = None
            preprocessor = None
        
        with patch('sys.stdout'):
            # This should not raise an exception
            process_chunk(test_data, MockArgs(), [], 0, 0)
    
    def test_process_chunk_with_encoding(self):
        """Test process_chunk with encoding detection."""
        test_data = b"SGVsbG8gV29ybGQ="  # Base64 encoded "Hello World"
        
        # Create a mock args object
        class MockArgs:
            verbose = False
            analyze = False
            generator = None
            preprocessor = None
        
        with patch('sys.stdout'):
            # This should not raise an exception
            process_chunk(test_data, MockArgs(), [], 0, 0)


class TestConstants(unittest.TestCase):
    """Test cases for module constants."""
    
    def test_constants_are_defined(self):
        """Test that all constants are properly defined."""
        self.assertIsInstance(MIN_ENTROPY, float)
        self.assertIsInstance(MAX_FILE_WINDOW_SIZE, int)
        self.assertIsInstance(MAX_OVERLAP_WINDOW_SIZE, int)
        
        self.assertEqual(MIN_ENTROPY, 3.3)
        self.assertEqual(MAX_FILE_WINDOW_SIZE, 1_000_000)
        self.assertEqual(MAX_OVERLAP_WINDOW_SIZE, 5_000)


class TestIntegration(unittest.TestCase):
    """Integration tests for the codetective tool."""
    
    def test_end_to_end_detection(self):
        """Test end-to-end detection workflow."""
        # Test data with multiple types
        test_data = """
        MD5: d41d8cd98f00b204e9800998ecf8427e
        SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709
        Base64: SGVsbG8gV29ybGQ=
        UUID: 550e8400-e29b-41d4-a716-446655440000
        URL: https://www.example.com
        """
        
        results = get_type_of(test_data, ['crypto', 'web', 'other'])
        
        # Should find multiple types
        types_found = {result.type for result in results}
        expected_types = {'md5', 'sha1', 'base64', 'uuid', 'url'}
        
        # Check that we found at least some of the expected types
        self.assertTrue(types_found.intersection(expected_types))
    
    def test_show_results_function(self):
        """Test show_results function."""
        findings = [
            Finding("md5", "d41d8cd98f00b204e9800998ecf8427e", 
                   location=(0, (0, 32)), certainty=80, details="MD5 hash found"),
            Finding("sha1", "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                   location=(0, (0, 40)), certainty=85, details="SHA1 hash found")
        ]
        
        with patch('sys.stdout') as mock_stdout:
            show_results(findings, [], [], 0)
            # Check that something was printed
            self.assertTrue(mock_stdout.write.called)


if __name__ == '__main__':
    # Create a test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_classes = [
        TestFinding,
        TestEntropy,
        TestPatternMatcher,
        TestDetectionFunctions,
        TestUtilityFunctions,
        TestFileProcessing,
        TestConstants,
        TestIntegration
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run the tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)
