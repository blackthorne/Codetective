#!/usr/bin/env python3
"""
Configuration management for Codetective.

This module provides a centralized configuration system that allows users
to customize the behavior of the codetective tool through configuration files,
environment variables, and command-line arguments.
"""

import os
import json
import yaml
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from enum import Enum


class ConfigFormat(Enum):
    """Supported configuration file formats."""
    JSON = "json"
    YAML = "yaml"
    INI = "ini"


@dataclass
class DetectionConfig:
    """Configuration for detection algorithms."""
    min_entropy: float = 3.3
    min_certainty: int = 0
    max_file_window_size: int = 1_000_000
    max_overlap_window_size: int = 5_000
    min_av: int = 5
    max_preprocess_errors: int = 20
    bad_chars: str = "\n\r-"
    
    # Detection-specific settings
    enable_jwt_detection: bool = True
    enable_secret_detection: bool = True
    enable_web_cookie_detection: bool = True
    enable_url_detection: bool = True
    enable_phone_detection: bool = True
    enable_credit_card_detection: bool = True
    enable_hash_detection: bool = True
    enable_database_hash_detection: bool = True
    enable_windows_hash_detection: bool = True
    enable_sam_hash_detection: bool = True
    enable_base64_detection: bool = True
    enable_uuid_detection: bool = True
    enable_unix_hash_detection: bool = True
    enable_web_framework_hash_detection: bool = True
    enable_crc_detection: bool = True


@dataclass
class OutputConfig:
    """Configuration for output formatting."""
    verbose: bool = False
    show_details: bool = True
    show_confidence: bool = True
    show_location: bool = True
    show_timestamp: bool = True
    output_format: str = "text"  # text, json, csv, xml
    color_output: bool = True
    quiet_mode: bool = False


@dataclass
class FileProcessingConfig:
    """Configuration for file processing."""
    chunk_size: int = 8192
    max_file_size: int = 100 * 1024 * 1024  # 100MB
    use_memory_mapping: bool = True
    recursive_search: bool = False
    follow_symlinks: bool = False
    include_patterns: List[str] = field(default_factory=list)
    exclude_patterns: List[str] = field(default_factory=list)


@dataclass
class CodetectiveConfig:
    """Main configuration class for Codetective."""
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    file_processing: FileProcessingConfig = field(default_factory=FileProcessingConfig)
    
    # Global settings
    config_file: Optional[str] = None
    log_level: str = "INFO"
    log_file: Optional[str] = None


class ConfigManager:
    """Manages configuration loading and merging."""
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize the configuration manager.
        
        Args:
            config_file: Path to configuration file (optional)
        """
        self.config_file = config_file
        self.config = CodetectiveConfig()
        self._load_config()
    
    def _load_config(self) -> None:
        """Load configuration from various sources."""
        # Load from default locations if no config file specified
        if not self.config_file:
            self._load_from_default_locations()
        
        # Load from specified config file
        if self.config_file and Path(self.config_file).exists():
            self._load_from_file(self.config_file)
        
        # Override with environment variables
        self._load_from_environment()
    
    def _load_from_default_locations(self) -> None:
        """Load configuration from default locations."""
        default_locations = [
            Path.home() / ".codetective" / "config.json",
            Path.home() / ".codetective" / "config.yaml",
            Path.home() / ".codetective" / "config.yml",
            Path.cwd() / "codetective.json",
            Path.cwd() / "codetective.yaml",
            Path.cwd() / "codetective.yml",
            Path.cwd() / ".codetective.json",
            Path.cwd() / ".codetective.yaml",
            Path.cwd() / ".codetective.yml",
        ]
        
        for location in default_locations:
            if location.exists():
                self._load_from_file(str(location))
                break
    
    def _load_from_file(self, file_path: str) -> None:
        """Load configuration from a file."""
        file_path = Path(file_path)
        
        if not file_path.exists():
            return
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                if file_path.suffix.lower() in ['.yaml', '.yml']:
                    data = yaml.safe_load(f)
                elif file_path.suffix.lower() == '.json':
                    data = json.load(f)
                else:
                    return
                
                self._merge_config(data)
        except Exception as e:
            print(f"Warning: Could not load config from {file_path}: {e}")
    
    def _load_from_environment(self) -> None:
        """Load configuration from environment variables."""
        env_mappings = {
            'CODETECTIVE_MIN_ENTROPY': ('detection.min_entropy', float),
            'CODETECTIVE_MIN_CERTAINTY': ('detection.min_certainty', int),
            'CODETECTIVE_MAX_FILE_SIZE': ('file_processing.max_file_size', int),
            'CODETECTIVE_VERBOSE': ('output.verbose', lambda x: x.lower() in ('true', '1', 'yes')),
            'CODETECTIVE_QUIET': ('output.quiet_mode', lambda x: x.lower() in ('true', '1', 'yes')),
            'CODETECTIVE_LOG_LEVEL': ('log_level', str),
            'CODETECTIVE_LOG_FILE': ('log_file', str),
        }
        
        for env_var, (config_path, converter) in env_mappings.items():
            value = os.getenv(env_var)
            if value is not None:
                try:
                    converted_value = converter(value)
                    self._set_nested_value(config_path, converted_value)
                except (ValueError, TypeError) as e:
                    print(f"Warning: Invalid value for {env_var}: {e}")
    
    def _merge_config(self, data: Dict[str, Any]) -> None:
        """Merge configuration data into the current config."""
        if 'detection' in data:
            self._merge_detection_config(data['detection'])
        
        if 'output' in data:
            self._merge_output_config(data['output'])
        
        if 'file_processing' in data:
            self._merge_file_processing_config(data['file_processing'])
        
        if 'log_level' in data:
            self.config.log_level = data['log_level']
        
        if 'log_file' in data:
            self.config.log_file = data['log_file']
    
    def _merge_detection_config(self, data: Dict[str, Any]) -> None:
        """Merge detection configuration."""
        for key, value in data.items():
            if hasattr(self.config.detection, key):
                setattr(self.config.detection, key, value)
    
    def _merge_output_config(self, data: Dict[str, Any]) -> None:
        """Merge output configuration."""
        for key, value in data.items():
            if hasattr(self.config.output, key):
                setattr(self.config.output, key, value)
    
    def _merge_file_processing_config(self, data: Dict[str, Any]) -> None:
        """Merge file processing configuration."""
        for key, value in data.items():
            if hasattr(self.config.file_processing, key):
                setattr(self.config.file_processing, key, value)
    
    def _set_nested_value(self, path: str, value: Any) -> None:
        """Set a nested configuration value."""
        keys = path.split('.')
        obj = self.config
        
        for key in keys[:-1]:
            obj = getattr(obj, key)
        
        setattr(obj, keys[-1], value)
    
    def get_config(self) -> CodetectiveConfig:
        """Get the current configuration."""
        return self.config
    
    def save_config(self, file_path: str, format: ConfigFormat = ConfigFormat.JSON) -> None:
        """Save the current configuration to a file."""
        file_path = Path(file_path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        config_dict = self._config_to_dict()
        
        with open(file_path, 'w', encoding='utf-8') as f:
            if format == ConfigFormat.JSON:
                json.dump(config_dict, f, indent=2, sort_keys=True)
            elif format == ConfigFormat.YAML:
                yaml.dump(config_dict, f, default_flow_style=False, indent=2)
    
    def _config_to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            'detection': {
                'min_entropy': self.config.detection.min_entropy,
                'min_certainty': self.config.detection.min_certainty,
                'max_file_window_size': self.config.detection.max_file_window_size,
                'max_overlap_window_size': self.config.detection.max_overlap_window_size,
                'min_av': self.config.detection.min_av,
                'max_preprocess_errors': self.config.detection.max_preprocess_errors,
                'bad_chars': self.config.detection.bad_chars,
                'enable_jwt_detection': self.config.detection.enable_jwt_detection,
                'enable_secret_detection': self.config.detection.enable_secret_detection,
                'enable_web_cookie_detection': self.config.detection.enable_web_cookie_detection,
                'enable_url_detection': self.config.detection.enable_url_detection,
                'enable_phone_detection': self.config.detection.enable_phone_detection,
                'enable_credit_card_detection': self.config.detection.enable_credit_card_detection,
                'enable_hash_detection': self.config.detection.enable_hash_detection,
                'enable_database_hash_detection': self.config.detection.enable_database_hash_detection,
                'enable_windows_hash_detection': self.config.detection.enable_windows_hash_detection,
                'enable_sam_hash_detection': self.config.detection.enable_sam_hash_detection,
                'enable_base64_detection': self.config.detection.enable_base64_detection,
                'enable_uuid_detection': self.config.detection.enable_uuid_detection,
                'enable_unix_hash_detection': self.config.detection.enable_unix_hash_detection,
                'enable_web_framework_hash_detection': self.config.detection.enable_web_framework_hash_detection,
                'enable_crc_detection': self.config.detection.enable_crc_detection,
            },
            'output': {
                'verbose': self.config.output.verbose,
                'show_details': self.config.output.show_details,
                'show_confidence': self.config.output.show_confidence,
                'show_location': self.config.output.show_location,
                'show_timestamp': self.config.output.show_timestamp,
                'output_format': self.config.output.output_format,
                'color_output': self.config.output.color_output,
                'quiet_mode': self.config.output.quiet_mode,
            },
            'file_processing': {
                'chunk_size': self.config.file_processing.chunk_size,
                'max_file_size': self.config.file_processing.max_file_size,
                'use_memory_mapping': self.config.file_processing.use_memory_mapping,
                'recursive_search': self.config.file_processing.recursive_search,
                'follow_symlinks': self.config.file_processing.follow_symlinks,
                'include_patterns': self.config.file_processing.include_patterns,
                'exclude_patterns': self.config.file_processing.exclude_patterns,
            },
            'log_level': self.config.log_level,
            'log_file': self.config.log_file,
        }


def create_default_config() -> CodetectiveConfig:
    """Create a default configuration."""
    return CodetectiveConfig()


def load_config(config_file: Optional[str] = None) -> CodetectiveConfig:
    """Load configuration from file and environment."""
    manager = ConfigManager(config_file)
    return manager.get_config()


def save_default_config(file_path: str, format: ConfigFormat = ConfigFormat.JSON) -> None:
    """Save a default configuration file."""
    manager = ConfigManager()
    manager.save_config(file_path, format)


if __name__ == '__main__':
    # Example usage
    config = load_config()
    print("Current configuration:")
    print(f"Min entropy: {config.detection.min_entropy}")
    print(f"Verbose mode: {config.output.verbose}")
    print(f"Chunk size: {config.file_processing.chunk_size}")
    
    # Save default config
    save_default_config("codetective_config.json")
    print("Default configuration saved to codetective_config.json")
