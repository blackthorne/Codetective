#!/usr/bin/env python3
"""
Example script demonstrating the Codetective configuration system.

This script shows how to use the configuration system to customize
the behavior of the codetective tool.
"""

import sys
import os
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from config import ConfigManager, CodetectiveConfig, ConfigFormat
    from codetective import get_type_of, show_results
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Make sure you're running this from the Codetective directory")
    sys.exit(1)


def demonstrate_config_loading():
    """Demonstrate loading configuration from different sources."""
    print("=== Configuration Loading Demo ===\n")
    
    # Load default configuration
    print("1. Loading default configuration:")
    config = CodetectiveConfig()
    print(f"   Min entropy: {config.detection.min_entropy}")
    print(f"   Verbose mode: {config.output.verbose}")
    print(f"   Chunk size: {config.file_processing.chunk_size}")
    print()
    
    # Load configuration from file
    config_file = "codetective_config.json"
    if Path(config_file).exists():
        print(f"2. Loading configuration from {config_file}:")
        manager = ConfigManager(config_file)
        config = manager.get_config()
        print(f"   Min entropy: {config.detection.min_entropy}")
        print(f"   Verbose mode: {config.output.verbose}")
        print(f"   Chunk size: {config.file_processing.chunk_size}")
        print()
    
    # Demonstrate environment variable override
    print("3. Setting environment variable and reloading:")
    os.environ['CODETECTIVE_VERBOSE'] = 'true'
    manager = ConfigManager()
    config = manager.get_config()
    print(f"   Verbose mode (from env): {config.output.verbose}")
    print()


def demonstrate_detection_with_config():
    """Demonstrate detection with custom configuration."""
    print("=== Detection with Custom Configuration ===\n")
    
    # Create a custom configuration
    config = CodetectiveConfig()
    config.detection.min_certainty = 50  # Only show high-confidence results
    config.output.verbose = True
    config.detection.enable_credit_card_detection = False  # Disable credit card detection
    
    print("Custom configuration:")
    print(f"  Min certainty: {config.detection.min_certainty}")
    print(f"  Verbose mode: {config.output.verbose}")
    print(f"  Credit card detection: {config.detection.enable_credit_card_detection}")
    print()
    
    # Test data
    test_data = """
    MD5: d41d8cd98f00b204e9800998ecf8427e
    Credit Card: 4111111111111111
    UUID: 550e8400-e29b-41d4-a716-446655440000
    """
    
    print("Analyzing test data:")
    print(test_data)
    
    # Perform detection
    results = get_type_of(test_data)
    
    # Filter results based on configuration
    filtered_results = [r for r in results if r.certainty >= config.detection.min_certainty]
    
    print(f"Found {len(results)} total results, {len(filtered_results)} above certainty threshold")
    
    if config.output.verbose:
        for result in filtered_results:
            print(f"  {result.type}: {result.payload[:20]}... (certainty: {result.certainty})")
    print()


def demonstrate_config_saving():
    """Demonstrate saving configuration to different formats."""
    print("=== Configuration Saving Demo ===\n")
    
    # Create a custom configuration
    config = CodetectiveConfig()
    config.detection.min_certainty = 75
    config.output.verbose = True
    config.output.color_output = False
    config.file_processing.chunk_size = 16384
    
    # Create manager with custom config
    manager = ConfigManager()
    manager.config = config
    
    # Save as JSON
    json_file = "example_config.json"
    manager.save_config(json_file, ConfigFormat.JSON)
    print(f"Saved configuration to {json_file}")
    
    # Save as YAML
    yaml_file = "example_config.yaml"
    manager.save_config(yaml_file, ConfigFormat.YAML)
    print(f"Saved configuration to {yaml_file}")
    
    # Show the saved configuration
    print(f"\nContents of {json_file}:")
    with open(json_file, 'r') as f:
        print(f.read())
    print()


def main():
    """Main demonstration function."""
    print("Codetective Configuration System Demo")
    print("=" * 40)
    print()
    
    try:
        demonstrate_config_loading()
        demonstrate_detection_with_config()
        demonstrate_config_saving()
        
        print("Demo completed successfully!")
        
    except Exception as e:
        print(f"Error during demo: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
