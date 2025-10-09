# Codetective Configuration Guide

This document describes how to configure the Codetective tool using configuration files, environment variables, and command-line arguments.

## Configuration Files

Codetective supports configuration files in JSON and YAML formats. The tool will automatically look for configuration files in the following locations (in order):

1. `~/.codetective/config.json`
2. `~/.codetective/config.yaml`
3. `~/.codetective/config.yml`
4. `./codetective.json`
5. `./codetective.yaml`
6. `./codetective.yml`
7. `./.codetective.json`
8. `./.codetective.yaml`
9. `./.codetective.yml`

You can also specify a custom configuration file using the `--config` command-line option.

## Configuration Sections

### Detection Configuration

Controls the behavior of detection algorithms:

```yaml
detection:
  min_entropy: 3.3                    # Minimum entropy threshold
  min_certainty: 0                    # Minimum certainty level to display
  max_file_window_size: 1000000       # Maximum file window size
  max_overlap_window_size: 5000       # Maximum overlap window size
  min_av: 5                           # Minimum antivirus score
  max_preprocess_errors: 20           # Maximum preprocessing errors
  
  # Detection algorithm toggles
  enable_jwt_detection: true
  enable_secret_detection: true
  enable_web_cookie_detection: true
  enable_url_detection: true
  enable_phone_detection: true
  enable_credit_card_detection: true
  enable_hash_detection: true
  enable_database_hash_detection: true
  enable_windows_hash_detection: true
  enable_sam_hash_detection: true
  enable_base64_detection: true
  enable_uuid_detection: true
  enable_unix_hash_detection: true
  enable_web_framework_hash_detection: true
  enable_crc_detection: true
```

### Output Configuration

Controls the output formatting and verbosity:

```yaml
output:
  verbose: false                       # Enable verbose output
  show_details: true                   # Show detailed information
  show_confidence: true                # Show confidence levels
  show_location: true                  # Show location information
  show_timestamp: true                 # Show timestamps
  output_format: text                  # Output format (text, json, csv, xml)
  color_output: true                   # Enable colored output
  quiet_mode: false                    # Enable quiet mode
```

### File Processing Configuration

Controls file processing behavior:

```yaml
file_processing:
  chunk_size: 8192                     # Chunk size for processing
  max_file_size: 104857600            # Maximum file size (100MB)
  use_memory_mapping: true            # Use memory mapping for large files
  recursive_search: false              # Enable recursive directory search
  follow_symlinks: false               # Follow symbolic links
  include_patterns: []                 # File patterns to include
  exclude_patterns: []                 # File patterns to exclude
```

### Global Settings

```yaml
log_level: INFO                        # Logging level (DEBUG, INFO, WARNING, ERROR)
log_file: null                         # Log file path (null for stdout)
```

## Environment Variables

You can override configuration settings using environment variables:

- `CODETECTIVE_MIN_ENTROPY`: Minimum entropy threshold
- `CODETECTIVE_MIN_CERTAINTY`: Minimum certainty level
- `CODETECTIVE_MAX_FILE_SIZE`: Maximum file size
- `CODETECTIVE_VERBOSE`: Enable verbose mode (true/false)
- `CODETECTIVE_QUIET`: Enable quiet mode (true/false)
- `CODETECTIVE_LOG_LEVEL`: Logging level
- `CODETECTIVE_LOG_FILE`: Log file path

## Command-Line Arguments

Command-line arguments take precedence over configuration files and environment variables:

```bash
# Use a custom configuration file
codetective --config /path/to/config.yaml file.txt

# Override specific settings
codetective --min-certainty 50 --verbose file.txt

# Disable specific detection algorithms
codetective --disable-jwt --disable-uuid file.txt
```

## Example Configuration Files

### Minimal Configuration

```json
{
  "detection": {
    "min_certainty": 50
  },
  "output": {
    "verbose": true
  }
}
```

### Security-Focused Configuration

```yaml
detection:
  min_certainty: 70
  enable_credit_card_detection: false
  enable_phone_detection: false

output:
  verbose: true
  show_confidence: true
  output_format: json

file_processing:
  exclude_patterns: ["*.log", "*.tmp"]
```

### Performance-Optimized Configuration

```yaml
detection:
  max_file_window_size: 500000
  max_overlap_window_size: 2500

file_processing:
  chunk_size: 16384
  use_memory_mapping: true
  max_file_size: 52428800  # 50MB

output:
  quiet_mode: true
  show_details: false
```

## Configuration Validation

The configuration system validates all settings and will warn about invalid values. Invalid settings will fall back to default values.

## Creating Configuration Files

You can create a default configuration file using the configuration module:

```python
from config import save_default_config, ConfigFormat

# Save as JSON
save_default_config("my_config.json", ConfigFormat.JSON)

# Save as YAML
save_default_config("my_config.yaml", ConfigFormat.YAML)
```

## Best Practices

1. **Use environment variables for sensitive settings** like log file paths
2. **Create different configurations for different use cases** (development, production, security analysis)
3. **Use include/exclude patterns** to filter files during processing
4. **Adjust chunk sizes** based on your system's memory constraints
5. **Enable verbose mode** for debugging and development
6. **Use quiet mode** for automated scripts and batch processing
