# Email Investigator - Forensic Edition

A comprehensive, modular email forensics analysis tool built with PyQt5 for digital forensics investigations.

## Features

### Core Features
- **Email Parsing**: Parse RFC-822 compliant email files (.eml)
- **File Metadata**: Extract comprehensive file metadata and hashes
- **Header Analysis**: Detailed analysis of email headers including Received, Authentication-Results, DKIM
- **Attachment Analysis**: Advanced attachment analysis with magic bytes detection, EXIF extraction, macro detection
- **Anti-Forensics Detection**: Comprehensive anti-forensics detection including header manipulation, timestamp analysis, content obfuscation
- **Network Intelligence**: Network pivot analysis with IP geolocation, domain analysis, and threat intelligence
- **Chain of Custody**: Built-in chain of custody documentation
- **Forensic Reporting**: Export comprehensive JSON forensic reports

### Modular Architecture
The application is organized into logical modules for better maintainability:

- **`forensics/core.py`**: Core forensic utilities and helper functions
- **`forensics/email_parser.py`**: Email parsing and basic analysis
- **`forensics/analysis/`**: Specialized analysis modules
  - `attachments.py`: Advanced attachment analysis
  - `anti_forensics.py`: Anti-forensics detection
  - `network.py`: Network intelligence analysis
- **`ui/components.py`**: User interface components
- **`utils/constants.py`**: Application constants and utilities
- **`main.py`**: Main application entry point

## Installation

### Prerequisites
- Python 3.7+
- PyQt5
- requests
- dnspython

### Install from source
```bash
git clone https://github.com/forensic-analyst/email-investigator.git
cd email-investigator
pip install -r requirements.txt
python setup.py install
```

### Run the application
```bash
email-investigator
```

## Usage

1. **Open Email File**: Use "Open .eml" to load an email file for analysis
2. **Clipboard Parsing**: Use "Parse from clipboard" to analyze email content from clipboard
3. **Chain of Custody**: Document chain of custody information
4. **Export Report**: Generate comprehensive forensic reports in JSON format

## Analysis Tabs

### Basic Tabs
- **Plain text**: Raw text content of the email
- **HTML source**: HTML content if present
- **Raw headers**: Complete email headers
- **Attachments**: List of email attachments with hashes

### Forensic Analysis Tabs
- **File Metadata**: File information, hashes, and chain of custody
- **Received Headers**: Email routing analysis
- **Authentication**: SPF, DKIM, DMARC verification
- **IOCs**: Extracted indicators of compromise (URLs, emails, IPs)
- **Anomalies**: Detected anomalies and suspicious patterns
- **Network Pivots**: Network intelligence and pivot analysis
- **Anti-Forensics**: Anti-forensics detection results

## Optional Dependencies

The following libraries are optional and provide enhanced functionality:

- **Pillow (PIL)**: EXIF metadata extraction from images
- **olefile**: OLE file analysis for Office documents
- **tlsh**: TLSH fuzzy hashing for similarity analysis
- **chardet**: Enhanced character set detection

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Disclaimer

This tool is designed for digital forensics and security analysis. Use only with proper authorization and in compliance with applicable laws and regulations.
