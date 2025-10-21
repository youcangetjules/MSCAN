
<xaiArtifact artifact_id="4e6a18d0-f24c-44a4-8a5d-263039531325" artifact_version_id="49793c35-c72f-4ff3-9b39-6858840936f0" title="README.md" contentType="text/markdown">

# Email Security Analysis Tool

## Overview

The **Email Security Analysis Tool** is a Python-based utility designed to analyze email headers for security indicators, geolocation information, and authentication details. It processes `.eml` files or raw email header files to generate a comprehensive HTML report summarizing the security posture of an email. The tool evaluates sender information, IP geolocation, domain WHOIS data, authentication results (SPF, DKIM, DMARC, ARC, and CompAuth), and checks for web beacons in HTML email bodies. It also provides a per-hop analysis of email routing and integrates with external services like AbuseIPDB and ipinfo.io for enhanced security insights.

The tool is particularly useful for email administrators, security analysts, and users who need to assess the legitimacy and safety of incoming emails, with a focus on detecting potential threats such as phishing, spam, or malicious domains.

## Features

- **Header Parsing**: Extracts sender email, domain, IP address, and hostname from email headers.
- **Geolocation**: Identifies the geographic location of the sender's IP using services like ipinfo.io and AbuseIPDB, with special handling for Outlook.com hosts.
- **Authentication Analysis**: Evaluates SPF, DKIM, DMARC, ARC, and CompAuth results to determine email authenticity.
- **WHOIS Lookup**: Retrieves domain registration details, including registrar, creation date, and domain age.
- **Security Assessment**: Calculates a risk score based on geolocation, blocklist status, and authentication results, with a color-coded risk level (LOW, MEDIUM, HIGH).
- **Web Beacon Detection**: Identifies and removes 1x1 pixel tracking images (web beacons) from HTML email bodies.
- **Per-Hop Analysis**: Provides detailed routing information for each hop in the email's delivery path, including hostname, IP, ASN, organization, and reputation score.
- **HTML Report Generation**: Produces a clean, email-safe, table-based HTML report with a summary section and detailed per-hop analysis.
- **GURI Generation**: Creates a unique identifier (GURI) for each analysis and stores it in a SQLite database for tracking.
- **Logging**: Comprehensive logging with rotation to a configurable file for debugging and audit purposes.

## Requirements

- **Python Version**: Python 3.6 or higher
- **Dependencies**: Install required packages using:
  ```bash
  pip install -r requirements.txt
  ```
  Required packages include:
  - `requests`
  - `dnspython`
  - `python-whois`
  - `ipwhois`
  - `beautifulsoup4`
  - `pycountry`
  - `python-dateutil`

- **API Keys**:
  - **AbuseIPDB**: Required for IP reputation and blocklist checks. Obtain a key from [AbuseIPDB](https://www.abuseipdb.com).
  - **ipinfo.io**: Required for IP geolocation. Obtain a token from [ipinfo.io](https://ipinfo.io).
  - **ipgeolocation.io**: Optional for fallback geolocation (not used in the current version).

- **System Requirements**:
  - Access to DNS resolution for blocklist checks.
  - Write permissions in the configured `base_path` directory (`C:/GeoFooter` by default) for logs and output files.
  - Internet connectivity for API calls and WHOIS lookups.

## Installation

1. **Clone the Repository**:
   ```bash
   git clone <repository-url>
   cd <repository-directory>
   ```

2. **Install Dependencies**:
   Create a `requirements.txt` file with the following content:
   ```
   requests
   dnspython
   python-whois
   ipwhois
   beautifulsoup4
   pycountry
   python-dateutil
   ```
   Then run:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure API Keys**:
   Update the `CONFIG` dictionary in `geolocate_headers.py` with your API keys:
   ```python
   CONFIG = {
       "api_keys": {
           "abuseipdb": "your_abuseipdb_key_here",
           "ipinfo": "your_ipinfo_token_here",
           "ipgeolocation": "your_ipgeolocation_key_here"
       },
       ...
   }
   ```

4. **Set Up Directory Structure**:
   Ensure the `base_path` directory (`C:/GeoFooter` by default) exists and is writable. The tool will create:
   - Log files (`geolocate_debug.log` and rotated backups).
   - Output directory (`C:/GeoFooter/output`) for HTML reports.
   - SQLite database (`guri_records.db`) for GURI tracking.

## Usage

Run the tool from the command line, providing an input `.eml` file or raw header file and an optional output file path:

```bash
python geolocate_headers.py <input_file> [output_file]
```

- **`<input_file>`**: Path to the `.eml` file or raw email header file.
- **`[output_file]`**: (Optional) Path to save the HTML report. If omitted, the report is saved in `C:/GeoFooter/output` with a timestamped filename (e.g., `footer_20251021_170530_123.html`).

**Example**:
```bash
python geolocate_headers.py sample.eml output.html
```

**Output**:
- An HTML report is generated at the specified or default output path.
- The report includes sender details, geolocation, authentication status, security flags, per-hop analysis, and a risk assessment.
- A GURI (Global Unique Report Identifier) is generated and stored in the SQLite database (`guri_records.db`).
- Logs are written to `C:/GeoFooter/geolocate_debug.log`.

## Configuration

The `CONFIG` dictionary in the script allows customization of:

- **`base_path`**: Directory for logs, database, and output files (default: `C:/GeoFooter`).
- **`log_file`**: Log file name (default: `geolocate_debug.log`).
- **`log_max_bytes`**: Maximum log file size before rotation (default: 5MB).
- **`log_backup_count`**: Number of log backup files to keep (default: 5).
- **`timezone`**: Timezone for timestamps (default: `Europe/London`).
- **`api_keys`**: API keys for external services.
- **`blocklists`**: DNS-based blocklists for IPv4 and IPv6 checks.
- **`risk_thresholds`**: Thresholds for LOW, MEDIUM, and HIGH risk levels.
- **`domain_age_thresholds`**: Thresholds for flagging new domains.

Modify these settings in the `CONFIG` dictionary as needed.

## Output Format

The output is an HTML file with a compact, email-safe, table-based layout, featuring:

- **Header**: A colored banner indicating the risk level (LOW: green, MEDIUM: amber, HIGH: red) and score (0-100).
- **Main Table**: Key information including sender, domain, IP, hops, route, location, organization, ASN, WHOIS data, authentication results, security flags, and web beacon status.
- **Summary Section**: A concise overview of risk level, sender, location, organization, authentication, hops, and web beacons.
- **Per-Hop Analysis Table**: Detailed routing information for each hop, including hostname, IP, ASN, organization, prefix, RIR, country/city, reverse DNS, reputation score, timestamp, delay, and BGP peers.
- **AbuseIPDB Breakdown**: For hosts with non-zero reputation scores, a breakdown of reports (last hour, day, week, 30 days) and categories.
- **GURI and Metadata**: A unique identifier, copyright notice, and creation timestamp at the bottom.

The report is designed to be embedded as an email footer or viewed standalone in a browser.

## Database

The tool stores analysis metadata in a SQLite database (`guri_records.db`) with the following schema:

| Column         | Type | Description                          |
|----------------|------|--------------------------------------|
| `id`           | INTEGER | Primary key, auto-incremented        |
| `guri`         | TEXT | Unique identifier for the report     |
| `sender`       | TEXT | Sender email address                |
| `recipients`   | TEXT | Recipient email addresses           |
| `subject`      | TEXT | Email subject                       |
| `datetime`     | TEXT | Analysis timestamp                  |
| `avg_risk`     | TEXT | Risk score (0-100)                  |
| `random_block` | TEXT | Random block from GURI generation   |

The GURI is a unique identifier composed of hashed blocks derived from sender, recipients, subject, timestamp, and risk score, plus a random 2-character block.

## Logging

Logs are written to `C:/GeoFooter/geolocate_debug.log` with rotation (max 5MB, 5 backups). Log entries include timestamps, log level, and detailed messages for debugging. Key events logged include:

- Script startup and arguments
- Sender/IP extraction results
- Geolocation and WHOIS lookup outcomes
- Authentication parsing results
- Errors and exceptions
- Report generation success/failure

## Limitations

- **API Dependency**: Requires valid API keys for AbuseIPDB and ipinfo.io. Rate limits or downtime may affect functionality.
- **Outlook.com Handling**: Special logic for Outlook.com hosts may not cover all edge cases.
- **Web Beacon Detection**: Limited to 1x1 pixel images and specific CSS styles; advanced beacons may be missed.
- **IPv6 Support**: Blocklist checks are limited for IPv6 addresses due to fewer available blocklists.
- **WHOIS Accuracy**: Dependent on the `python-whois` library, which may fail for some domains or return incomplete data.
- **Header Parsing**: Complex or malformed headers may lead to incomplete extraction of sender or IP information.

## Troubleshooting

- **File Not Found**: Ensure the input file exists and is a valid `.eml` or header file.
- **API Errors**: Verify API keys in `CONFIG` and check internet connectivity.
- **No Sender/IP Found**: Check the input headers for `From` and `Received` fields; malformed headers may require manual inspection.
- **Log Analysis**: Review `geolocate_debug.log` for detailed error messages.
- **Output Directory Issues**: Ensure write permissions for `C:/GeoFooter` and its subdirectories.

## Contributing

Contributions are welcome! Please submit pull requests or issues to the repository. Ensure code follows PEP 8 style guidelines and includes appropriate logging for debugging.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Contact

For support or inquiries, contact the Aliniant Labs team at [support@aliniantlabs.com](mailto:support@aliniantlabs.com).

</xaiArtifact>
