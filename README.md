# CMS Recon Tool

A comprehensive CMS reconnaissance and vulnerability scanning tool that automatically detects Content Management Systems and web servers, then runs appropriate security scanners.

## Features

- **Multi-CMS Detection**: Automatically detects WordPress, Joomla, Drupal, Magento, Shopify, Wix, Squarespace
- **Server Detection**: Identifies Nginx, Apache, IIS, LiteSpeed web servers
- **Automated Vulnerability Scanning**:
  - **WordPress**: WPScan (plugins, themes, core vulnerabilities)
  - **Joomla**: JoomScan
  - **Drupal**: Droopescan / Drupescan
  - **Magento**: MageScan
  - **Nginx/Apache**: Sensitive path fuzzing with ffuf/gobuster
  - **Unknown CMS**: CMSeeK for comprehensive detection
- **Concurrent Processing**: Fast parallel scanning with configurable workers
- **JSON Output**: Results in JSONL format for easy parsing and integration

## Installation

### Prerequisites

```bash
# Install Go (if not already installed)
# Download from https://golang.org/dl/

# Install scanning tools (optional but recommended)
# WordPress Scanner
gem install wpscan
wpscan --update

# Joomla Scanner
git clone https://github.com/OWASP/joomscan.git
cd joomscan && chmod +x joomscan.pl
# Add to PATH or use full path

# Drupal Scanner
pip3 install droopescan

# CMSeeK (General CMS Detection)
git clone https://github.com/Tuhinshubhra/CMSeeK.git
cd CMSeeK && pip3 install -r requirements.txt
# Create alias: alias cmseek='python3 /path/to/CMSeeK/cmseek.py'

# Fuzzing Tools
go install github.com/ffuf/ffuf@latest
go install github.com/OJ/gobuster/v3@latest

# Wordlists
sudo apt install seclists
# Or download from https://github.com/danielmiessler/SecLists
```

### Build the Tool

```bash
cd /workspace
go build -o cmsrecon main.go
```

## Usage

### Basic Usage

```bash
# Simple CMS detection (no scanner execution)
./cmsrecon -input sub.txt -out results.jsonl

# With vulnerability scanning
./cmsrecon -input sub.txt -out results.jsonl -exec-scanners

# Verbose mode
./cmsrecon -input sub.txt -out results.jsonl -exec-scanners -v
```

### Advanced Options

```bash
./cmsrecon [OPTIONS]

Options:
  -input string
        newline-separated list of target URLs (default "targets.txt")
  -out string
        output JSONL file (default "cmsrecon_results.jsonl")
  -exec-scanners
        execute external scanners when CMS is detected
  -scanner-timeout int
        timeout seconds for external scanners (default 60)
  -workers int
        concurrent workers (default 8)
  -http-timeout int
        HTTP client timeout seconds (default 15)
  -v    verbose logs
```

### Input Format

The input file should contain one URL per line:

```
https://example.com
https://blog.example.com
http://shop.example.com
subdomain.example.org
```

URLs without scheme will default to `http://`.

### Output Format

Results are saved in JSONL format (one JSON object per line):

```json
{
  "target": "https://example.com",
  "detected_cms": "WordPress",
  "server_type": "Nginx",
  "cms_version": "6.3.1",
  "scanner_used": "wpscan",
  "scanner_output": "...",
  "vulnerabilities": [
    "[!] WordPress 6.3.1 - CVE-2023-xxxxx",
    "[+] Plugin vulnerable-plugin 1.2.3 has known vulnerabilities"
  ],
  "notes": ""
}
```

## Example Workflow

```bash
# 1. Scan subdomains with subfinder, amass, etc.
subfinder -d example.com -o subs.txt
amass enum -d example.com >> subs.txt

# 2. Filter live hosts with httpx
cat subs.txt | httpx -silent -o live_subs.txt

# 3. Run CMS recon
./cmsrecon -input live_subs.txt -out cms_results.jsonl -exec-scanners -v -workers 10

# 4. Parse results
cat cms_results.jsonl | jq 'select(.detected_cms != null)'
cat cms_results.jsonl | jq 'select(.vulnerabilities | length > 0)'
```

## Scanning Tools Mapping

| CMS/Server | Primary Scanner | Fallback Scanner |
|------------|----------------|------------------|
| WordPress  | wpscan         | cmseek          |
| Joomla     | joomscan       | cmseek          |
| Drupal     | droopescan     | drupescan, cmseek |
| Magento    | magescan       | cmseek          |
| Nginx      | ffuf           | gobuster        |
| Apache     | ffuf           | gobuster        |
| Unknown    | cmseek         | -               |

## Performance Tips

1. **Adjust Workers**: Use `-workers 20` for faster scanning (if your system can handle it)
2. **Increase Timeouts**: For slow targets, use `-http-timeout 30 -scanner-timeout 120`
3. **Skip Scanners**: Remove `-exec-scanners` for faster detection-only mode
4. **Filter Input**: Pre-filter your subdomain list to reduce noise

## Troubleshooting

### Scanners Not Found

If a scanner is not installed, the tool will automatically skip it and try fallback options:

```bash
# Check if tools are in PATH
which wpscan joomscan droopescan cmseek ffuf gobuster
```

### Permission Denied

```bash
chmod +x cmsrecon
```

### SSL/TLS Errors

The tool uses standard Go HTTP client. For self-signed certificates, you may need to modify the client in `main.go`.

## Security Considerations

- **Authorization**: Only scan targets you have permission to test
- **Rate Limiting**: Be mindful of rate limits and use appropriate worker counts
- **API Keys**: Some scanners (like WPScan) work better with API keys
- **Logs**: The tool logs to stdout; redirect as needed for operational security

## Contributing

Feel free to add more CMS detections or scanner integrations by modifying:
- `cmsIndicators` map for new CMS patterns
- `serverIndicators` map for new server types
- `scannerCandidates` map for new scanning tools

## License

This tool is for authorized security testing only. Use responsibly.

## Output Analysis Examples

### Find all WordPress sites

```bash
cat cms_results.jsonl | jq -r 'select(.detected_cms == "WordPress") | .target'
```

### Find vulnerable targets

```bash
cat cms_results.jsonl | jq 'select(.vulnerabilities | length > 0)'
```

### Generate summary report

```bash
cat cms_results.jsonl | jq -r '[.detected_cms] | unique'
```

### Export to CSV

```bash
cat cms_results.jsonl | jq -r '[.target, .detected_cms, .server_type, (.vulnerabilities | length)] | @csv'
```

## Known Issues

- CMSeeK can be slow on some targets
- Some scanners require API keys for full functionality
- Fuzzing tools need wordlist paths adjusted based on your system

## Roadmap

- [ ] Add support for more CMS platforms (PrestaShop, OpenCart, etc.)
- [ ] Integrate Nuclei templates
- [ ] Add screenshot capability
- [ ] Generate HTML reports
- [ ] Add proxy support
- [ ] Implement rate limiting per target
