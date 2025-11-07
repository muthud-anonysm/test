# CMS Recon Tool - Quick Start Guide

## Installation (5 minutes)

### Step 1: Build the Tool

```bash
cd /workspace
go build -o cmsrecon main.go
```

### Step 2: Install Scanning Tools (Optional but Recommended)

```bash
# Make the installation script executable
chmod +x install_scanners.sh

# Run the installation script
./install_scanners.sh
```

Or install tools manually:

```bash
# WPScan (WordPress)
gem install wpscan

# JoomScan (Joomla)
git clone https://github.com/OWASP/joomscan.git
cd joomscan && chmod +x joomscan.pl

# Droopescan (Drupal)
pip3 install droopescan

# CMSeeK (Multi-CMS)
git clone https://github.com/Tuhinshubhra/CMSeeK.git
cd CMSeeK && pip3 install -r requirements.txt

# ffuf (Fuzzing)
go install github.com/ffuf/ffuf/v2@latest

# Gobuster (Directory brute force)
go install github.com/OJ/gobuster/v3@latest
```

## Basic Usage

### Example 1: Quick CMS Detection (No Scanner Execution)

```bash
# Prepare your subdomain list
cat > sub.txt << EOF
https://example.com
https://blog.example.com
https://shop.example.com
EOF

# Run detection only (fast)
./cmsrecon -input sub.txt -out results.jsonl -v
```

### Example 2: Full Vulnerability Scan

```bash
# Run with scanner execution
./cmsrecon -input sub.txt -out results.jsonl -exec-scanners -v

# View results
cat results.jsonl | jq '.'
```

### Example 3: High-Performance Scan

```bash
# Use more workers and longer timeouts
./cmsrecon \
  -input sub.txt \
  -out results.jsonl \
  -exec-scanners \
  -workers 20 \
  -http-timeout 30 \
  -scanner-timeout 120 \
  -v
```

## Real-World Workflow

### Complete Bug Bounty / Pentest Workflow

```bash
# 1. Subdomain Enumeration
subfinder -d target.com -o subs.txt
amass enum -d target.com >> subs.txt

# 2. Filter for live hosts
cat subs.txt | httpx -silent -status-code -tech-detect -o live_subs.txt

# 3. Run CMS Recon
./cmsrecon \
  -input live_subs.txt \
  -out cms_scan_results.jsonl \
  -exec-scanners \
  -workers 15 \
  -scanner-timeout 180 \
  -v

# 4. Filter results
# Find all WordPress sites
cat cms_scan_results.jsonl | jq -r 'select(.detected_cms == "WordPress") | .target'

# Find all vulnerable targets
cat cms_scan_results.jsonl | jq 'select(.vulnerabilities | length > 0)'

# Get summary
cat cms_scan_results.jsonl | jq -r '.detected_cms' | sort | uniq -c
```

## Output Analysis

### View All Detected CMS

```bash
cat results.jsonl | jq -r '[.target, .detected_cms, .server_type] | @tsv' | column -t
```

### Find Vulnerable WordPress Sites

```bash
cat results.jsonl | jq 'select(.detected_cms == "WordPress" and (.vulnerabilities | length > 0))'
```

### Export to CSV

```bash
echo "Target,CMS,Server,Vulnerabilities" > report.csv
cat results.jsonl | jq -r '[.target, .detected_cms, .server_type, (.vulnerabilities | length)] | @csv' >> report.csv
```

### Generate HTML Report

```bash
cat results.jsonl | jq -s '.' | \
  jq -r '
    "<html><head><title>CMS Recon Report</title></head><body>",
    "<h1>CMS Reconnaissance Report</h1>",
    "<table border=\"1\"><tr><th>Target</th><th>CMS</th><th>Server</th><th>Vulns</th></tr>",
    (.[] | "<tr><td>\(.target)</td><td>\(.detected_cms // "N/A")</td><td>\(.server_type // "N/A")</td><td>\(.vulnerabilities | length)</td></tr>"),
    "</table></body></html>"
  ' > report.html
```

## Useful Commands

### Check Tool Installation

```bash
which wpscan joomscan droopescan cmseek ffuf gobuster
```

### Update Scanner Databases

```bash
# WPScan
wpscan --update

# Nuclei (if installed)
nuclei -update-templates
```

### Monitor Progress

```bash
# In another terminal
watch -n 5 'wc -l results.jsonl'
```

### Filter by Severity

```bash
# High severity findings
cat results.jsonl | jq 'select(.scanner_output | test("critical|high"; "i"))'
```

## Troubleshooting

### Issue: "command not found"

**Solution:** Make sure tools are in your PATH

```bash
# Add Go bin to PATH
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc

# Check if tools are accessible
which wpscan ffuf gobuster
```

### Issue: Timeouts on slow targets

**Solution:** Increase timeouts

```bash
./cmsrecon -input sub.txt -http-timeout 60 -scanner-timeout 300
```

### Issue: Too many "scanner not found" messages

**Solution:** Install missing tools or run without `-exec-scanners`

```bash
# Detection only (no scanners needed)
./cmsrecon -input sub.txt -out results.jsonl
```

### Issue: Rate limiting / blocked

**Solution:** Reduce workers and add delays

```bash
./cmsrecon -input sub.txt -workers 5
```

## Performance Benchmarks

| Workers | Targets | Time | Notes |
|---------|---------|------|-------|
| 5       | 100     | ~5 min | Conservative |
| 10      | 100     | ~3 min | Recommended |
| 20      | 100     | ~2 min | Aggressive |
| 50      | 100     | ~1 min | Very aggressive (may trigger WAF) |

## Best Practices

1. **Start with detection only** - Run without `-exec-scanners` first
2. **Use appropriate worker counts** - Start with 10, increase if needed
3. **Respect rate limits** - Don't overwhelm targets
4. **Keep scanners updated** - Run `wpscan --update` regularly
5. **Save your results** - Use descriptive output filenames with timestamps
6. **Legal authorization** - Only scan targets you have permission to test

## Integration with Other Tools

### With Nuclei

```bash
# Extract all targets that have CMS detected
cat results.jsonl | jq -r 'select(.detected_cms != null) | .target' | \
  nuclei -t ~/nuclei-templates/
```

### With Burp Suite

```bash
# Export to Burp-friendly format
cat results.jsonl | jq -r '.target' > targets_for_burp.txt
```

### With Metasploit

```bash
# Find WordPress with vulnerabilities
cat results.jsonl | jq -r 'select(.detected_cms == "WordPress" and (.vulnerabilities | length > 0)) | .target'
# Then use in msfconsole
```

## Advanced Tips

### Custom CMS Detection

Edit `main.go` to add your own CMS indicators:

```go
var cmsIndicators = map[string]string{
    "your-pattern": "Your-CMS",
}
```

### Custom Scanner Integration

Add your scanner to the `scannerCandidates` map:

```go
"YourCMS": {
    {"your-scanner", "-u", "{target}", "--options"},
},
```

## Support

For issues or questions:
1. Check the README.md for detailed documentation
2. Verify scanner installations
3. Run with `-v` for verbose output
4. Check tool versions

Happy hunting! 🎯
