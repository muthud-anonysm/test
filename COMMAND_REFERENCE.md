# CMS Recon Tool - Command Reference Card

## 🚀 Quick Commands

### Basic Scans

```bash
# Simple CMS detection
./cmsrecon -input sub.txt -out results.jsonl

# With verbose output
./cmsrecon -input sub.txt -out results.jsonl -v

# With vulnerability scanning
./cmsrecon -input sub.txt -out results.jsonl -exec-scanners -v

# Fast scan (more workers)
./cmsrecon -input sub.txt -out results.jsonl -workers 20 -v

# Slow/thorough scan (longer timeouts)
./cmsrecon -input sub.txt -out results.jsonl -exec-scanners -http-timeout 30 -scanner-timeout 300 -v
```

## 📋 All Options

```
./cmsrecon [OPTIONS]

-input string           Input file with targets (default: "targets.txt")
-out string            Output JSONL file (default: "cmsrecon_results.jsonl")
-exec-scanners         Execute vulnerability scanners (default: false)
-workers int           Concurrent workers (default: 8)
-http-timeout int      HTTP timeout seconds (default: 15)
-scanner-timeout int   Scanner timeout seconds (default: 60)
-v                     Verbose logging (default: false)
```

## 🔍 Result Analysis

```bash
# Analyze results (generates reports)
./analyze_results.sh results.jsonl

# View specific CMS
cat results.jsonl | jq -r 'select(.detected_cms == "WordPress") | .target'
cat results.jsonl | jq -r 'select(.detected_cms == "Joomla") | .target'
cat results.jsonl | jq -r 'select(.detected_cms == "Drupal") | .target'

# View vulnerable targets
cat results.jsonl | jq 'select(.vulnerabilities | length > 0)'

# Count by CMS
cat results.jsonl | jq -r '.detected_cms // "Unknown"' | sort | uniq -c

# Count by server
cat results.jsonl | jq -r '.server_type // "Unknown"' | sort | uniq -c

# Export to CSV
echo "Target,CMS,Server,Vulns" > summary.csv
cat results.jsonl | jq -r '[.target, .detected_cms, .server_type, (.vulnerabilities|length)] | @csv' >> summary.csv

# Find errors
cat results.jsonl | jq -r 'select(.notes != "" and .notes != null) | "\(.target): \(.notes)"'
```

## 📊 JQ Recipes

```bash
# Pretty print single result
cat results.jsonl | head -1 | jq '.'

# All WordPress sites with vulnerabilities
cat results.jsonl | jq 'select(.detected_cms == "WordPress" and (.vulnerabilities | length > 0))'

# Summary statistics
cat results.jsonl | jq -s '{
  total: length,
  detected: map(select(.detected_cms != null)) | length,
  vulnerable: map(select(.vulnerabilities | length > 0)) | length
}'

# Group by CMS
cat results.jsonl | jq -s 'group_by(.detected_cms) | map({cms: .[0].detected_cms, count: length})'

# Extract URLs only
cat results.jsonl | jq -r '.target'

# Filter by scanner used
cat results.jsonl | jq 'select(.scanner_used == "wpscan")'

# Find specific vulnerabilities
cat results.jsonl | jq 'select(.scanner_output | test("CVE-2023"; "i"))'
```

## 🔧 Installation Commands

```bash
# Build tool
go build -o cmsrecon main.go

# Make scripts executable
chmod +x cmsrecon install_scanners.sh analyze_results.sh

# Install all scanners
./install_scanners.sh

# Install individual scanners
gem install wpscan                    # WordPress
pip3 install droopescan              # Drupal
go install github.com/ffuf/ffuf/v2@latest  # Fuzzer
```

## 🧪 Testing Commands

```bash
# Test with example targets
./cmsrecon -input example_targets.txt -out test.jsonl -v

# Test single target
echo "https://wordpress.org" | ./cmsrecon -input /dev/stdin -out test.jsonl -v

# Verify scanner installation
which wpscan joomscan droopescan cmseek ffuf gobuster

# Check versions
wpscan --version
droopescan --version
ffuf -V
```

## 🎯 Common Workflows

### Workflow 1: Quick Recon
```bash
# 1. Detect CMS only
./cmsrecon -input sub.txt -out detected.jsonl -workers 20 -v

# 2. Extract WordPress targets
cat detected.jsonl | jq -r 'select(.detected_cms == "WordPress") | .target' > wp.txt

# 3. Deep scan WordPress
./cmsrecon -input wp.txt -out wp_vuln.jsonl -exec-scanners -v
```

### Workflow 2: Full Assessment
```bash
# 1. Comprehensive scan
./cmsrecon -input sub.txt -out full_scan.jsonl -exec-scanners -workers 10 -scanner-timeout 180 -v

# 2. Generate reports
./analyze_results.sh full_scan.jsonl

# 3. Extract vulnerabilities
cat full_scan.jsonl | jq 'select(.vulnerabilities | length > 0)' > vulnerable.json
```

### Workflow 3: Large Scale
```bash
# 1. Split targets
split -l 100 large_list.txt chunk_

# 2. Scan in parallel
for f in chunk_*; do
  ./cmsrecon -input "$f" -out "results_${f}.jsonl" -exec-scanners &
done
wait

# 3. Merge results
cat results_chunk_*.jsonl > all_results.jsonl

# 4. Analyze
./analyze_results.sh all_results.jsonl
```

## 📝 Input File Format

```
# Create input file
cat > targets.txt << EOF
https://example.com
https://blog.example.com
http://shop.example.com
subdomain.example.org
EOF

# Or from other tools
subfinder -d example.com | httpx -silent > targets.txt
```

## 🔍 Real-Time Monitoring

```bash
# Monitor progress (in another terminal)
watch -n 5 'wc -l results.jsonl'
watch -n 5 'tail -5 results.jsonl | jq .'

# Monitor system resources
watch -n 2 'ps aux | grep cmsrecon'

# Follow verbose output
./cmsrecon -input sub.txt -out results.jsonl -v | tee scan.log
```

## 🚨 Troubleshooting Commands

```bash
# Check if ports are open
nc -zv example.com 80
nc -zv example.com 443

# Test HTTP connectivity
curl -I https://example.com
curl -I -A "Mozilla/5.0" https://example.com

# Verify DNS resolution
nslookup example.com
dig example.com

# Test scanner manually
wpscan --url https://example.com --no-update
joomscan -u https://example.com

# Check disk space
df -h

# Check network
ping -c 3 example.com
traceroute example.com
```

## 📊 Reporting Commands

```bash
# Generate summary
./analyze_results.sh results.jsonl

# Custom CSV export
cat results.jsonl | jq -r '
  [.target, .detected_cms, .server_type, (.vulnerabilities|length), .scanner_used] 
  | @csv
' > custom_report.csv

# Markdown report
cat results.jsonl | jq -r '
  "| \(.target) | \(.detected_cms // "N/A") | \(.server_type // "N/A") | \(.vulnerabilities|length) |"
'

# HTML summary
cat results.jsonl | jq -r '
  "<tr><td>\(.target)</td><td>\(.detected_cms // "N/A")</td></tr>"
'
```

## 💡 Pro Tips

```bash
# Save with timestamp
./cmsrecon -input sub.txt -out "scan_$(date +%Y%m%d_%H%M%S).jsonl"

# Retry failed scans
cat results.jsonl | jq -r 'select(.notes | test("error|timeout")) | .target' | \
  ./cmsrecon -input /dev/stdin -out retry.jsonl

# Compare two scans
diff <(jq -r '.target' scan1.jsonl | sort) <(jq -r '.target' scan2.jsonl | sort)

# Find new vulnerabilities
comm -13 <(jq -r 'select(.vulnerabilities|length>0) | .target' old.jsonl | sort) \
         <(jq -r 'select(.vulnerabilities|length>0) | .target' new.jsonl | sort)

# Backup before scanning
cp sub.txt "sub_backup_$(date +%Y%m%d).txt"
```

## 🔗 Integration

```bash
# Pipe to Nuclei
cat results.jsonl | jq -r '.target' | nuclei -t nuclei-templates/

# Export for Burp
cat results.jsonl | jq -r '.target' > burp_targets.txt

# Send to webhook
cat results.jsonl | jq -c 'select(.vulnerabilities|length>0)' | \
  while read line; do
    curl -X POST https://webhook.site/xxx -d "$line"
  done

# Alert on Slack (example)
VULN_COUNT=$(jq 'select(.vulnerabilities|length>0)' results.jsonl | wc -l)
curl -X POST -H 'Content-type: application/json' \
  --data "{\"text\":\"Found $VULN_COUNT vulnerable targets\"}" \
  YOUR_SLACK_WEBHOOK_URL
```

## 📞 Quick Help

```bash
# Show help
./cmsrecon -h

# View README
cat README.md | less

# View examples
cat USAGE_EXAMPLES.md | less

# Check tool status
ls -lh cmsrecon
file cmsrecon
./cmsrecon -h
```

---

## 📌 Bookmark These

**Most Common Command:**
```bash
./cmsrecon -input sub.txt -out results.jsonl -exec-scanners -v
```

**Quick Analysis:**
```bash
./analyze_results.sh results.jsonl
```

**Find Vulnerabilities:**
```bash
cat results.jsonl | jq 'select(.vulnerabilities | length > 0)'
```

---

## 🎯 Cheat Sheet Summary

| Task | Command |
|------|---------|
| Basic scan | `./cmsrecon -input sub.txt -out results.jsonl` |
| With scanners | `./cmsrecon -input sub.txt -exec-scanners -v` |
| Fast scan | `./cmsrecon -input sub.txt -workers 20` |
| Analyze | `./analyze_results.sh results.jsonl` |
| Find WordPress | `cat results.jsonl \| jq -r 'select(.detected_cms=="WordPress") \| .target'` |
| Find vulns | `cat results.jsonl \| jq 'select(.vulnerabilities \| length>0)'` |
| Count CMS | `cat results.jsonl \| jq -r '.detected_cms' \| sort \| uniq -c` |
| Export CSV | `cat results.jsonl \| jq -r '[.target,.detected_cms] \| @csv'` |

---

Keep this reference handy for quick lookups! 📖
