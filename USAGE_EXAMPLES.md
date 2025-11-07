# CMS Recon Tool - Usage Examples

## Tool Workflow

```
Input (sub.txt) → CMS Detection → CMS Identified? → Run Specific Scanner → Output (JSONL)
                         ↓                  ↓
                    Server Detection   Try CMSeeK
                         ↓
                    Run Path Fuzzing
```

## Scanner Mapping

| Detected | Primary Scanner | Fallback | Purpose |
|----------|----------------|----------|---------|
| WordPress | `wpscan` | `cmseek` | Plugin, theme, core vulnerabilities |
| Joomla | `joomscan` | `cmseek` | Component vulnerabilities |
| Drupal | `droopescan` | `drupescan`, `cmseek` | Module vulnerabilities |
| Magento | `magescan` | `cmseek` | Magento-specific vulns |
| Nginx | `ffuf` | `gobuster` | Sensitive path discovery |
| Apache | `ffuf` | `gobuster` | Sensitive path discovery |
| Unknown | `cmseek` | - | CMS identification |

## Scenario-Based Examples

### Scenario 1: Bug Bounty - Initial Recon

**Goal:** Quickly identify CMS on all subdomains

```bash
# Step 1: Gather subdomains
subfinder -d target.com -silent | \
httpx -silent -status-code -o live_subs.txt

# Step 2: Quick CMS detection (no scanners)
./cmsrecon -input live_subs.txt -out cms_detected.jsonl -workers 20 -v

# Step 3: Analyze results
./analyze_results.sh cms_detected.jsonl

# Step 4: Focus on WordPress targets
cat cms_detected.jsonl | jq -r 'select(.detected_cms == "WordPress") | .target' > wordpress_targets.txt

# Step 5: Deep scan WordPress only
./cmsrecon -input wordpress_targets.txt -out wp_vulns.jsonl -exec-scanners -v
```

### Scenario 2: Penetration Test - Comprehensive Scan

**Goal:** Full vulnerability assessment with all scanners

```bash
# Comprehensive scan with longer timeouts
./cmsrecon \
  -input targets.txt \
  -out pentest_results.jsonl \
  -exec-scanners \
  -workers 10 \
  -http-timeout 30 \
  -scanner-timeout 300 \
  -v

# Generate report
./analyze_results.sh pentest_results.jsonl

# Extract vulnerable targets for manual testing
cat pentest_results.jsonl | \
  jq -r 'select(.vulnerabilities | length > 0) | 
    "\(.target)\t\(.detected_cms)\t\(.vulnerabilities | length)"' | \
  column -t > vulnerable_for_manual_test.txt
```

### Scenario 3: Red Team - Stealth Scan

**Goal:** Slow, stealthy reconnaissance

```bash
# Low worker count, longer timeouts, detection only
./cmsrecon \
  -input targets.txt \
  -out stealth_scan.jsonl \
  -workers 2 \
  -http-timeout 45 \
  -v

# Manual follow-up on interesting targets
# (don't use -exec-scanners to avoid detection)
```

### Scenario 4: Large Scale Scan (1000+ domains)

**Goal:** Scan thousands of domains efficiently

```bash
# Split targets into chunks
split -l 100 large_subdomain_list.txt chunk_

# Scan in parallel
for chunk in chunk_*; do
  ./cmsrecon \
    -input "$chunk" \
    -out "results_${chunk}.jsonl" \
    -exec-scanners \
    -workers 15 &
done
wait

# Merge results
cat results_chunk_*.jsonl > final_results.jsonl

# Analyze
./analyze_results.sh final_results.jsonl
```

### Scenario 5: WordPress Focus

**Goal:** Find all WordPress sites and identify vulnerable plugins

```bash
# 1. Detect WordPress
./cmsrecon -input all_subs.txt -out detected.jsonl

# 2. Extract WordPress targets
cat detected.jsonl | \
  jq -r 'select(.detected_cms == "WordPress") | .target' > wp_only.txt

# 3. Deep WordPress scan
./cmsrecon \
  -input wp_only.txt \
  -out wp_deep_scan.jsonl \
  -exec-scanners \
  -scanner-timeout 180 \
  -v

# 4. Find vulnerable plugins
cat wp_deep_scan.jsonl | \
  jq -r 'select(.vulnerabilities | length > 0) | 
    "\(.target)\n\(.vulnerabilities | join("\n"))\n"' > wp_vulnerable_plugins.txt
```

### Scenario 6: Server-Specific Recon

**Goal:** Focus on Nginx/Apache misconfigurations

```bash
# Scan with focus on server detection
./cmsrecon -input targets.txt -out server_scan.jsonl -exec-scanners -v

# Extract Nginx servers
cat server_scan.jsonl | \
  jq -r 'select(.server_type == "Nginx") | .target' > nginx_servers.txt

# Extract Apache servers  
cat server_scan.jsonl | \
  jq -r 'select(.server_type == "Apache") | .target' > apache_servers.txt

# Manual fuzzing with custom wordlists
cat nginx_servers.txt | while read target; do
  ffuf -u "$target/FUZZ" \
    -w /usr/share/seclists/Discovery/Web-Content/nginx.txt \
    -mc 200,301,302,401,403 \
    -o "nginx_fuzz_$(echo $target | tr '/:' '_').json"
done
```

## Integration Examples

### With Nuclei

```bash
# 1. Detect CMS
./cmsrecon -input targets.txt -out cms.jsonl

# 2. Run Nuclei on WordPress sites
cat cms.jsonl | \
  jq -r 'select(.detected_cms == "WordPress") | .target' | \
  nuclei -t ~/nuclei-templates/cms/wordpress/ -o nuclei_wp_results.txt

# 3. Run Nuclei on Joomla sites
cat cms.jsonl | \
  jq -r 'select(.detected_cms == "Joomla") | .target' | \
  nuclei -t ~/nuclei-templates/cms/joomla/ -o nuclei_joomla_results.txt
```

### With Metasploit

```bash
# Find WordPress with known vulnerabilities
cat cms_results.jsonl | \
  jq -r 'select(.detected_cms == "WordPress" and 
    (.scanner_output | contains("vulnerable"))) | .target' > msf_targets.txt

# Use in Metasploit
# msfconsole
# > use auxiliary/scanner/http/wordpress_scanner
# > set RHOSTS file:/path/to/msf_targets.txt
# > run
```

### With Burp Suite

```bash
# Export all detected CMS targets
cat cms_results.jsonl | \
  jq -r 'select(.detected_cms != null) | .target' > burp_targets.txt

# Import into Burp Suite Target Scope
```

### With Nmap

```bash
# Extract targets and convert to IP list
cat cms_results.jsonl | \
  jq -r '.target' | \
  sed 's|https\?://||' | \
  sed 's|/.*||' > domains.txt

# Resolve to IPs and scan
cat domains.txt | while read domain; do
  nmap -sV -p 80,443,8080,8443 "$domain"
done
```

## Output Parsing Examples

### Find High-Value Targets

```bash
# WordPress with vulnerabilities
cat results.jsonl | \
  jq 'select(.detected_cms == "WordPress" and (.vulnerabilities | length > 5))'

# Any CMS with critical vulns
cat results.jsonl | \
  jq 'select(.scanner_output | test("critical|high"; "i"))'

# Outdated CMS versions
cat results.jsonl | \
  jq 'select(.scanner_output | test("outdated|old version"; "i"))'
```

### Generate Target Lists

```bash
# All WordPress sites
cat results.jsonl | jq -r 'select(.detected_cms == "WordPress") | .target' > wp_sites.txt

# All sites with vulnerabilities
cat results.jsonl | jq -r 'select(.vulnerabilities | length > 0) | .target' > vuln_sites.txt

# Mix of CMS
cat results.jsonl | jq -r 'select(.detected_cms != null) | "\(.detected_cms): \(.target)"' | sort

# Failed scans for retry
cat results.jsonl | jq -r 'select(.notes | test("error|timeout"; "i")) | .target' > retry_targets.txt
```

### Statistics and Reporting

```bash
# Count by CMS
cat results.jsonl | jq -r '.detected_cms // "Unknown"' | sort | uniq -c | sort -rn

# Vulnerability stats
cat results.jsonl | jq -r '.vulnerabilities | length' | \
  awk '{sum+=$1; if($1>0) vuln++} END {print "Total vulns:", sum, "Affected targets:", vuln}'

# Average scan time (if you log timestamps)
cat results.jsonl | jq -r '.scan_duration' | awk '{sum+=$1; count++} END {print sum/count}'

# Success rate
total=$(wc -l < results.jsonl)
success=$(jq -r 'select(.detected_cms != null)' results.jsonl | wc -l)
echo "Detection rate: $(echo "scale=2; $success*100/$total" | bc)%"
```

### Advanced JQ Queries

```bash
# Group by CMS with counts
cat results.jsonl | \
  jq -s 'group_by(.detected_cms) | 
    map({cms: .[0].detected_cms, count: length, targets: map(.target)})'

# Find targets with specific vulnerability types
cat results.jsonl | \
  jq 'select(.vulnerabilities | 
    any(. | test("SQL Injection|XSS|RCE"; "i")))'

# Create summary object
cat results.jsonl | \
  jq -s '{
    total: length,
    cms_detected: map(select(.detected_cms != null)) | length,
    vulnerable: map(select(.vulnerabilities | length > 0)) | length,
    by_cms: group_by(.detected_cms) | map({(.[0].detected_cms): length}) | add
  }'
```

## Automation Examples

### Cron Job for Daily Scanning

```bash
# Create script: ~/daily_cms_scan.sh
#!/bin/bash
DATE=$(date +%Y%m%d)
cd /path/to/cmsrecon
./cmsrecon -input prod_targets.txt -out "results_${DATE}.jsonl" -exec-scanners
./analyze_results.sh "results_${DATE}.jsonl"

# Add to crontab
# 0 2 * * * ~/daily_cms_scan.sh >> ~/scan_logs/cron.log 2>&1
```

### Continuous Monitoring

```bash
#!/bin/bash
# monitor_new_subs.sh - Monitor for new subdomains and scan them

LAST_SCAN="last_scan.txt"
DOMAIN="target.com"

# Get current subdomains
subfinder -d $DOMAIN -silent | sort > current_subs.txt

if [ -f "$LAST_SCAN" ]; then
    # Find new subdomains
    comm -13 "$LAST_SCAN" current_subs.txt > new_subs.txt
    
    if [ -s new_subs.txt ]; then
        echo "Found $(wc -l < new_subs.txt) new subdomains"
        
        # Scan new subdomains
        ./cmsrecon -input new_subs.txt -out "new_subs_$(date +%Y%m%d).jsonl" -exec-scanners -v
        
        # Alert on vulnerabilities
        vulns=$(jq 'select(.vulnerabilities | length > 0)' "new_subs_$(date +%Y%m%d).jsonl" | wc -l)
        if [ $vulns -gt 0 ]; then
            echo "ALERT: $vulns new vulnerable targets found!" | mail -s "CMS Scan Alert" admin@example.com
        fi
    fi
fi

cp current_subs.txt "$LAST_SCAN"
```

## Pro Tips

1. **Always test locally first**
   ```bash
   echo "http://localhost:8080" > test.txt
   ./cmsrecon -input test.txt -out test.jsonl -v
   ```

2. **Use timeouts appropriately**
   - Quick recon: `-http-timeout 10 -scanner-timeout 60`
   - Thorough scan: `-http-timeout 30 -scanner-timeout 300`

3. **Monitor resource usage**
   ```bash
   # In another terminal
   watch -n 2 'ps aux | grep cmsrecon'
   ```

4. **Save intermediate results**
   ```bash
   # Detection phase
   ./cmsrecon -input all.txt -out detected.jsonl
   
   # Scanning phase (on detected targets only)
   cat detected.jsonl | jq -r 'select(.detected_cms != null) | .target' | \
     ./cmsrecon -input /dev/stdin -out scanned.jsonl -exec-scanners
   ```

5. **Validate before reporting**
   ```bash
   # Always manually verify findings
   cat results.jsonl | \
     jq -r 'select(.vulnerabilities | length > 0) | .target' | \
     while read target; do
       echo "Check: $target"
       # Manual verification here
     done
   ```

## Troubleshooting Examples

### Debug a Single Target

```bash
# Create single target file
echo "https://example.com" > single.txt

# Run with verbose and no timeout
./cmsrecon -input single.txt -out debug.jsonl -v -http-timeout 60 -exec-scanners

# Check output
cat debug.jsonl | jq '.'
```

### Test Scanner Installation

```bash
# Test each scanner individually
wpscan --help
joomscan --help
droopescan --help
cmseek -h
ffuf -h
gobuster help
```

### Verify Wordlists

```bash
# Check if wordlists exist
ls -lh /usr/share/seclists/Discovery/Web-Content/
ls -lh /usr/share/wordlists/dirb/
```

Happy scanning! Remember to always get proper authorization before testing any targets. 🔒
