#!/bin/bash

# CMS Recon Results Analyzer
# Analyzes JSONL output from cmsrecon tool

RESULTS_FILE="${1:-cmsrecon_results.jsonl}"

if [ ! -f "$RESULTS_FILE" ]; then
    echo "Error: Results file not found: $RESULTS_FILE"
    echo "Usage: $0 [results_file.jsonl]"
    exit 1
fi

echo "================================================"
echo "CMS Recon Results Analysis"
echo "================================================"
echo ""
echo "Analyzing: $RESULTS_FILE"
echo ""

# Total targets scanned
TOTAL=$(wc -l < "$RESULTS_FILE")
echo "Total Targets Scanned: $TOTAL"
echo ""

# CMS Distribution
echo "=== CMS Distribution ==="
jq -r '.detected_cms // "Unknown"' "$RESULTS_FILE" | sort | uniq -c | sort -rn
echo ""

# Server Distribution
echo "=== Server Distribution ==="
jq -r '.server_type // "Unknown"' "$RESULTS_FILE" | sort | uniq -c | sort -rn
echo ""

# Vulnerable Targets
VULNERABLE=$(jq 'select(.vulnerabilities | length > 0)' "$RESULTS_FILE" | wc -l)
echo "=== Vulnerability Summary ==="
echo "Targets with Vulnerabilities: $VULNERABLE"
echo ""

if [ $VULNERABLE -gt 0 ]; then
    echo "Vulnerable Targets:"
    jq -r 'select(.vulnerabilities | length > 0) | "\(.target) - \(.detected_cms // "Unknown") - \(.vulnerabilities | length) vulnerabilities"' "$RESULTS_FILE"
    echo ""
fi

# Targets by CMS
echo "=== WordPress Sites ==="
WP_COUNT=$(jq -r 'select(.detected_cms == "WordPress") | .target' "$RESULTS_FILE" | wc -l)
echo "Count: $WP_COUNT"
if [ $WP_COUNT -gt 0 ]; then
    jq -r 'select(.detected_cms == "WordPress") | .target' "$RESULTS_FILE" | head -5
    [ $WP_COUNT -gt 5 ] && echo "... and $((WP_COUNT - 5)) more"
fi
echo ""

echo "=== Joomla Sites ==="
JOOMLA_COUNT=$(jq -r 'select(.detected_cms == "Joomla") | .target' "$RESULTS_FILE" | wc -l)
echo "Count: $JOOMLA_COUNT"
if [ $JOOMLA_COUNT -gt 0 ]; then
    jq -r 'select(.detected_cms == "Joomla") | .target' "$RESULTS_FILE" | head -5
    [ $JOOMLA_COUNT -gt 5 ] && echo "... and $((JOOMLA_COUNT - 5)) more"
fi
echo ""

echo "=== Drupal Sites ==="
DRUPAL_COUNT=$(jq -r 'select(.detected_cms == "Drupal") | .target' "$RESULTS_FILE" | wc -l)
echo "Count: $DRUPAL_COUNT"
if [ $DRUPAL_COUNT -gt 0 ]; then
    jq -r 'select(.detected_cms == "Drupal") | .target' "$RESULTS_FILE" | head -5
    [ $DRUPAL_COUNT -gt 5 ] && echo "... and $((DRUPAL_COUNT - 5)) more"
fi
echo ""

# Errors and Issues
ERRORS=$(jq 'select(.notes != "" and .notes != null)' "$RESULTS_FILE" | wc -l)
echo "=== Errors and Issues ==="
echo "Targets with errors: $ERRORS"
if [ $ERRORS -gt 0 ]; then
    echo "Sample errors:"
    jq -r 'select(.notes != "" and .notes != null) | "\(.target): \(.notes)"' "$RESULTS_FILE" | head -5
fi
echo ""

# Generate reports
echo "=== Report Files ==="
REPORT_DIR="cmsrecon_reports"
mkdir -p "$REPORT_DIR"

# CSV Report
CSV_FILE="$REPORT_DIR/cms_summary_$(date +%Y%m%d_%H%M%S).csv"
echo "Target,CMS,Server,Scanner,Vulnerabilities,Status" > "$CSV_FILE"
jq -r '[.target, (.detected_cms // "Unknown"), (.server_type // "Unknown"), (.scanner_used // "None"), (.vulnerabilities | length), (if .notes == "" or .notes == null then "Success" else "Error" end)] | @csv' "$RESULTS_FILE" >> "$CSV_FILE"
echo "✓ CSV Report: $CSV_FILE"

# Vulnerable targets list
VULN_FILE="$REPORT_DIR/vulnerable_targets_$(date +%Y%m%d_%H%M%S).txt"
jq -r 'select(.vulnerabilities | length > 0) | .target' "$RESULTS_FILE" > "$VULN_FILE"
echo "✓ Vulnerable Targets: $VULN_FILE"

# WordPress targets
WP_FILE="$REPORT_DIR/wordpress_targets_$(date +%Y%m%d_%H%M%S).txt"
jq -r 'select(.detected_cms == "WordPress") | .target' "$RESULTS_FILE" > "$WP_FILE"
echo "✓ WordPress Targets: $WP_FILE"

# HTML Report
HTML_FILE="$REPORT_DIR/report_$(date +%Y%m%d_%H%M%S).html"
cat > "$HTML_FILE" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>CMS Recon Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        h1 { color: #333; }
        table { border-collapse: collapse; width: 100%; background: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        th { background: #4CAF50; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f5f5f5; }
        .vuln { color: #d32f2f; font-weight: bold; }
        .success { color: #388e3c; }
        .error { color: #f57c00; }
        .stats { display: flex; gap: 20px; margin: 20px 0; }
        .stat-box { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); flex: 1; }
        .stat-number { font-size: 36px; font-weight: bold; color: #4CAF50; }
    </style>
</head>
<body>
    <h1>🔍 CMS Reconnaissance Report</h1>
    <p>Generated: $(date)</p>
    
    <div class="stats">
        <div class="stat-box">
            <div>Total Targets</div>
            <div class="stat-number">$TOTAL</div>
        </div>
        <div class="stat-box">
            <div>Vulnerable</div>
            <div class="stat-number" style="color: #d32f2f;">$VULNERABLE</div>
        </div>
        <div class="stat-box">
            <div>WordPress</div>
            <div class="stat-number" style="color: #21759b;">$WP_COUNT</div>
        </div>
        <div class="stat-box">
            <div>Errors</div>
            <div class="stat-number" style="color: #f57c00;">$ERRORS</div>
        </div>
    </div>
    
    <h2>Scan Results</h2>
    <table>
        <tr>
            <th>Target</th>
            <th>CMS</th>
            <th>Server</th>
            <th>Scanner</th>
            <th>Vulnerabilities</th>
            <th>Status</th>
        </tr>
EOF

jq -r '.[] | "<tr><td>\(.target)</td><td>\(.detected_cms // "Unknown")</td><td>\(.server_type // "Unknown")</td><td>\(.scanner_used // "None")</td><td class=\"" + (if (.vulnerabilities | length) > 0 then "vuln" else "" end) + "\">\((.vulnerabilities | length) // 0)</td><td class=\"" + (if .notes == "" or .notes == null then "success\">✓ Success" else "error\">⚠ Error" end) + "</td></tr>"' "$RESULTS_FILE" >> "$HTML_FILE"

cat >> "$HTML_FILE" << EOF
    </table>
</body>
</html>
EOF

echo "✓ HTML Report: $HTML_FILE"

echo ""
echo "================================================"
echo "Analysis Complete!"
echo "================================================"
echo ""
echo "Next Steps:"
echo "  1. Review vulnerable targets in: $VULN_FILE"
echo "  2. Open HTML report: $HTML_FILE"
echo "  3. Manually verify findings"
echo ""
