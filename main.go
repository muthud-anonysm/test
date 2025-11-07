package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Simple CMS recon + external scanner launcher
// - Reads a newline-separated list of target URLs from -input
// - Detects CMS by fetching the target and looking for common indicators
// - Optionally runs external scanners for detected CMS using -exec-scanners
// - Writes results as JSONL to -out

var (
	inputFile        string
	outFile          string
	execScanners     bool
	scannerTimeoutSec int
	verbose          bool
	workerCount      int
	clientTimeoutSec int
)

func init() {
	flag.StringVar(&inputFile, "input", "targets.txt", "newline-separated list of target URLs")
	flag.StringVar(&outFile, "out", "cmsrecon_results.jsonl", "output JSONL file")
	flag.BoolVar(&execScanners, "exec-scanners", false, "execute external scanners when CMS is detected")
	flag.IntVar(&scannerTimeoutSec, "scanner-timeout", 60, "timeout seconds for external scanners")
	flag.BoolVar(&verbose, "v", false, "verbose logs")
	flag.IntVar(&workerCount, "workers", 8, "concurrent workers")
	flag.IntVar(&clientTimeoutSec, "http-timeout", 15, "HTTP client timeout seconds")
}

func vlog(format string, a ...interface{}) {
	if verbose {
		fmt.Printf(format+"\n", a...)
	}
}

// result struct for JSONL
type Result struct {
	Target        string   `json:"target"`
	DetectedCMS   string   `json:"detected_cms,omitempty"`
	ServerType    string   `json:"server_type,omitempty"`
	CMSVersion    string   `json:"cms_version,omitempty"`
	ScannerUsed   string   `json:"scanner_used,omitempty"`
	ScannerOutput string   `json:"scanner_output,omitempty"`
	Vulnerabilities []string `json:"vulnerabilities,omitempty"`
	Notes         string   `json:"notes,omitempty"`
}

// cmsIndicators maps simple substrings to CMS names
var cmsIndicators = map[string]string{
	"wp-content":       "WordPress",
	"wp-includes":      "WordPress",
	"wordpress":        "WordPress",
	"<meta name=\"generator\" content=\"WordPress": "WordPress",
	"/wp-json/":        "WordPress",
	"/administrator/index.php": "Joomla",
	"com_content":      "Joomla",
	"joomla":           "Joomla",
	"option=com_":      "Joomla",
	"drupal":           "Drupal",
	"/sites/default/":  "Drupal",
	"/core/misc/drupal.js": "Drupal",
	"x-generator: drupal": "Drupal",
	"mage":             "Magento",
	"/skin/frontend":   "Magento",
	"magento":          "Magento",
	"shopify":          "Shopify",
	"wix.com":          "Wix",
	"squarespace":      "Squarespace",
}

// serverIndicators for detecting web servers
var serverIndicators = map[string]string{
	"nginx":  "Nginx",
	"apache": "Apache",
	"iis":    "IIS",
	"litespeed": "LiteSpeed",
}

// scannerCandidates maps CMS to one or more candidate commands (each command is a string slice)
var scannerCandidates = map[string][][]string{
	"WordPress": {
		{"wpscan", "--url", "{target}", "--no-update", "--enumerate", "vp,vt,u", "--plugins-detection", "aggressive"},
		{"cmseek", "-u", "{target}"},
	},
	"Joomla": {
		{"joomscan", "-u", "{target}"},
		{"cmseek", "-u", "{target}"},
	},
	"Drupal": {
		{"droopescan", "scan", "drupal", "-u", "{target}"},
		{"drupescan", "scan", "-u", "{target}"},
		{"cmseek", "-u", "{target}"},
	},
	"Magento": {
		{"magescan", "scan:all", "{target}"},
		{"cmseek", "-u", "{target}"},
	},
	"Nginx": {
		{"ffuf", "-u", "{target}/FUZZ", "-w", "/usr/share/seclists/Discovery/Web-Content/nginx.txt", "-mc", "200,204,301,302,307,401,403"},
		{"gobuster", "dir", "-u", "{target}", "-w", "/usr/share/wordlists/dirb/common.txt", "-t", "50"},
	},
	"Apache": {
		{"ffuf", "-u", "{target}/FUZZ", "-w", "/usr/share/seclists/Discovery/Web-Content/apache.txt", "-mc", "200,204,301,302,307,401,403"},
		{"gobuster", "dir", "-u", "{target}", "-w", "/usr/share/wordlists/dirb/common.txt", "-t", "50"},
	},
	"Unknown": {
		{"cmseek", "-u", "{target}", "--follow-redirect"},
	},
}

func main() {
	flag.Parse()

	// open input
	f, err := os.Open(inputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open input %s: %v\n", inputFile, err)
		os.Exit(1)
	}
	defer f.Close()

	out, err := os.Create(outFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create output %s: %v\n", outFile, err)
		os.Exit(1)
	}
	defer out.Close()

	scanner := bufio.NewScanner(f)
	jobs := make(chan string)
	var wg sync.WaitGroup

	ctx := context.Background()
	client := &http.Client{Timeout: time.Duration(clientTimeoutSec) * time.Second}

	// worker pool
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				res := processTarget(ctx, client, target)
				b, _ := json.Marshal(res)
				out.Write(b)
				out.Write([]byte("\n"))
			}
		}()
	}

	for scanner.Scan() {
		t := strings.TrimSpace(scanner.Text())
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		jobs <- t
	}
	close(jobs)
	wg.Wait()

	fmt.Printf("done. results written to %s\n", outFile)
}

func processTarget(ctx context.Context, client *http.Client, target string) Result {
	var r Result
	r.Target = target

	// try to fetch target
	body, headers, err := fetchTarget(ctx, client, target)
	if err != nil {
		r.Notes = fmt.Sprintf("fetch error: %v", err)
		vlog("%s - fetch error: %v", target, err)
		return r
	}

	// detect server type from headers
	serverType := detectServerType(headers)
	if serverType != "" {
		r.ServerType = serverType
		vlog("%s - detected server: %s", target, serverType)
	}

	// detect CMS
	detected := detectCMS(body, headers)
	if detected == "" {
		vlog("%s - CMS not detected by simple heuristics", target)
		// Try CMSeeK as fallback if exec-scanners is enabled
		if execScanners {
			vlog("%s - trying CMSeeK for detection", target)
			outStr, scannerName, err := tryExecScannersForCMS(ctx, "Unknown", target)
			if err == nil && outStr != "" {
				r.ScannerUsed = scannerName
				r.ScannerOutput = outStr
				// Try to extract CMS from CMSeeK output
				extractedCMS := extractCMSFromOutput(outStr)
				if extractedCMS != "" {
					r.DetectedCMS = extractedCMS
					vlog("%s - CMSeeK detected: %s", target, extractedCMS)
				}
			}
		}
	} else {
		r.DetectedCMS = detected
		vlog("%s - detected CMS: %s", target, detected)
	}

	// Run specific scanners for detected CMS or server type
	if execScanners {
		scanTarget := detected
		if scanTarget == "" && serverType != "" {
			scanTarget = serverType
		}
		if scanTarget != "" {
			outStr, scannerName, err := tryExecScannersForCMS(ctx, scanTarget, target)
			if err != nil {
				// record both some output and the error
				r.ScannerOutput = outStr
				r.ScannerUsed = scannerName
				if r.Notes == "" {
					r.Notes = err.Error()
				} else {
					r.Notes += "; " + err.Error()
				}
				vlog("%s - scanner error: %v", target, err)
			} else if outStr != "" {
				r.ScannerOutput = outStr
				r.ScannerUsed = scannerName
				// Extract vulnerabilities
				r.Vulnerabilities = extractVulnerabilities(outStr)
				vlog("%s - scan completed with %s", target, scannerName)
			}
		}
	}

	return r
}

func fetchTarget(ctx context.Context, client *http.Client, target string) (string, http.Header, error) {
	// ensure scheme
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(io.LimitReader(resp.Body, 200*1024)) // 200KB max
	if err != nil {
		return "", nil, err
	}
	return string(b), resp.Header, nil
}

func detectCMS(body string, headers http.Header) string {
	lower := strings.ToLower(body)
	
	// Check headers first
	if xPowered := headers.Get("X-Powered-By"); xPowered != "" {
		xpLower := strings.ToLower(xPowered)
		for k, v := range cmsIndicators {
			if strings.Contains(xpLower, strings.ToLower(k)) {
				return v
			}
		}
	}
	
	// Check body content
	for k, v := range cmsIndicators {
		if strings.Contains(lower, strings.ToLower(k)) {
			return v
		}
	}
	return ""
}

func detectServerType(headers http.Header) string {
	server := headers.Get("Server")
	if server == "" {
		return ""
	}
	serverLower := strings.ToLower(server)
	for k, v := range serverIndicators {
		if strings.Contains(serverLower, k) {
			return v
		}
	}
	return ""
}

func extractCMSFromOutput(output string) string {
	lower := strings.ToLower(output)
	// Common patterns in CMSeeK output
	if strings.Contains(lower, "wordpress") {
		return "WordPress"
	}
	if strings.Contains(lower, "joomla") {
		return "Joomla"
	}
	if strings.Contains(lower, "drupal") {
		return "Drupal"
	}
	if strings.Contains(lower, "magento") {
		return "Magento"
	}
	return ""
}

func extractVulnerabilities(output string) []string {
	var vulns []string
	lines := strings.Split(output, "\n")
	
	for _, line := range lines {
		lineLower := strings.ToLower(line)
		// Look for common vulnerability indicators
		if strings.Contains(lineLower, "vulnerability") ||
		   strings.Contains(lineLower, "vulnerable") ||
		   strings.Contains(lineLower, "cve-") ||
		   strings.Contains(lineLower, "exploit") ||
		   strings.Contains(lineLower, "critical") ||
		   strings.Contains(lineLower, "high risk") {
			vulns = append(vulns, strings.TrimSpace(line))
		}
	}
	
	// Limit to first 20 vulnerabilities to avoid huge outputs
	if len(vulns) > 20 {
		vulns = vulns[:20]
	}
	return vulns
}

// tryExecScannersForCMS tries all candidate commands for a CMS until one succeeds.
// It returns the captured output, scanner name, and an error if no scanner succeeded.
func tryExecScannersForCMS(ctx context.Context, cms, target string) (string, string, error) {
	candidates, ok := scannerCandidates[cms]
	if !ok || len(candidates) == 0 {
		vlog("no scanner candidates configured for CMS=%s", cms)
		return "", "", nil
	}

	var lastErr error
	for _, cand := range candidates {
		// prepare args with target substitution
		args := make([]string, len(cand))
		for i, a := range cand {
			args[i] = strings.ReplaceAll(a, "{target}", target)
		}
		cmdName := args[0]
		cmdArgs := args[1:]
		
		// Check if command exists
		if !commandExists(cmdName) {
			vlog("scanner %s not found, skipping", cmdName)
			continue
		}
		
		vlog("attempting scanner: %s %v", cmdName, cmdArgs)
		out, err := runCommandWithTimeout(ctx, cmdName, cmdArgs, time.Duration(scannerTimeoutSec)*time.Second)
		if err != nil {
			vlog("scanner %s failed: %v", cmdName, err)
			lastErr = err
			// try next candidate
			continue
		}
		// success
		return out, cmdName, nil
	}
	return "", "", fmt.Errorf("no scanner succeeded for CMS=%s (last error: %v)", cms, lastErr)
}

func commandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

func runCommandWithTimeout(ctx context.Context, name string, args []string, timeout time.Duration) (string, error) {
	ctx2, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx2, name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("start error: %w", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		out := buf.String()
		if err != nil {
			// include output even on error
			if out == "" {
				return firstN(out, 2000), fmt.Errorf("command finished with error: %w", err)
			}
			return firstN(out, 2000), fmt.Errorf("command finished with error: %w; output: %s", err, firstN(out, 2000))
		}
		return firstN(out, 2000), nil
	case <-ctx2.Done():
		// timed out
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return "", fmt.Errorf("command timed out after %s", timeout)
	}
}

func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
