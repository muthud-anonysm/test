package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"sort"
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
	inputFile         string
	outFile           string
	execScanners      bool
	scannerTimeoutSec int
	verbose           bool
	workerCount       int
	clientTimeoutSec  int
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
	Target          string          `json:"target"`
	DetectedCMS     string          `json:"detected_cms,omitempty"`
	DetectedCMSes   []string        `json:"detected_cmses,omitempty"`
	ServerHeader    string          `json:"server_header,omitempty"`
	DetectedServers []string        `json:"detected_servers,omitempty"`
	ScannerOutput   string          `json:"scanner_output,omitempty"`
	ScannerResults  []ScannerResult `json:"scanner_results,omitempty"`
	Notes           string          `json:"notes,omitempty"`
}

type ScannerResult struct {
	Name       string `json:"name"`
	Command    string `json:"command"`
	Success    bool   `json:"success"`
	Output     string `json:"output,omitempty"`
	Error      string `json:"error,omitempty"`
	DurationMs int64  `json:"duration_ms,omitempty"`
}

type ScannerDefinition struct {
	Name               string
	Command            []string
	TimeoutOverrideSec int
}

type FetchInfo struct {
	URL        string
	Body       string
	Headers    http.Header
	StatusCode int
}

var (
	cmsBodyIndicators = map[string]string{
		"wp-content":                   "WordPress",
		"wp-includes":                  "WordPress",
		"wp-json":                      "WordPress",
		"/xmlrpc.php":                  "WordPress",
		"/wp-admin/":                   "WordPress",
		"content=\"wordpress":          "WordPress",
		"/administrator/index.php":     "Joomla",
		"joomla":                       "Joomla",
		"com_content":                  "Joomla",
		"Joomla!":                      "Joomla",
		"drupal":                       "Drupal",
		"/sites/default/files":         "Drupal",
		"drupalSettings":               "Drupal",
		"mage":                         "Magento",
		"/skin/frontend":               "Magento",
		"Shopify.theme":                "Shopify",
		"prestashop":                   "PrestaShop",
		"ghost-sdk":                    "Ghost",
		"<meta name=\"generator\"":     "", // placeholder, meta handled separately
		"<meta property=\"generator\"": "",
	}

	cmsHeaderIndicators = []struct {
		Header    string
		Substring string
		CMS       string
	}{
		{"x-pingback", "xmlrpc.php", "WordPress"},
		{"x-powered-by", "wp", "WordPress"},
		{"x-generator", "wordpress", "WordPress"},
		{"x-generator", "drupal", "Drupal"},
		{"x-drupal-cache", "", "Drupal"},
		{"x-generator", "joomla", "Joomla"},
		{"set-cookie", "wordpress", "WordPress"},
		{"set-cookie", "drupal", "Drupal"},
	}

	metaGeneratorIndicators = map[string]string{
		"wordpress":  "WordPress",
		"joomla":     "Joomla",
		"drupal":     "Drupal",
		"magento":    "Magento",
		"shopify":    "Shopify",
		"prestashop": "PrestaShop",
		"ghost":      "Ghost",
	}

	metaGeneratorRe = regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]*content=["']([^"']+)["']`)

	cmsScannerDefinitions = map[string][]ScannerDefinition{
		"WordPress": {
			{Name: "wpscan", Command: []string{"wpscan", "--url", "{target}", "--no-update", "--enumerate", "vp,vt"}, TimeoutOverrideSec: 180},
		},
		"Joomla": {
			{Name: "joomscan", Command: []string{"joomscan", "-u", "{target}"}, TimeoutOverrideSec: 120},
		},
		"Drupal": {
			{Name: "droopescan", Command: []string{"droopescan", "scan", "drupal", "-u", "{target}"}, TimeoutOverrideSec: 180},
		},
		"Magento": {
			{Name: "magento-scan", Command: []string{"magento-scanner", "--url", "{target}"}, TimeoutOverrideSec: 180},
		},
	}

	serverScannerDefinitions = map[string][]ScannerDefinition{
		"nginx": {
			{Name: "nikto-nginx", Command: []string{"nikto", "-host", "{target}"}, TimeoutOverrideSec: 180},
		},
		"apache": {
			{Name: "nikto-apache", Command: []string{"nikto", "-host", "{target}"}, TimeoutOverrideSec: 180},
		},
	}

	genericScannerDefinitions = []ScannerDefinition{
		{Name: "cmseek", Command: []string{"cmseek", "--url", "{target}", "--follow-redirect", "--batch"}, TimeoutOverrideSec: 240},
	}
)

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

	info, err := fetchTarget(ctx, client, target)
	if err != nil {
		r.Notes = fmt.Sprintf("fetch error: %v", err)
		vlog("%s - fetch error: %v", target, err)
		return r
	}

	cmsList := detectCMSes(info)
	if len(cmsList) == 0 {
		vlog("%s - CMS not detected by heuristics", target)
	} else {
		r.DetectedCMS = cmsList[0]
		r.DetectedCMSes = cmsList
		vlog("%s - detected CMS candidates: %s", target, strings.Join(cmsList, ", "))
	}

	serverHeader := strings.Join(info.Headers.Values("Server"), ", ")
	if serverHeader != "" {
		r.ServerHeader = serverHeader
		vlog("%s - server header: %s", target, serverHeader)
	}

	serverTypes := detectServers(serverHeader)
	if len(serverTypes) > 0 {
		r.DetectedServers = serverTypes
		vlog("%s - detected server types: %s", target, strings.Join(serverTypes, ", "))
	}

	if execScanners {
		defs := buildScannerDefinitions(cmsList, serverTypes)
		if len(defs) == 0 {
			vlog("%s - no scanner definitions matched", target)
		} else {
			results := runScanners(ctx, info.URL, defs)
			r.ScannerResults = results
			r.ScannerOutput = summarizeScannerResults(results)
			if note := aggregateScannerErrors(results); note != "" {
				if r.Notes == "" {
					r.Notes = note
				} else {
					r.Notes = r.Notes + "; " + note
				}
			}
		}
	}

	return r
}

func fetchTarget(ctx context.Context, client *http.Client, target string) (*FetchInfo, error) {
	url := normalizeTargetURL(target)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "cmsrecon/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 200*1024)) // 200KB max
	if err != nil {
		return nil, err
	}

	return &FetchInfo{
		URL:        url,
		Body:       string(bodyBytes),
		Headers:    resp.Header.Clone(),
		StatusCode: resp.StatusCode,
	}, nil
}

func normalizeTargetURL(target string) string {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return target
	}
	return "http://" + target
}

func detectCMSes(info *FetchInfo) []string {
	if info == nil {
		return nil
	}

	found := make(map[string]struct{})
	bodyLower := strings.ToLower(info.Body)
	for pattern, cms := range cmsBodyIndicators {
		if cms == "" {
			continue
		}
		patternLower := strings.ToLower(pattern)
		if patternLower == "" {
			continue
		}
		if strings.Contains(bodyLower, patternLower) {
			found[cms] = struct{}{}
		}
	}

	metaMatches := metaGeneratorRe.FindAllStringSubmatch(info.Body, -1)
	for _, m := range metaMatches {
		if len(m) < 2 {
			continue
		}
		val := strings.ToLower(strings.TrimSpace(m[1]))
		for needle, cms := range metaGeneratorIndicators {
			if strings.Contains(val, needle) {
				found[cms] = struct{}{}
			}
		}
	}

	for _, indicator := range cmsHeaderIndicators {
		headerVal := info.Headers.Get(indicator.Header)
		if headerVal == "" {
			continue
		}
		headerLower := strings.ToLower(headerVal)
		if indicator.Substring == "" || strings.Contains(headerLower, strings.ToLower(indicator.Substring)) {
			found[indicator.CMS] = struct{}{}
		}
	}

	if len(found) == 0 {
		return nil
	}

	out := make([]string, 0, len(found))
	for cms := range found {
		out = append(out, cms)
	}
	sort.Strings(out)
	return out
}

func detectServers(serverHeader string) []string {
	if serverHeader == "" {
		return nil
	}
	lower := strings.ToLower(serverHeader)
	var servers []string
	seen := make(map[string]struct{})

	check := func(name string) {
		if _, ok := seen[name]; !ok {
			servers = append(servers, name)
			seen[name] = struct{}{}
		}
	}

	if strings.Contains(lower, "nginx") {
		check("nginx")
	}
	if strings.Contains(lower, "apache") {
		check("apache")
	}
	if strings.Contains(lower, "iis") {
		check("iis")
	}
	if strings.Contains(lower, "cloudflare") {
		check("cloudflare")
	}
	if strings.Contains(lower, "lighttpd") {
		check("lighttpd")
	}
	if strings.Contains(lower, "caddy") {
		check("caddy")
	}

	return servers
}

func buildScannerDefinitions(cmsList, serverTypes []string) []ScannerDefinition {
	seen := make(map[string]struct{})
	var defs []ScannerDefinition

	add := func(def ScannerDefinition) {
		key := def.Name + "|" + strings.Join(def.Command, " ")
		if _, ok := seen[key]; ok {
			return
		}
		defs = append(defs, def)
		seen[key] = struct{}{}
	}

	for _, cms := range cmsList {
		if cmsDefs, ok := cmsScannerDefinitions[cms]; ok {
			for _, def := range cmsDefs {
				add(def)
			}
		}
	}

	for _, def := range genericScannerDefinitions {
		add(def)
	}

	for _, server := range serverTypes {
		if serverDefs, ok := serverScannerDefinitions[server]; ok {
			for _, def := range serverDefs {
				add(def)
			}
		}
	}

	return defs
}

func runScanners(ctx context.Context, target string, defs []ScannerDefinition) []ScannerResult {
	results := make([]ScannerResult, 0, len(defs))
	for _, def := range defs {
		results = append(results, runScanner(ctx, target, def))
	}
	return results
}

func runScanner(ctx context.Context, target string, def ScannerDefinition) ScannerResult {
	res := ScannerResult{
		Name: def.Name,
	}
	args := substituteArgs(def.Command, target)
	if len(args) == 0 {
		res.Error = "empty command definition"
		return res
	}
	res.Command = strings.Join(args, " ")
	cmdName := args[0]
	if _, err := exec.LookPath(cmdName); err != nil {
		res.Error = fmt.Sprintf("command not found: %s", cmdName)
		return res
	}

	timeout := time.Duration(scannerTimeoutSec) * time.Second
	if def.TimeoutOverrideSec > 0 {
		timeout = time.Duration(def.TimeoutOverrideSec) * time.Second
	}

	start := time.Now()
	output, err := runCommandWithTimeout(ctx, cmdName, args[1:], timeout)
	res.DurationMs = int64(time.Since(start) / time.Millisecond)
	res.Output = output
	if err != nil {
		res.Success = false
		res.Error = err.Error()
	} else {
		res.Success = true
	}
	return res
}

func substituteArgs(args []string, target string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = strings.ReplaceAll(a, "{target}", target)
	}
	return out
}

func summarizeScannerResults(results []ScannerResult) string {
	if len(results) == 0 {
		return ""
	}

	var sb strings.Builder
	for _, res := range results {
		status := "ok"
		detail := ""
		if res.Success {
			if res.Output != "" {
				detail = strings.TrimSpace(firstN(res.Output, 400))
			}
		} else {
			status = "error"
			if res.Error != "" {
				detail = res.Error
			} else if res.Output != "" {
				detail = strings.TrimSpace(firstN(res.Output, 200))
			}
		}

		if detail != "" {
			fmt.Fprintf(&sb, "[%s: %s] %s\n", res.Name, status, detail)
		} else {
			fmt.Fprintf(&sb, "[%s: %s]\n", res.Name, status)
		}
	}

	return strings.TrimSpace(sb.String())
}

func aggregateScannerErrors(results []ScannerResult) string {
	var errs []string
	for _, res := range results {
		if !res.Success && res.Error != "" {
			errs = append(errs, fmt.Sprintf("%s: %s", res.Name, res.Error))
		}
	}
	if len(errs) == 0 {
		return ""
	}
	return strings.Join(errs, "; ")
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
