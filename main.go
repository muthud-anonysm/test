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
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

// Simple CMS recon + external scanner launcher
// - Reads a newline-separated list of target URLs from -input
// - Detects CMS by fetching the target and looking for common indicators
// - Optionally runs external scanners for detected CMS using -exec-scanners
// - Writes results as JSONL to -out

const maxCommandOutput = 4000

var (
	inputFile           string
	outFile             string
	execScanners        bool
	useCmseek           bool
	cmseekAlways        bool
	enableSensitiveFuzz bool
	scannerTimeoutSec   int
	cmseekTimeoutSec    int
	sensitiveTimeoutSec int
	verbose             bool
	workerCount         int
	clientTimeoutSec    int
)

func init() {
	flag.StringVar(&inputFile, "input", "targets.txt", "newline-separated list of target URLs")
	flag.StringVar(&outFile, "out", "cmsrecon_results.jsonl", "output JSONL file")
	flag.BoolVar(&execScanners, "exec-scanners", false, "execute external scanners when CMS is detected")
	flag.BoolVar(&useCmseek, "use-cmseek", false, "run cmseek for detection (requires cmseek in PATH)")
	flag.BoolVar(&cmseekAlways, "cmseek-always", false, "run cmseek even when CMS detection already succeeded")
	flag.IntVar(&scannerTimeoutSec, "scanner-timeout", 120, "timeout seconds for external scanners")
	flag.IntVar(&cmseekTimeoutSec, "cmseek-timeout", 180, "timeout seconds for cmseek detection")
	flag.BoolVar(&enableSensitiveFuzz, "sensitive-fuzz", false, "attempt sensitive path fuzzing for detected servers (nginx/apache)")
	flag.IntVar(&sensitiveTimeoutSec, "sensitive-timeout", 8, "timeout seconds per sensitive path request")
	flag.BoolVar(&verbose, "v", false, "verbose logs")
	flag.IntVar(&workerCount, "workers", 8, "concurrent workers")
	flag.IntVar(&clientTimeoutSec, "http-timeout", 15, "HTTP client timeout seconds")
}

func vlog(format string, a ...interface{}) {
	if verbose {
		fmt.Printf(format+"\n", a...)
	}
}

type Result struct {
	Target            string          `json:"target"`
	FinalURL          string          `json:"final_url,omitempty"`
	StatusCode        int             `json:"status_code,omitempty"`
	Server            string          `json:"server,omitempty"`
	PoweredBy         string          `json:"powered_by,omitempty"`
	DetectedCMS       []string        `json:"detected_cms,omitempty"`
	DetectionNotes    []string        `json:"detection_notes,omitempty"`
	SensitiveFindings []string        `json:"sensitive_findings,omitempty"`
	ScannerResults    []ScannerResult `json:"scanner_results,omitempty"`
	ScannerOutput     string          `json:"scanner_output,omitempty"`
	Notes             []string        `json:"notes,omitempty"`
}

type ScannerResult struct {
	Name    string   `json:"name"`
	Command []string `json:"command,omitempty"`
	Output  string   `json:"output,omitempty"`
	Error   string   `json:"error,omitempty"`
}

type CommandSpec struct {
	Label      string
	Cmd        []string
	TimeoutSec int
}

type FetchInfo struct {
	Body       string
	Headers    http.Header
	FinalURL   string
	StatusCode int
	Server     string
	PoweredBy  string
}

// cmsIndicators maps simple substrings to CMS names
var cmsIndicators = map[string]string{
	"wp-content":  "WordPress",
	"wp-includes": "WordPress",
	"wp-json":     "WordPress",
	"wordpress":   "WordPress",
	"<meta name=\"generator\" content=\"wordpress": "WordPress",
	"/administrator/index.php":                     "Joomla",
	"joomla":                                       "Joomla",
	"/media/system/js/":                            "Joomla",
	"drupal":                                       "Drupal",
	"/sites/default/":                              "Drupal",
	"drupal-settings-json":                         "Drupal",
	"mage":                                         "Magento",
	"/skin/frontend":                               "Magento",
	"magento":                                      "Magento",
}

// scannerCandidates maps CMS to one or more candidate commands (each command is a string slice)
var scannerCandidates = map[string][]CommandSpec{
	"WordPress": {
		{Label: "wpscan", Cmd: []string{"wpscan", "--url", "{target}", "--no-update", "--enumerate", "vp,vt"}, TimeoutSec: 300},
	},
	"Joomla": {
		{Label: "joomscan", Cmd: []string{"joomscan", "-u", "{target}"}, TimeoutSec: 180},
	},
	"Drupal": {
		{Label: "droopescan", Cmd: []string{"droopescan", "scan", "drupal", "-u", "{target}"}, TimeoutSec: 240},
	},
	"Magento": {
		{Label: "magento-scanner", Cmd: []string{"magento-scanner", "--url", "{target}"}, TimeoutSec: 240},
	},
}

var cmsNamePatterns = map[string]string{
	"wordpress":   "WordPress",
	"joomla":      "Joomla",
	"drupal":      "Drupal",
	"magento":     "Magento",
	"droopal":     "Drupal", // common typo
	"prestashop":  "PrestaShop",
	"opencart":    "OpenCart",
	"typo3":       "TYPO3",
	"ghost":       "Ghost",
	"craft cms":   "Craft CMS",
	"umbraco":     "Umbraco",
	"dnn":         "DotNetNuke",
	"sitecore":    "Sitecore",
	"sharepoint":  "SharePoint",
	"blogger":     "Blogger",
	"shopify":     "Shopify",
	"bigcommerce": "BigCommerce",
}

var cmseekCMSRegex = regexp.MustCompile(`(?mi)(?:Detected\s+CMS|CMS\s+Name|CMS)\s*[:=]\s*([A-Za-z0-9!\-_/\. ]{2,})`)

var sensitivePathLibrary = map[string][]string{
	"common": {
		"/.git/config",
		"/.env",
		"/.htaccess",
		"/config.php",
		"/config.php.bak",
		"/backup.zip",
		"/adminer.php",
		"/phpinfo.php",
		"/wp-config.php.bak",
	},
	"nginx": {
		"/nginx_status",
		"/status",
		"/stub_status",
	},
	"apache": {
		"/server-status",
		"/server-info",
		"/balancer-manager",
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
	res := Result{Target: target}

	info, err := fetchTarget(ctx, client, target)
	if err != nil {
		msg := fmt.Sprintf("fetch error: %v", err)
		res.Notes = append(res.Notes, msg)
		vlog("%s - %s", target, msg)
		return res
	}

	res.FinalURL = info.FinalURL
	res.StatusCode = info.StatusCode
	res.Server = info.Server
	res.PoweredBy = info.PoweredBy

	detectedCMS, detectionNotes := detectCMS(info)
	if len(detectionNotes) > 0 {
		res.DetectionNotes = append(res.DetectionNotes, detectionNotes...)
	}
	if len(detectedCMS) > 0 {
		res.DetectedCMS = mergeCMS(nil, detectedCMS)
		vlog("%s - detected CMS: %v", target, res.DetectedCMS)
	} else {
		vlog("%s - CMS not detected by built-in heuristics", target)
	}

	scanTarget := info.FinalURL
	if scanTarget == "" {
		scanTarget = ensureScheme(target)
	}

	if useCmseek && (len(res.DetectedCMS) == 0 || cmseekAlways) {
		cmseekResult := runCmseekDetection(ctx, scanTarget)
		res.ScannerResults = append(res.ScannerResults, cmseekResult)
		if cmseekResult.Error != "" {
			res.Notes = append(res.Notes, fmt.Sprintf("cmseek error: %s", cmseekResult.Error))
			vlog("%s - cmseek error: %s", target, cmseekResult.Error)
		}
		if cmseekResult.Output != "" {
			candidates := extractCMSFromText(cmseekResult.Output)
			if len(candidates) > 0 {
				prevLen := len(res.DetectedCMS)
				res.DetectedCMS = mergeCMS(res.DetectedCMS, candidates)
				if len(res.DetectedCMS) > prevLen {
					res.DetectionNotes = append(res.DetectionNotes, fmt.Sprintf("cmseek output suggested %v", candidates))
				}
			}
		}
	}

	if execScanners && len(res.DetectedCMS) > 0 {
		for _, cms := range res.DetectedCMS {
			results := runScannersForCMS(ctx, cms, scanTarget)
			if len(results) == 0 {
				vlog("%s - no scanners configured or executed for CMS=%s", target, cms)
				continue
			}
			res.ScannerResults = append(res.ScannerResults, results...)
		}
	}

	if enableSensitiveFuzz && res.Server != "" {
		findings := runSensitiveFuzz(ctx, client, scanTarget, res.Server)
		if len(findings) > 0 {
			res.SensitiveFindings = findings
			vlog("%s - sensitive paths: %v", target, findings)
		}
	}

	if len(res.ScannerResults) > 0 {
		res.ScannerOutput = renderScannerOutputs(res.ScannerResults)
	}

	return res
}

func fetchTarget(ctx context.Context, client *http.Client, target string) (*FetchInfo, error) {
	reqURL := ensureScheme(target)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "cmsrecon/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(io.LimitReader(resp.Body, 200*1024)) // 200KB max
	if err != nil {
		return nil, err
	}

	info := &FetchInfo{
		Body:       string(bodyBytes),
		Headers:    resp.Header.Clone(),
		FinalURL:   resp.Request.URL.String(),
		StatusCode: resp.StatusCode,
		Server:     resp.Header.Get("Server"),
	}

	poweredByValues := make([]string, 0, 2)
	if v := resp.Header.Get("X-Powered-By"); v != "" {
		poweredByValues = append(poweredByValues, v)
	}
	if v := resp.Header.Get("X-Generator"); v != "" {
		poweredByValues = append(poweredByValues, fmt.Sprintf("generator: %s", v))
	}
	if len(poweredByValues) > 0 {
		info.PoweredBy = strings.Join(poweredByValues, " | ")
	}

	return info, nil
}

func detectCMS(info *FetchInfo) ([]string, []string) {
	if info == nil {
		return nil, nil
	}

	found := make(map[string]struct{})
	var notes []string

	lowerBody := strings.ToLower(info.Body)
	for indicator, cms := range cmsIndicators {
		if strings.Contains(lowerBody, strings.ToLower(indicator)) {
			name := normalizeCMSName(cms)
			if _, exists := found[name]; !exists {
				found[name] = struct{}{}
				notes = append(notes, fmt.Sprintf("body indicator %q -> %s", indicator, name))
			}
		}
	}

	for _, generator := range extractMetaGenerators(info.Body) {
		notes = append(notes, fmt.Sprintf("meta generator: %s", generator))
		for _, name := range guessCMSNamesFromString(generator) {
			name = normalizeCMSName(name)
			if _, exists := found[name]; !exists {
				found[name] = struct{}{}
			}
		}
	}

	if info.Headers != nil {
		for _, headerName := range []string{"X-Powered-By", "X-Generator"} {
			if val := info.Headers.Get(headerName); val != "" {
				notes = append(notes, fmt.Sprintf("%s: %s", headerName, val))
				for _, name := range guessCMSNamesFromString(val) {
					name = normalizeCMSName(name)
					if _, exists := found[name]; !exists {
						found[name] = struct{}{}
					}
				}
			}
		}
	}

	return setToSortedSlice(found), notes
}

func runScannersForCMS(ctx context.Context, cms, target string) []ScannerResult {
	normalized := normalizeCMSName(cms)
	specs, ok := scannerCandidates[normalized]
	if !ok || len(specs) == 0 {
		return nil
	}

	results := make([]ScannerResult, 0, len(specs))
	for _, spec := range specs {
		results = append(results, executeCommandSpec(ctx, spec, target))
	}
	return results
}

func runCmseekDetection(ctx context.Context, target string) ScannerResult {
	normalizedTarget := ensureScheme(target)
	spec := CommandSpec{
		Label:      "cmseek-detect",
		Cmd:        []string{"cmseek", "-u", "{target}", "--batch"},
		TimeoutSec: cmseekTimeoutSec,
	}
	return executeCommandSpec(ctx, spec, normalizedTarget)
}

func executeCommandSpec(ctx context.Context, spec CommandSpec, target string) ScannerResult {
	normalizedTarget := ensureScheme(target)
	resolvedCmd := make([]string, len(spec.Cmd))
	for i, part := range spec.Cmd {
		resolvedCmd[i] = strings.ReplaceAll(part, "{target}", normalizedTarget)
	}

	name := spec.Label
	if name == "" && len(resolvedCmd) > 0 {
		name = resolvedCmd[0]
	}

	result := ScannerResult{
		Name:    name,
		Command: resolvedCmd,
	}

	if len(resolvedCmd) == 0 {
		result.Error = "empty command"
		return result
	}

	timeout := spec.TimeoutSec
	if timeout <= 0 {
		timeout = scannerTimeoutSec
	}

	cmdName := resolvedCmd[0]
	cmdArgs := resolvedCmd[1:]
	vlog("attempting scanner: %s %v", cmdName, cmdArgs)
	output, err := runCommandWithTimeout(ctx, cmdName, cmdArgs, time.Duration(timeout)*time.Second)
	result.Output = output
	if err != nil {
		result.Error = err.Error()
		vlog("scanner %s failed: %v", name, err)
	}

	return result
}

func renderScannerOutputs(results []ScannerResult) string {
	if len(results) == 0 {
		return ""
	}

	var b strings.Builder
	for _, r := range results {
		b.WriteString("## ")
		b.WriteString(r.Name)
		b.WriteByte('\n')
		if len(r.Command) > 0 {
			b.WriteString("$ ")
			b.WriteString(strings.Join(r.Command, " "))
			b.WriteByte('\n')
		}
		if r.Output != "" {
			b.WriteString(r.Output)
			if !strings.HasSuffix(r.Output, "\n") {
				b.WriteByte('\n')
			}
		}
		if r.Error != "" {
			b.WriteString("error: ")
			b.WriteString(r.Error)
			b.WriteByte('\n')
		}
		b.WriteByte('\n')
	}
	return strings.TrimSpace(b.String())
}

func mergeCMS(existing []string, newCMS []string) []string {
	set := make(map[string]struct{})
	for _, name := range existing {
		if n := normalizeCMSName(name); n != "" {
			set[n] = struct{}{}
		}
	}
	for _, name := range newCMS {
		if n := normalizeCMSName(name); n != "" {
			set[n] = struct{}{}
		}
	}
	return setToSortedSlice(set)
}

func setToSortedSlice(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func normalizeCMSName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	lower := strings.ToLower(name)
	switch lower {
	case "wp", "wordpress":
		return "WordPress"
	case "joomla", "joomla!":
		return "Joomla"
	case "drupal", "droopal":
		return "Drupal"
	case "magento", "magento cms", "magento open source":
		return "Magento"
	case "prestashop":
		return "PrestaShop"
	case "opencart":
		return "OpenCart"
	case "typo3":
		return "TYPO3"
	case "ghost":
		return "Ghost"
	case "craft cms", "craftcms":
		return "Craft CMS"
	case "umbraco":
		return "Umbraco"
	case "dotnetnuke", "dnn":
		return "DotNetNuke"
	case "sitecore":
		return "Sitecore"
	case "sharepoint":
		return "SharePoint"
	case "blogger":
		return "Blogger"
	case "shopify":
		return "Shopify"
	case "bigcommerce":
		return "BigCommerce"
	default:
		return strings.TrimSpace(name)
	}
}

func guessCMSNamesFromString(s string) []string {
	lower := strings.ToLower(s)
	set := make(map[string]struct{})
	for pattern, canonical := range cmsNamePatterns {
		if strings.Contains(lower, pattern) {
			set[normalizeCMSName(canonical)] = struct{}{}
		}
	}
	return setToSortedSlice(set)
}

func extractCMSFromText(text string) []string {
	set := make(map[string]struct{})

	for _, match := range cmseekCMSRegex.FindAllStringSubmatch(text, -1) {
		if len(match) < 2 {
			continue
		}
		if name := normalizeCMSName(match[1]); name != "" {
			set[name] = struct{}{}
		}
	}

	for _, name := range guessCMSNamesFromString(text) {
		if name != "" {
			set[name] = struct{}{}
		}
	}

	return setToSortedSlice(set)
}

func extractMetaGenerators(body string) []string {
	if body == "" {
		return nil
	}
	root, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil
	}

	var generators []string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && strings.EqualFold(n.Data, "meta") {
			var nameAttr, contentAttr string
			for _, attr := range n.Attr {
				switch strings.ToLower(attr.Key) {
				case "name":
					nameAttr = strings.ToLower(attr.Val)
				case "content":
					contentAttr = attr.Val
				}
			}
			if nameAttr == "generator" && strings.TrimSpace(contentAttr) != "" {
				generators = append(generators, contentAttr)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)

	return generators
}

func ensureScheme(target string) string {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return target
	}
	return "http://" + target
}

func runSensitiveFuzz(ctx context.Context, client *http.Client, baseURL, server string) []string {
	paths := collectSensitivePaths(server)
	if len(paths) == 0 {
		return nil
	}

	normalizedBase := ensureScheme(baseURL)
	parsed, err := url.Parse(normalizedBase)
	if err != nil {
		return nil
	}
	parsed.Path = "/"
	parsed.RawQuery = ""
	parsed.Fragment = ""

	var findings []string
	timeout := time.Duration(sensitiveTimeoutSec) * time.Second

	for _, p := range paths {
		candidate := parsed.ResolveReference(&url.URL{Path: p})
		ctxReq, cancel := context.WithTimeout(ctx, timeout)
		req, err := http.NewRequestWithContext(ctxReq, http.MethodGet, candidate.String(), nil)
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("User-Agent", "cmsrecon/1.0 sensitive-probe")

		resp, err := client.Do(req)
		if err != nil {
			cancel()
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 16*1024))
		resp.Body.Close()
		cancel()

		if isInterestingStatus(resp.StatusCode) {
			findings = append(findings, fmt.Sprintf("%s [%d]", candidate.String(), resp.StatusCode))
		}
	}

	return findings
}

func collectSensitivePaths(server string) []string {
	serverLower := strings.ToLower(server)
	set := make(map[string]struct{})
	for _, p := range sensitivePathLibrary["common"] {
		set[p] = struct{}{}
	}
	if strings.Contains(serverLower, "nginx") {
		for _, p := range sensitivePathLibrary["nginx"] {
			set[p] = struct{}{}
		}
	}
	if strings.Contains(serverLower, "apache") {
		for _, p := range sensitivePathLibrary["apache"] {
			set[p] = struct{}{}
		}
	}
	return setToSortedSlice(set)
}

func isInterestingStatus(statusCode int) bool {
	switch statusCode {
	case http.StatusOK, http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect, http.StatusForbidden:
		return true
	default:
		return false
	}
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
		out := firstN(buf.String(), maxCommandOutput)
		if err != nil {
			if out == "" {
				return out, fmt.Errorf("command finished with error: %w", err)
			}
			return out, fmt.Errorf("command finished with error: %w; output: %s", err, out)
		}
		return out, nil
	case <-ctx2.Done():
		// timed out
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return firstN(buf.String(), maxCommandOutput), fmt.Errorf("command timed out after %s", timeout)
	}
}

func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
