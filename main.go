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
	Target        string `json:"target"`
	DetectedCMS   string `json:"detected_cms,omitempty"`
	ScannerOutput string `json:"scanner_output,omitempty"`
	Notes         string `json:"notes,omitempty"`
}

// cmsIndicators maps simple substrings to CMS names
var cmsIndicators = map[string]string{
	"wp-content":       "WordPress",
	"wordpress":        "WordPress",
	"<meta name=\"generator\" content=\"WordPress": "WordPress",
	"/administrator/index.php": "Joomla",
	"joomla":           "Joomla",
	"drupal":           "Drupal",
	"/sites/default/":  "Drupal",
	"mage":             "Magento",
	"/skin/frontend":   "Magento",
}

// scannerCandidates maps CMS to one or more candidate commands (each command is a string slice)
var scannerCandidates = map[string][][]string{
	"WordPress": {
		{"wpscan", "--url", "{target}", "--no-update", "--enumerate", "vp,vt"},
	},
	"Joomla": {
		{"joomscan", "-u", "{target}"},
	},
	"Drupal": {
		{"droopescan", "scan", "drupal", "-u", "{target}"},
	},
	"Magento": {
		{"magento-scanner", "--url", "{target}"},
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
	body, err := fetchTarget(ctx, client, target)
	if err != nil {
		r.Notes = fmt.Sprintf("fetch error: %v", err)
		vlog("%s - fetch error: %v", target, err)
		return r
	}

	// detect CMS
	detected := detectCMS(body)
	if detected == "" {
		vlog("%s - CMS not detected by simple heuristics", target)
	} else {
		r.DetectedCMS = detected
		vlog("%s - detected CMS: %s", target, detected)
	}

	if execScanners && detected != "" {
		outStr, err := tryExecScannersForCMS(ctx, detected, target)
		if err != nil {
			// record both some output and the error
			r.ScannerOutput = outStr
			r.Notes = err.Error()
			vlog("%s - scanner error: %v", target, err)
		} else {
			r.ScannerOutput = outStr
		}
	}

	return r
}

func fetchTarget(ctx context.Context, client *http.Client, target string) (string, error) {
	// ensure scheme
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "cmsrecon/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(io.LimitReader(resp.Body, 200*1024)) // 200KB max
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func detectCMS(body string) string {
	lower := strings.ToLower(body)
	for k, v := range cmsIndicators {
		if strings.Contains(lower, strings.ToLower(k)) {
			return v
		}
	}
	return ""
}

// tryExecScannersForCMS tries all candidate commands for a CMS until one succeeds.
// It returns the first captured output (truncated) and an error if no scanner succeeded or if a scanner failed with an error.
func tryExecScannersForCMS(ctx context.Context, cms, target string) (string, error) {
	candidates, ok := scannerCandidates[cms]
	if !ok || len(candidates) == 0 {
		vlog("no scanner candidates configured for CMS=%s", cms)
		return "", nil
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
		vlog("attempting scanner: %s %v", cmdName, cmdArgs)
		out, err := runCommandWithTimeout(ctx, cmdName, cmdArgs, time.Duration(scannerTimeoutSec)*time.Second)
		if err != nil {
			vlog("scanner %s failed: %v", cmdName, err)
			lastErr = err
			// try next candidate
			continue
		}
		// success
		return out, nil
	}
	return "", fmt.Errorf("no scanner succeeded for CMS=%s (last error: %v)", cms, lastErr)
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
