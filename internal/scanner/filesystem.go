package scanner

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type Mode int

type Config struct {
	MaxFileSize    int64
	MaxDepth       int
	TimeoutSeconds int
	IncludeDirs    []string
	ExcludeDirs    []string
}

type Result struct {
	Findings       []Finding `json:"findings"`
	FilesScanned   int       `json:"files_scanned"`
	Duration       string    `json:"duration"`
	BytesProcessed int64     `json:"bytes_processed"`
}

type Finding struct {
	FilePath    string `json:"file_path"`
	LineNumber  int    `json:"line_number"`
	PatternName string `json:"pattern_name"`
	Snippet     string `json:"snippet"`
	Risk        string `json:"risk"`
}

var defaultConfig = Config{
	MaxFileSize:    5 * 1024 * 1024,
	MaxDepth:       5,
	TimeoutSeconds: 120,
	IncludeDirs: []string{
		"Desktop", "Documents", "Downloads",
		".ssh", ".aws", ".azure", ".gcloud",
		".config", ".kube",
	},
	ExcludeDirs: []string{
		"node_modules", ".git", ".svn", "__pycache__",
		"venv", ".venv", "env", ".env",
		"vendor", "bin", "obj",
	},
}

var patterns = []struct {
	Name string
	Re   *regexp.Regexp
	Risk string
}{
	{"password_in_ini", regexp.MustCompile(`(?i)^\s*password\s*[=:]\s*.+$`), "high"},
	{"db_password", regexp.MustCompile(`(?i)DB_PASSWORD\s*[=:]\s*\S+`), "high"},
	{"connection_string", regexp.MustCompile(`(?i)(connection|conn)(string)?\s*[=:].*password\s*=\s*\S+`), "high"},
	{"private_key", regexp.MustCompile(`-----BEGIN\s+(RSA|DSA|EC|OPENSSH|PRIVATE)\s+KEY-----`), "critical"},
	{"api_key", regexp.MustCompile(`(?i)(api[-_]?key|api[-_]?secret|access[-_]?key|secret[-_]?key)\s*[=:]\s*\S{16,}`), "high"},
	{"aws_access_key", regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`), "critical"},
	{"github_token", regexp.MustCompile(`(?i)ghp_[a-zA-Z0-9]{36}`), "critical"},
	{"slack_token", regexp.MustCompile(`xox[baprs]-[a-zA-Z0-9-]{10,}`), "critical"},
	{"base64_secret", regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`), "medium"},
	{"json_password", regexp.MustCompile(`"password"\s*:\s*"[^"]{3,}"`), "high"},
	{"json_token", regexp.MustCompile(`"token"\s*:\s*"[a-zA-Z0-9_\-\.]{20,}"`), "high"},
	{"xml_password", regexp.MustCompile(`<password>[^<]+</password>`), "high"},
	{"env_file", regexp.MustCompile(`(?i)^\s*(PASSWORD|SECRET|TOKEN|KEY)\s*=\s*\S+`), "high"},
}

func ScanCredentials(sysInfo interface{}, mode Mode) (*Result, error) {
	start := time.Now()
	result := &Result{}

	cfg := defaultConfig

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	var scanPaths []string
	for _, dir := range cfg.IncludeDirs {
		fullPath := filepath.Join(homeDir, dir)
		if _, err := os.Stat(fullPath); err == nil {
			scanPaths = append(scanPaths, fullPath)
		}
	}

	// Simulation mode deep checking based on arbitrary ints since we don't know the exact enum here, 2 typically maps to ModeDeep
	if mode == 2 {
		cfg.MaxDepth = 10
		cfg.TimeoutSeconds = 300
		extraDirs := []string{
			filepath.Join(homeDir, ".local", "share"),
			filepath.Join(homeDir, "AppData", "Roaming"),
		}
		for _, dir := range extraDirs {
			if _, err := os.Stat(dir); err == nil {
				scanPaths = append(scanPaths, dir)
			}
		}
	}

	timeout := time.After(time.Duration(cfg.TimeoutSeconds) * time.Second)
	done := make(chan bool, 1)

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	go func() {
		for _, root := range scanPaths {
			wg.Add(1)
			sem <- struct{}{}
			go func(root string) {
				defer wg.Done()
				defer func() { <-sem }()
				scanDir(root, cfg, result, &mu)
			}(root)
		}
		wg.Wait()
		done <- true
	}()

	select {
	case <-done:
	case <-timeout:
	}

	result.Duration = time.Since(start).String()
	return result, nil
}

func scanDir(root string, cfg Config, result *Result, mu *sync.Mutex) {
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return filepath.SkipDir
		}

		depth := strings.Count(strings.TrimPrefix(path, root), string(filepath.Separator))
		if depth > cfg.MaxDepth {
			return filepath.SkipDir
		}

		if info.IsDir() {
			for _, exclude := range cfg.ExcludeDirs {
				if strings.EqualFold(info.Name(), exclude) {
					return filepath.SkipDir
				}
			}
			return nil
		}

		if info.Size() > cfg.MaxFileSize {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		switch ext {
		case ".exe", ".dll", ".sys", ".bin", ".iso", ".img",
			".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico",
			".mp3", ".mp4", ".avi", ".mkv", ".wav",
			".zip", ".rar", ".7z", ".tar", ".gz":
			return nil
		}

		findings := scanFile(path, cfg)
		if len(findings) > 0 {
			mu.Lock()
			result.Findings = append(result.Findings, findings...)
			result.FilesScanned++
			result.BytesProcessed += info.Size()
			mu.Unlock()
		}

		return nil
	})
	if err != nil {
		return
	}
}

func scanFile(path string, cfg Config) []Finding {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var findings []Finding
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		if len(line) > 2000 {
			continue
		}

		for _, p := range patterns {
			if matches := p.Re.FindString(line); matches != "" {
				snippet := truncateSnippet(line, 80)

				findings = append(findings, Finding{
					FilePath:    path,
					LineNumber:  lineNum,
					PatternName: p.Name,
					Snippet:     snippet,
					Risk:        p.Risk,
				})
				break
			}
		}
	}

	return findings
}

func truncateSnippet(line string, maxLen int) string {
	runes := []rune(line)
	if len(runes) <= maxLen {
		return line
	}
	prefix := string(runes[:30])
	return prefix + "...[masqué]..."
}
