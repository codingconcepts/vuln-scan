package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
)

func main() {
	image := flag.String("image", "", "name and version of the image")
	dir := flag.String("dir", "./vuln", "directory in which to process vulnerabilities")
	flag.Parse()

	if *image == "" {
		flag.Usage()
		os.Exit(2)
	}

	log.Printf("Scanning %s", *image)
	res, err := run(*image, *dir)
	log.Printf("Scanning finished for %s", *image)
	if err != nil {
		log.Fatalf("error running: %v", err)
	}

	for _, r := range res {
		if len(r.Vulnerabilities) == 0 {
			continue
		}

		for _, v := range r.Vulnerabilities {
			log.Println(v)
		}
	}
}

func run(image, dir string) (result, error) {
	cmd := exec.Command("trivy", "--cache-dir", dir, "--clear-cache", "--format", "json", image)

	buf := &bytes.Buffer{}
	mw := io.MultiWriter(buf, os.Stdout)
	cmd.Stdout = mw

	if err := cmd.Run(); err != nil {
		return result{}, fmt.Errorf("executing command: %w", err)
	}

	b := bytes.TrimSpace(buf.Bytes())
	log.Println("START")
	log.Println(string(b))
	log.Println("END")

	var res result
	if err := json.Unmarshal(b, &res); err != nil {
		return result{}, fmt.Errorf("parsing output: %w", err)
	}

	return res, nil
}

type result []target

type target struct {
	Name            string          `json:"Target"`
	Vulnerabilities []vulnerability `json:"Vulnerabilities"`
}

type vulnerability struct {
	ID               string   `json:"VulnerabilityID"`
	PackageName      string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion"`
	Title            string   `json:"Title"`
	Description      string   `json:"Description"`
	Severity         severity `json:"Severity"`
	References       []string `json:"References"`
}

type severity struct {
	Name  string
	Value int
}

const (
	SeverityUnknown = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s *severity) UnmarshalJSON(data []byte) error {
	s.Name = string(bytes.ToUpper(bytes.Trim(data, `"`)))
	switch s.Name {
	case "CRITICAL":
		s.Value = SeverityCritical
	case "HIGH":
		s.Value = SeverityHigh
	case "MEDIUM":
		s.Value = SeverityMedium
	case "LOW":
		s.Value = SeverityLow
	default:
		s.Value = SeverityUnknown
	}

	return nil
}
