package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
)

type ScanSummary struct {
	Filename      string         `json:"filename"`
	Size          int64          `json:"size"`
	ModifiedAt    time.Time      `json:"modifiedAt"`
	ArtifactName  string         `json:"artifactName,omitempty"`
	ProjectName   string         `json:"projectName,omitempty"`
	ImageName     string         `json:"imageName,omitempty"`
	TotalVulns    int            `json:"totalVulns"`
	SeverityCount map[string]int `json:"severityCount"`
}

type ProjectSummary struct {
	ProjectName   string         `json:"projectName"`
	TotalScans    int            `json:"totalScans"`
	TotalVulns    int            `json:"totalVulns"`
	SeverityCount map[string]int `json:"severityCount"`
	Images        []ImageSummary `json:"images"`
	LastScan      time.Time      `json:"lastScan"`
}

type ImageSummary struct {
	ImageName     string         `json:"imageName"`
	Filename      string         `json:"filename"`
	TotalVulns    int            `json:"totalVulns"`
	SeverityCount map[string]int `json:"severityCount"`
	ModifiedAt    time.Time      `json:"modifiedAt"`
}

// Trivy JSON structures
type TrivyReport struct {
	SchemaVersion int      `json:"SchemaVersion"`
	ArtifactName  string   `json:"ArtifactName"`
	ArtifactType  string   `json:"ArtifactType"`
	Results       []Result `json:"Results"`
}

type Result struct {
	Target          string          `json:"Target"`
	Class           string          `json:"Class"`
	Type            string          `json:"Type"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
}

type Vulnerability struct {
	VulnerabilityID  string                 `json:"VulnerabilityID"`
	PkgName          string                 `json:"PkgName"`
	PkgPath          string                 `json:"PkgPath,omitempty"`
	InstalledVersion string                 `json:"InstalledVersion"`
	FixedVersion     string                 `json:"FixedVersion"`
	Severity         string                 `json:"Severity"`
	Title            string                 `json:"Title"`
	Description      string                 `json:"Description"`
	PrimaryURL       string                 `json:"PrimaryURL,omitempty"`
	PublishedDate    string                 `json:"PublishedDate,omitempty"`
	LastModifiedDate string                 `json:"LastModifiedDate,omitempty"`
	CVSS             map[string]interface{} `json:"CVSS,omitempty"`
}

func main() {
	r := chi.NewRouter()

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000"},
		AllowedMethods:   []string{"GET", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		ExposedHeaders:   []string{"*"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	// Root info
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Trivy Dashboard backend is running.\nTry /health or /api/scans\n"))
	})

	// Simple health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// List all scans with vulnerability summaries
	r.Get("/api/scans", func(w http.ResponseWriter, r *http.Request) {
		exportDir := os.Getenv("EXPORT_DIR")
		if exportDir == "" {
			exportDir = "/app/export"
		}

		entries, err := os.ReadDir(exportDir)
		if err != nil {
			http.Error(w, "failed to read export directory", http.StatusInternalServerError)
			return
		}

		var scans []ScanSummary

		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if filepath.Ext(e.Name()) != ".json" {
				continue
			}

			info, err := e.Info()
			if err != nil {
				continue
			}

			// Parse Trivy JSON to get vulnerability stats
			filePath := filepath.Join(exportDir, e.Name())
			summary := ScanSummary{
				Filename:      e.Name(),
				Size:          info.Size(),
				ModifiedAt:    info.ModTime(),
				SeverityCount: make(map[string]int),
			}

			// Extract project and image name from filename (e.g., "trivy-dashboard-backend.json" -> project: "trivy-dashboard", image: "backend")
			projectName, imageName := extractProjectAndImage(e.Name())
			summary.ProjectName = projectName
			summary.ImageName = imageName

			if report, err := parseTrivyJSON(filePath); err == nil {
				summary.ArtifactName = report.ArtifactName
				total := 0
				for _, result := range report.Results {
					for _, vuln := range result.Vulnerabilities {
						total++
						severity := strings.ToUpper(vuln.Severity)
						if severity == "" {
							severity = "UNKNOWN"
						}
						summary.SeverityCount[severity]++
					}
				}
				summary.TotalVulns = total
			}

			scans = append(scans, summary)
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(scans); err != nil {
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
			return
		}
	})

	// List all projects with summaries
	r.Get("/api/projects", func(w http.ResponseWriter, r *http.Request) {
		exportDir := os.Getenv("EXPORT_DIR")
		if exportDir == "" {
			exportDir = "/app/export"
		}

		entries, err := os.ReadDir(exportDir)
		if err != nil {
			http.Error(w, "failed to read export directory", http.StatusInternalServerError)
			return
		}

		projectsMap := make(map[string]*ProjectSummary)

		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if filepath.Ext(e.Name()) != ".json" {
				continue
			}

			info, err := e.Info()
			if err != nil {
				continue
			}

			projectName, imageName := extractProjectAndImage(e.Name())
			if projectName == "" {
				continue
			}

			if projectsMap[projectName] == nil {
				projectsMap[projectName] = &ProjectSummary{
					ProjectName:   projectName,
					SeverityCount: make(map[string]int),
					Images:        []ImageSummary{},
				}
			}

			project := projectsMap[projectName]
			project.TotalScans++

			// Parse Trivy JSON to get vulnerability stats
			filePath := filepath.Join(exportDir, e.Name())
			imageSummary := ImageSummary{
				ImageName:     imageName,
				Filename:      e.Name(),
				SeverityCount: make(map[string]int),
				ModifiedAt:    info.ModTime(),
			}

			if report, err := parseTrivyJSON(filePath); err == nil {
				total := 0
				for _, result := range report.Results {
					for _, vuln := range result.Vulnerabilities {
						total++
						severity := strings.ToUpper(vuln.Severity)
						if severity == "" {
							severity = "UNKNOWN"
						}
						imageSummary.SeverityCount[severity]++
						project.SeverityCount[severity]++
					}
				}
				imageSummary.TotalVulns = total
				project.TotalVulns += total
			}

			if imageSummary.ModifiedAt.After(project.LastScan) {
				project.LastScan = imageSummary.ModifiedAt
			}

			project.Images = append(project.Images, imageSummary)
		}

		// Convert map to slice
		var projects []ProjectSummary
		for _, project := range projectsMap {
			projects = append(projects, *project)
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(projects); err != nil {
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
			return
		}
	})

	// Get project details with all scans
	r.Get("/api/projects/{projectName}", func(w http.ResponseWriter, r *http.Request) {
		projectName := chi.URLParam(r, "projectName")
		if projectName == "" {
			http.Error(w, "project name is required", http.StatusBadRequest)
			return
		}

		exportDir := os.Getenv("EXPORT_DIR")
		if exportDir == "" {
			exportDir = "/app/export"
		}

		entries, err := os.ReadDir(exportDir)
		if err != nil {
			http.Error(w, "failed to read export directory", http.StatusInternalServerError)
			return
		}

		project := &ProjectSummary{
			ProjectName:   projectName,
			SeverityCount: make(map[string]int),
			Images:        []ImageSummary{},
		}

		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if filepath.Ext(e.Name()) != ".json" {
				continue
			}

			fileProjectName, imageName := extractProjectAndImage(e.Name())
			if fileProjectName != projectName {
				continue
			}

			info, err := e.Info()
			if err != nil {
				continue
			}

			project.TotalScans++

			filePath := filepath.Join(exportDir, e.Name())
			imageSummary := ImageSummary{
				ImageName:     imageName,
				Filename:      e.Name(),
				SeverityCount: make(map[string]int),
				ModifiedAt:    info.ModTime(),
			}

			if report, err := parseTrivyJSON(filePath); err == nil {
				total := 0
				for _, result := range report.Results {
					for _, vuln := range result.Vulnerabilities {
						total++
						severity := strings.ToUpper(vuln.Severity)
						if severity == "" {
							severity = "UNKNOWN"
						}
						imageSummary.SeverityCount[severity]++
						project.SeverityCount[severity]++
					}
				}
				imageSummary.TotalVulns = total
				project.TotalVulns += total
			}

			if imageSummary.ModifiedAt.After(project.LastScan) {
				project.LastScan = imageSummary.ModifiedAt
			}

			project.Images = append(project.Images, imageSummary)
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(project); err != nil {
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
			return
		}
	})

	// Get detailed vulnerability list for a specific scan
	r.Get("/api/scans/{filename}", func(w http.ResponseWriter, r *http.Request) {
		filename := chi.URLParam(r, "filename")
		if filename == "" {
			http.Error(w, "filename is required", http.StatusBadRequest)
			return
		}

		// Security: prevent path traversal
		if strings.Contains(filename, "..") || strings.Contains(filename, "/") {
			http.Error(w, "invalid filename", http.StatusBadRequest)
			return
		}

		exportDir := os.Getenv("EXPORT_DIR")
		if exportDir == "" {
			exportDir = "/app/export"
		}

		filePath := filepath.Join(exportDir, filename)
		report, err := parseTrivyJSON(filePath)
		if err != nil {
			http.Error(w, "failed to read or parse report: "+err.Error(), http.StatusNotFound)
			return
		}

		// Flatten all vulnerabilities from all results
		var allVulns []Vulnerability
		for _, result := range report.Results {
			for _, vuln := range result.Vulnerabilities {
				allVulns = append(allVulns, vuln)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"artifactName":    report.ArtifactName,
			"artifactType":    report.ArtifactType,
			"totalVulns":      len(allVulns),
			"vulnerabilities": allVulns,
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
			return
		}
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Backend listening on :%s\n", port)
	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatal(err)
	}
}

func parseTrivyJSON(filePath string) (*TrivyReport, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	var report TrivyReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, err
	}

	return &report, nil
}

// extractProjectAndImage extracts project and image name from filename
// Format: {project-name}-{image-name}.json
// Example: "trivy-dashboard-backend.json" -> project: "trivy-dashboard", image: "backend"
func extractProjectAndImage(filename string) (projectName, imageName string) {
	// Remove .json extension
	baseName := strings.TrimSuffix(filename, ".json")
	if baseName == "" {
		return "", ""
	}

	// Find last dash to split project and image
	lastDash := strings.LastIndex(baseName, "-")
	if lastDash == -1 || lastDash == 0 || lastDash == len(baseName)-1 {
		// No dash found, or dash at start/end - treat whole name as project
		return baseName, ""
	}

	projectName = baseName[:lastDash]
	imageName = baseName[lastDash+1:]

	return projectName, imageName
}
