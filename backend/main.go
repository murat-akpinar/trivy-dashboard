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

// walkJSONFiles recursively walks through directory and finds all JSON files
func walkJSONFiles(rootDir string) ([]string, error) {
	var jsonFiles []string
	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(path) == ".json" {
			jsonFiles = append(jsonFiles, path)
		}
		return nil
	})
	return jsonFiles, err
}

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
	TotalVulns    int            `json:"totalVulns"`
	SeverityCount map[string]int `json:"severityCount"`
	LastScan      time.Time      `json:"lastScan"`
	Scans         []ScanSummary  `json:"scans"` // All scans for this image
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

		jsonFiles, err := walkJSONFiles(exportDir)
		if err != nil {
			http.Error(w, "failed to read export directory", http.StatusInternalServerError)
			return
		}

		var scans []ScanSummary

		for _, filePath := range jsonFiles {
			info, err := os.Stat(filePath)
			if err != nil {
				continue
			}

			// Get relative path from exportDir
			relPath, err := filepath.Rel(exportDir, filePath)
			if err != nil {
				continue
			}

			// Extract project and image name from path
			// Support both: export/project/image.json and export/project-image.json
			projectName, imageName := extractProjectAndImageFromPath(relPath, exportDir)

			summary := ScanSummary{
				Filename:      relPath, // Store relative path for API access
				Size:          info.Size(),
				ModifiedAt:    info.ModTime(),
				SeverityCount: make(map[string]int),
			}
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

		jsonFiles, err := walkJSONFiles(exportDir)
		if err != nil {
			http.Error(w, "failed to read export directory", http.StatusInternalServerError)
			return
		}

		projectsMap := make(map[string]*ProjectSummary)
		imagesMap := make(map[string]map[string]*ImageSummary) // project -> image -> ImageSummary

		for _, filePath := range jsonFiles {
			info, err := os.Stat(filePath)
			if err != nil {
				continue
			}

			// Get relative path from exportDir
			relPath, err := filepath.Rel(exportDir, filePath)
			if err != nil {
				continue
			}

			// Extract project and image name from path
			projectName, imageName := extractProjectAndImageFromPath(relPath, exportDir)
			if projectName == "" || imageName == "" {
				continue
			}

			if projectsMap[projectName] == nil {
				projectsMap[projectName] = &ProjectSummary{
					ProjectName:   projectName,
					SeverityCount: make(map[string]int),
					Images:        []ImageSummary{},
				}
				imagesMap[projectName] = make(map[string]*ImageSummary)
			}

			project := projectsMap[projectName]
			project.TotalScans++

			// Create scan summary
			scanSummary := ScanSummary{
				Filename:      relPath, // Store relative path
				Size:          info.Size(),
				ModifiedAt:    info.ModTime(),
				SeverityCount: make(map[string]int),
			}
			scanSummary.ProjectName = projectName
			scanSummary.ImageName = imageName

			if report, err := parseTrivyJSON(filePath); err == nil {
				scanSummary.ArtifactName = report.ArtifactName
				total := 0
				for _, result := range report.Results {
					for _, vuln := range result.Vulnerabilities {
						total++
						severity := strings.ToUpper(vuln.Severity)
						if severity == "" {
							severity = "UNKNOWN"
						}
						scanSummary.SeverityCount[severity]++
						project.SeverityCount[severity]++
					}
				}
				scanSummary.TotalVulns = total
				project.TotalVulns += total
			}

			// Initialize image summary if not exists
			if imagesMap[projectName][imageName] == nil {
				imagesMap[projectName][imageName] = &ImageSummary{
					ImageName:     imageName,
					SeverityCount: make(map[string]int),
					Scans:         []ScanSummary{},
				}
			}

			imageSummary := imagesMap[projectName][imageName]
			imageSummary.Scans = append(imageSummary.Scans, scanSummary)

			// Update image totals (use latest scan)
			if scanSummary.ModifiedAt.After(imageSummary.LastScan) {
				imageSummary.LastScan = scanSummary.ModifiedAt
				imageSummary.TotalVulns = scanSummary.TotalVulns
				imageSummary.SeverityCount = make(map[string]int)
				for k, v := range scanSummary.SeverityCount {
					imageSummary.SeverityCount[k] = v
				}
			}

			if scanSummary.ModifiedAt.After(project.LastScan) {
				project.LastScan = scanSummary.ModifiedAt
			}
		}

		// Convert images map to slice
		for projectName, project := range projectsMap {
			for _, imageSummary := range imagesMap[projectName] {
				// Sort scans by date (newest first)
				scans := imageSummary.Scans
				for i := 0; i < len(scans)-1; i++ {
					for j := i + 1; j < len(scans); j++ {
						if scans[i].ModifiedAt.Before(scans[j].ModifiedAt) {
							scans[i], scans[j] = scans[j], scans[i]
						}
					}
				}
				imageSummary.Scans = scans
				project.Images = append(project.Images, *imageSummary)
			}
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

	// Get project details with all scans grouped by image
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

		jsonFiles, err := walkJSONFiles(exportDir)
		if err != nil {
			http.Error(w, "failed to read export directory", http.StatusInternalServerError)
			return
		}

		project := &ProjectSummary{
			ProjectName:   projectName,
			SeverityCount: make(map[string]int),
			Images:        []ImageSummary{},
		}

		// Group scans by image name
		imagesMap := make(map[string]*ImageSummary)

		for _, filePath := range jsonFiles {
			// Get relative path from exportDir
			relPath, err := filepath.Rel(exportDir, filePath)
			if err != nil {
				continue
			}

			fileProjectName, imageName := extractProjectAndImageFromPath(relPath, exportDir)
			if fileProjectName != projectName {
				continue
			}

			if imageName == "" {
				continue
			}

			info, err := os.Stat(filePath)
			if err != nil {
				continue
			}

			project.TotalScans++

			// Create scan summary for this file
			scanSummary := ScanSummary{
				Filename:      relPath, // Store relative path
				Size:          info.Size(),
				ModifiedAt:    info.ModTime(),
				SeverityCount: make(map[string]int),
			}
			scanSummary.ProjectName = fileProjectName
			scanSummary.ImageName = imageName

			if report, err := parseTrivyJSON(filePath); err == nil {
				scanSummary.ArtifactName = report.ArtifactName
				total := 0
				for _, result := range report.Results {
					for _, vuln := range result.Vulnerabilities {
						total++
						severity := strings.ToUpper(vuln.Severity)
						if severity == "" {
							severity = "UNKNOWN"
						}
						scanSummary.SeverityCount[severity]++
						project.SeverityCount[severity]++
					}
				}
				scanSummary.TotalVulns = total
				project.TotalVulns += total
			}

			// Initialize image summary if not exists
			if imagesMap[imageName] == nil {
				imagesMap[imageName] = &ImageSummary{
					ImageName:     imageName,
					SeverityCount: make(map[string]int),
					Scans:         []ScanSummary{},
				}
			}

			imageSummary := imagesMap[imageName]
			
			// Add scan to image
			imageSummary.Scans = append(imageSummary.Scans, scanSummary)
			
			// Update image totals (use latest scan for totals)
			if scanSummary.ModifiedAt.After(imageSummary.LastScan) {
				imageSummary.LastScan = scanSummary.ModifiedAt
				imageSummary.TotalVulns = scanSummary.TotalVulns
				imageSummary.SeverityCount = make(map[string]int)
				for k, v := range scanSummary.SeverityCount {
					imageSummary.SeverityCount[k] = v
				}
			}

			if scanSummary.ModifiedAt.After(project.LastScan) {
				project.LastScan = scanSummary.ModifiedAt
			}
		}

		// Convert map to slice and sort scans by date (newest first)
		for _, imageSummary := range imagesMap {
			// Sort scans by ModifiedAt (newest first)
			scans := imageSummary.Scans
			for i := 0; i < len(scans)-1; i++ {
				for j := i + 1; j < len(scans); j++ {
					if scans[i].ModifiedAt.Before(scans[j].ModifiedAt) {
						scans[i], scans[j] = scans[j], scans[i]
					}
				}
			}
			imageSummary.Scans = scans
			project.Images = append(project.Images, *imageSummary)
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(project); err != nil {
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
			return
		}
	})

	// Get detailed vulnerability list for a specific scan
	// Use wildcard pattern to support subdirectories: /api/scans/*
	r.Get("/api/scans/*", func(w http.ResponseWriter, r *http.Request) {
		// Get the path after /api/scans/
		path := r.URL.Path
		prefix := "/api/scans/"
		if !strings.HasPrefix(path, prefix) {
			http.Error(w, "invalid path", http.StatusBadRequest)
			return
		}
		filename := strings.TrimPrefix(path, prefix)
		if filename == "" {
			http.Error(w, "filename is required", http.StatusBadRequest)
			return
		}

		// Security: prevent path traversal (but allow subdirectories)
		if strings.Contains(filename, "..") {
			http.Error(w, "invalid filename", http.StatusBadRequest)
			return
		}

		exportDir := os.Getenv("EXPORT_DIR")
		if exportDir == "" {
			exportDir = "/app/export"
		}

		// Join path and clean it to prevent directory traversal
		filePath := filepath.Join(exportDir, filename)
		filePath = filepath.Clean(filePath)
		
		// Ensure the file is within exportDir
		if !strings.HasPrefix(filePath, filepath.Clean(exportDir)+string(os.PathSeparator)) && filePath != filepath.Clean(exportDir) {
			http.Error(w, "invalid filename", http.StatusBadRequest)
			return
		}

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

// extractProjectAndImageFromPath extracts project and image name from file path
// Supports multiple formats:
// 1. {project-name}-{image-name}.json (flat structure)
// 2. {project-name}-{image-name}-{timestamp}.json (flat with timestamp)
// 3. {project-name}/{image-name}.json (directory structure)
// 4. {project-name}/{image-name}-{timestamp}.json (directory with timestamp)
// Example: "trivy-dashboard-backend.json" -> project: "trivy-dashboard", image: "backend"
// Example: "trivy-dashboard/backend.json" -> project: "trivy-dashboard", image: "backend"
func extractProjectAndImageFromPath(relPath, exportDir string) (projectName, imageName string) {
	// Normalize path separators
	relPath = filepath.ToSlash(relPath)
	
	// Remove .json extension
	basePath := strings.TrimSuffix(relPath, ".json")
	if basePath == "" {
		return "", ""
	}

	// Check if path contains directory separator (directory structure)
	dir, fileName := filepath.Split(basePath)
	if dir != "" {
		// Directory structure: {project-name}/{image-name} or {project-name}/{image-name}-{timestamp}
		projectName = strings.TrimSuffix(dir, "/")
		projectName = strings.TrimSuffix(projectName, string(os.PathSeparator))
		
		// Remove timestamp from filename if present
		imageName = removeTimestampFromFilename(fileName)
		return projectName, imageName
	}

	// Flat structure: {project-name}-{image-name} or {project-name}-{image-name}-{timestamp}
	baseName := fileName
	
	// Remove timestamp if present
	baseName = removeTimestampFromFilename(baseName)

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

// removeTimestampFromFilename removes timestamp pattern from filename
// Pattern: -YYYYMMDD-HHMMSS (16 characters)
func removeTimestampFromFilename(filename string) string {
	if len(filename) > 16 {
		// Check if last 16 characters match timestamp pattern
		lastPart := filename[len(filename)-16:]
		if len(lastPart) == 16 && lastPart[0] == '-' && 
			strings.Count(lastPart, "-") == 2 {
			// Check if it's a valid timestamp format (-YYYYMMDD-HHMMSS)
			parts := strings.Split(lastPart[1:], "-") // Skip first dash
			if len(parts) == 2 && len(parts[0]) == 8 && len(parts[1]) == 6 {
				// Validate that parts are numeric
				isValid := true
				for _, part := range parts {
					for _, r := range part {
						if r < '0' || r > '9' {
							isValid = false
							break
						}
					}
					if !isValid {
						break
					}
				}
				if isValid {
					// Remove timestamp from filename
					return filename[:len(filename)-16]
				}
			}
		}
	}
	return filename
}

// extractProjectAndImage is kept for backward compatibility
// It now calls extractProjectAndImageFromPath with empty exportDir
func extractProjectAndImage(filename string) (projectName, imageName string) {
	return extractProjectAndImageFromPath(filename, "")
}

