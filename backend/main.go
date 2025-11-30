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
	Tag           string         `json:"tag,omitempty"`
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

	// CORS configuration - support FQDN from environment variable
	allowedOrigins := []string{"http://localhost:3000", "http://localhost:80", "http://localhost"} // Default for local development
	
	// ALLOWED_ORIGINS manuel olarak belirtilmişse onu kullan (en yüksek öncelik)
	if origin := os.Getenv("ALLOWED_ORIGINS"); origin != "" {
		// Support multiple origins separated by comma
		origins := strings.Split(origin, ",")
		allowedOrigins = []string{} // Manuel belirtilmişse varsayılanları temizle
		for _, o := range origins {
			o = strings.TrimSpace(o)
			if o != "" {
				allowedOrigins = append(allowedOrigins, o)
			}
		}
	} else if fqdn := os.Getenv("FQDN"); fqdn != "" {
		// ALLOWED_ORIGINS yoksa FQDN'den otomatik türet (production)
		fqdn = strings.TrimSpace(fqdn)
		allowedOrigins = []string{} // FQDN kullanılıyorsa varsayılanları temizle
		// VITE_API_BASE'e bakarak HTTP mi HTTPS mi olduğunu anla
		viteBase := os.Getenv("VITE_API_BASE")
		if strings.HasPrefix(viteBase, "http://") {
			// HTTP ise (local test)
			allowedOrigins = append(allowedOrigins, "http://"+fqdn)
		} else {
			// HTTPS ise (production)
			allowedOrigins = append(allowedOrigins, "https://"+fqdn)
		}
	} else if frontendPort := os.Getenv("FRONTEND_PORT"); frontendPort != "" {
		// ALLOWED_ORIGINS ve FQDN yoksa FRONTEND_PORT'tan otomatik oluştur (local development)
		frontendPort = strings.TrimSpace(frontendPort)
		allowedOrigins = []string{} // FRONTEND_PORT kullanılıyorsa varsayılanları temizle
		allowedOrigins = append(allowedOrigins, "http://localhost:"+frontendPort)
		// Ayrıca localhost (port olmadan) da ekle
		allowedOrigins = append(allowedOrigins, "http://localhost")
	}
	
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   allowedOrigins,
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

			// Determine scan time: prefer timestamp in filename if present, fallback to file mod time
			scanTime := extractTimestampFromPath(relPath, info.ModTime())

			summary := ScanSummary{
				Filename:      relPath, // Store relative path for API access
				Size:          info.Size(),
				ModifiedAt:    scanTime,
				SeverityCount: make(map[string]int),
			}

			// Parse JSON to get ArtifactName
			var projectName, imageName, tag string
			if report, err := parseTrivyJSON(filePath); err == nil {
				summary.ArtifactName = report.ArtifactName
				
				// Try to extract project, image, and tag from ArtifactName first
				projectName, imageName, tag = extractProjectImageTagFromArtifactName(report.ArtifactName)
				summary.Tag = tag
				
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

			// Fallback to filename parsing if ArtifactName parsing failed
			// But only if we got projectName from ArtifactName but no imageName (shouldn't happen with new logic)
			if projectName != "" && imageName == "" {
				// This shouldn't happen now, but keep for safety
				projectName, imageName = extractProjectAndImageFromPath(relPath, exportDir)
			} else if projectName == "" {
				// If ArtifactName parsing completely failed, try filename
				projectName, imageName = extractProjectAndImageFromPath(relPath, exportDir)
			}

			summary.ProjectName = projectName
			summary.ImageName = imageName

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

			// Determine scan time: prefer timestamp in filename if present, fallback to file mod time
			scanTime := extractTimestampFromPath(relPath, info.ModTime())

			// Create scan summary
			scanSummary := ScanSummary{
				Filename:      relPath, // Store relative path
				Size:          info.Size(),
				ModifiedAt:    scanTime,
				SeverityCount: make(map[string]int),
			}

			// Parse JSON to get ArtifactName
			var projectName, imageName, tag string
			if report, err := parseTrivyJSON(filePath); err == nil {
				scanSummary.ArtifactName = report.ArtifactName
				
				// Try to extract project, image, and tag from ArtifactName first
				projectName, imageName, tag = extractProjectImageTagFromArtifactName(report.ArtifactName)
				scanSummary.Tag = tag
				
				total := 0
				for _, result := range report.Results {
					for _, vuln := range result.Vulnerabilities {
						total++
						severity := strings.ToUpper(vuln.Severity)
						if severity == "" {
							severity = "UNKNOWN"
						}
						scanSummary.SeverityCount[severity]++
					}
				}
				scanSummary.TotalVulns = total
			}

			// Fallback to filename parsing if ArtifactName parsing failed
			// But only if we got projectName from ArtifactName but no imageName (shouldn't happen with new logic)
			if projectName != "" && imageName == "" {
				// This shouldn't happen now, but keep for safety
				projectName, imageName = extractProjectAndImageFromPath(relPath, exportDir)
			} else if projectName == "" {
				// If ArtifactName parsing completely failed, try filename
				projectName, imageName = extractProjectAndImageFromPath(relPath, exportDir)
			}
			
			if projectName == "" || imageName == "" {
				continue
			}

			scanSummary.ProjectName = projectName
			scanSummary.ImageName = imageName

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
			// Reset project totals to ensure we only use latest scans per image
			project.TotalVulns = 0
			project.SeverityCount = make(map[string]int)

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

				// Aggregate project totals from latest scan of each image
				project.TotalVulns += imageSummary.TotalVulns
				for severity, count := range imageSummary.SeverityCount {
					project.SeverityCount[severity] += count
				}

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

			info, err := os.Stat(filePath)
			if err != nil {
				continue
			}

			// Determine scan time: prefer timestamp in filename if present, fallback to file mod time
			scanTime := extractTimestampFromPath(relPath, info.ModTime())

			// Create scan summary for this file
			scanSummary := ScanSummary{
				Filename:      relPath, // Store relative path
				Size:          info.Size(),
				ModifiedAt:    scanTime,
				SeverityCount: make(map[string]int),
			}

			// Parse JSON to get ArtifactName
			var fileProjectName, imageName, tag string
			if report, err := parseTrivyJSON(filePath); err == nil {
				scanSummary.ArtifactName = report.ArtifactName
				
				// Try to extract project, image, and tag from ArtifactName first
				fileProjectName, imageName, tag = extractProjectImageTagFromArtifactName(report.ArtifactName)
				scanSummary.Tag = tag
				total := 0
				for _, result := range report.Results {
					for _, vuln := range result.Vulnerabilities {
						total++
						severity := strings.ToUpper(vuln.Severity)
						if severity == "" {
							severity = "UNKNOWN"
						}
						scanSummary.SeverityCount[severity]++
						// Don't add to project totals here - we'll calculate from latest scans only
					}
				}
				scanSummary.TotalVulns = total
				// Don't add to project.TotalVulns here - we'll calculate from latest scans only
			}

			// Fallback to filename parsing if ArtifactName parsing failed
			if fileProjectName != "" && imageName == "" {
				// Got projectName from ArtifactName but no imageName (shouldn't happen with new logic)
				fileProjectName, imageName = extractProjectAndImageFromPath(relPath, exportDir)
			} else if fileProjectName == "" {
				// If ArtifactName parsing completely failed, try filename
				fileProjectName, imageName = extractProjectAndImageFromPath(relPath, exportDir)
			}

			// Skip if project name doesn't match or image name is empty
			if fileProjectName != projectName {
				continue
			}

			if imageName == "" {
				continue
			}

			scanSummary.ProjectName = fileProjectName
			scanSummary.ImageName = imageName

			project.TotalScans++

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
		// Also calculate project totals from latest scans only
		project.TotalVulns = 0
		project.SeverityCount = make(map[string]int)
		
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
			
			// Use latest scan for image totals (already set in the loop above)
			// Add image totals to project totals (from latest scan only)
			project.TotalVulns += imageSummary.TotalVulns
			for severity, count := range imageSummary.SeverityCount {
				project.SeverityCount[severity] += count
			}
			
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

// extractTimestampFromPath tries to read timestamp from filename and convert it to time.Time.
// If no valid timestamp pattern exists, it falls back to the provided defaultTime (usually file ModTime).
func extractTimestampFromPath(relPath string, defaultTime time.Time) time.Time {
	// Normalize and strip extension
	relPath = filepath.ToSlash(relPath)
	basePath := strings.TrimSuffix(relPath, ".json")
	if basePath == "" {
		return defaultTime
	}

	_, fileName := filepath.Split(basePath)

	// Timestamp pattern: -YYYYMMDD-HHMMSS (16 chars)
	if len(fileName) > 16 {
		lastPart := fileName[len(fileName)-16:]
		if len(lastPart) == 16 && lastPart[0] == '-' && strings.Count(lastPart, "-") == 2 {
			parts := strings.Split(lastPart[1:], "-") // skip first dash
			if len(parts) == 2 && len(parts[0]) == 8 && len(parts[1]) == 6 {
				// Validate numeric
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
					// Parse timestamp in local time
					tsStr := parts[0] + "-" + parts[1] // YYYYMMDD-HHMMSS
					if t, err := time.ParseInLocation("20060102-150405", tsStr, time.Local); err == nil {
						return t
					}
				}
			}
		}
	}

	return defaultTime
}

// extractProjectImageTagFromArtifactName extracts project, image, and tag from ArtifactName
// Format: {project-name}-{image-name}:{tag}
// Example: "trivy-dashboard-backend:latest" -> project: "trivy-dashboard", image: "backend", tag: "latest"
// Example: "my-service-api:v1.0.0" -> project: "my-service", image: "api", tag: "v1.0.0"
// Returns empty strings if parsing fails
func extractProjectImageTagFromArtifactName(artifactName string) (projectName, imageName, tag string) {
	if artifactName == "" {
		return "", "", ""
	}

	// Split by colon to get tag
	parts := strings.Split(artifactName, ":")
	var namePart string
	if len(parts) == 2 {
		namePart = parts[0]
		tag = parts[1]
	} else if len(parts) == 1 {
		namePart = parts[0]
		tag = "" // No tag specified
	} else {
		// Multiple colons? Use last one as tag
		lastColon := strings.LastIndex(artifactName, ":")
		if lastColon > 0 && lastColon < len(artifactName)-1 {
			namePart = artifactName[:lastColon]
			tag = artifactName[lastColon+1:]
		} else {
			return "", "", ""
		}
	}

	// Find last dash to split project and image
	// Format: {project-name}-{image-name}
	lastDash := strings.LastIndex(namePart, "-")
	if lastDash == -1 || lastDash == 0 || lastDash == len(namePart)-1 {
		// No dash found, or dash at start/end - treat whole name as both project and image
		// This handles cases like "wordpress:6.6.2" where imageName should be "wordpress", not empty
		return namePart, namePart, tag
	}

	projectName = namePart[:lastDash]
	imageName = namePart[lastDash+1:]

	return projectName, imageName, tag
}

// extractProjectAndImage is kept for backward compatibility
// It now calls extractProjectAndImageFromPath with empty exportDir
func extractProjectAndImage(filename string) (projectName, imageName string) {
	return extractProjectAndImageFromPath(filename, "")
}

