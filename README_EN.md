# Trivy Dashboard

[🇹🇷 Türkçe](README.md) | [🇺🇸 English](README_EN.md)

A web dashboard application that collects and visualizes Trivy security scan results. It aggregates Trivy JSON outputs generated in CI/CD environments into a single centralized location, allowing you to easily review them.

![Dashboard](/images/dashboard.png)
![Project](/images/project.png)
![Comparison](/images/comparison.png)

## Features

- **Project-Based View**: View scans for all Docker images of each project on a single page
- **Severity Filtering**: Filter projects by CRITICAL, HIGH, MEDIUM, LOW severity levels
- **Grade System**: Automatic security grade (A, B, C, D) for each image
- **Detailed Vulnerability List**: ID, description, fixed version, and detail links for each vulnerability
- **Timeline**: Visualize how scans change over time
- **General Dashboard**: View total statistics for all projects
- **Detailed Comparison**: Diff view showing which vulnerabilities were closed/added between two scans

## Quick Start

### Requirements

- Docker and Docker Compose

### Installation

1. Clone the project:
```bash
git clone git@github.com:murat-akpinar/Trivy-Dashboard.git
cd trivy-dashboard
```

2. Start the containers:
```bash
docker compose up -d --build
```

3. Access the dashboard:
- Frontend: http://localhost:3000
- Backend API: http://localhost:8180

## Adding Trivy Scan Results

### File Format

Place Trivy JSON reports in the `export/` folder. The backend automatically extracts project, image, and tag information from the filename or the `ArtifactName` field in the JSON.

**Supported Formats:**

1. **Flat Structure**:
   ```
   export/{project}-{image}.json
   export/{project}-{image}-{YYYYMMDD-HHMMSS}.json
   ```
   Example: `export/trivy-dashboard-backend-20251126-182000.json`

2. **Directory Structure** (Recommended):
   ```
   export/{project}/{image}.json
   export/{project}/{image}-{YYYYMMDD-HHMMSS}.json
   ```
   Example: `export/trivy-dashboard/backend-20251126-182000.json`

3. **Automatic Parse from ArtifactName** (Easiest):
   Automatically parsed from the `ArtifactName` field inside the JSON file:
   - `ArtifactName: "trivy-dashboard-backend:latest"` → Project: `trivy-dashboard`, Image: `backend`, Tag: `latest`

### Docker Test Scanning

Ready-made scripts for backend and frontend:
```bash
./scan-backend.sh
./scan-frontend.sh
```

Manual scan:
```bash
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/export:/output \
  aquasec/trivy:latest image \
  --format json -o /output/trivy-dashboard/backend-${TIMESTAMP}.json \
  trivy-dashboard-backend:latest
```

### CI/CD Integration (Jenkins Example)

```bash
# Run scan
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
trivy image --format json -o /tmp/backend-${TIMESTAMP}.json my-project-backend:latest

# Send to dashboard server
scp /tmp/backend-${TIMESTAMP}.json user@dashboard-host:/path/to/trivy-dashboard/export/my-project/
```

## Grade System

The dashboard automatically calculates a letter grade for each image based on severity counts:

| Grade | Conditions | Description |
|-------|------------|-------------|
| **A** | CRITICAL = 0, HIGH ≤ 2, MEDIUM ≤ 5 | Excellent |
| **B** | CRITICAL = 0, HIGH ≤ 5, MEDIUM ≤ 10 | Good |
| **C** | CRITICAL ≤ 2, HIGH ≤ 8, MEDIUM ≤ 15 | Medium risk |
| **D** | Other cases | High risk |

## Configuration

Create a `.env` file to set environment variables:

```bash
BACKEND_PORT=8180              # Backend port (default: 8180)
FRONTEND_PORT=3000             # Frontend port (default: 3000)
EXPORT_DIR=./export            # JSON reports folder (default: ./export)
VITE_API_BASE=http://localhost:8180  # Frontend's backend access URL
TZ=Europe/Istanbul             # Timezone
```

## API Endpoints

### Backend API (http://localhost:8180)

- `GET /` - Backend status information
- `GET /health` - Health check
- `GET /api/projects` - List of all projects
- `GET /api/projects/{projectName}` - Project details
- `GET /api/scans` - List of all scans
- `GET /api/scans/{filename}` - Scan details (vulnerability list)
- `GET /api/compare?scan1={filename}&scan2={filename}` - Compare two scans

## Project Structure

```
trivy-dashboard/
├── backend/           # Go backend
├── frontend/          # React frontend
├── export/            # Trivy JSON reports (place files here)
├── scan-backend.sh    # Backend scan script
├── scan-frontend.sh   # Frontend scan script
└── docker-compose.yml # Container orchestration
```

## Technology Stack

- **Backend**: Go 1.23 + chi router
- **Frontend**: React 18 + Vite + TypeScript + TailwindCSS
- **Containerization**: Docker + Docker Compose
- **Web Server**: Nginx

## Development

### Backend Development

```bash
cd backend
go mod download
go run main.go
```

### Frontend Development

```bash
cd frontend
npm install
npm run dev
```

### Rebuild Containers

```bash
docker compose down --rmi all
docker compose build
docker compose up -d
```

## Health Check

Docker Compose includes automatic health check configuration for each service:
- Backend: Checks the `/health` endpoint
- Frontend: Checks Nginx's main page
- Restart Policy: `unless-stopped` - Automatically restarts if container crashes

To check health check status:
```bash
docker compose ps
```

## Development Roadmap

### Future Features

- [✅] **Detailed Comparison Analysis**: Show which vulnerabilities were closed/added between two scans, delta calculations (support for both same-version and cross-version comparisons)
- [ ] **Trend Analysis**: Percentage increase/decrease compared to last scan, trend indicators (↑↓ arrows) on cards, "Changed X% since last scan" information
- [✅] **Version Grouping Mode**: Toggle to group/separate different versions of the same image in timeline charts (default: grouped, more useful for overall trend analysis)
- [ ] **Email Notifications**: Send notifications when new CRITICAL/HIGH vulnerabilities are found
- [ ] **Export/Import**: Backup and restore scan results
- [ ] **API Authentication**: Access control for backend API
- [ ] **Database Integration**: Store scan history with SQLite/PostgreSQL
- [ ] **Webhook Support**: Automatically trigger scans from CI/CD pipelines
- [ ] **Advanced Filtering and Sorting**: Enhanced filtering in vulnerability lists
- [ ] **Side-by-Side Comparison Mode**: Display two scan results in detailed side-by-side view
- [ ] **Automatic Cleanup**: Automatically delete old scan files (retention policy)

### Current Features

- ✅ Project-based view
- ✅ Severity filtering
- ✅ Grade system (A, B, C, D)
- ✅ Multiple scan support with timestamps
- ✅ Readable scan display (image name and tag instead of filename)
- ✅ Catppuccin Mocha theme
- ✅ Responsive design
- ✅ Docker Compose support
- ✅ Timeline charts
- ✅ Detailed comparison analysis (delta between two scans, added/removed/changed vulnerabilities)

## License

GPL-3.0

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## Contact

Project owner: [murat-akpinar](https://github.com/murat-akpinar)

