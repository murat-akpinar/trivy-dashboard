import React, { useEffect, useState, useMemo } from 'react';

type ProjectSummary = {
  projectName: string;
  totalScans: number;
  totalVulns: number;
  severityCount: Record<string, number>;
  images: ImageSummary[];
  lastScan: string;
};

type ImageSummary = {
  imageName: string;
  filename: string;
  totalVulns: number;
  severityCount: Record<string, number>;
  modifiedAt: string;
};

type Vulnerability = {
  VulnerabilityID: string;
  PkgName: string;
  InstalledVersion: string;
  FixedVersion: string;
  Severity: string;
  Title: string;
  Description: string;
  PrimaryURL?: string;
};

const API_BASE =
  import.meta.env.VITE_API_BASE || (import.meta.env.DEV ? 'http://localhost:8180' : '');

type Page = 'dashboard' | 'projects' | 'project-detail';

// Calculate grade based on severity counts
function calculateGrade(severityCount: Record<string, number>): { grade: string; color: string } {
  const critical = severityCount['CRITICAL'] || 0;
  const high = severityCount['HIGH'] || 0;
  const medium = severityCount['MEDIUM'] || 0;
  const low = severityCount['LOW'] || 0;

  // Grade A: No critical, low high/medium
  if (critical === 0 && high <= 2 && medium <= 5) {
    return { grade: 'A', color: 'catppuccin-green' };
  }

  // Grade B: No critical, moderate high/medium
  if (critical === 0 && high <= 5 && medium <= 10) {
    return { grade: 'B', color: 'catppuccin-blue' };
  }

  // Grade C: Low critical or moderate issues
  if (critical <= 2 && high <= 8 && medium <= 15) {
    return { grade: 'C', color: 'catppuccin-yellow' };
  }

  // Grade D: High critical or too many issues
  return { grade: 'D', color: 'catppuccin-red' };
}

function App() {
  const [projects, setProjects] = useState<ProjectSummary[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [currentPage, setCurrentPage] = useState<Page>('dashboard');
  const [selectedProject, setSelectedProject] = useState<string | null>(null);
  const [projectDetails, setProjectDetails] = useState<ProjectSummary | null>(null);
  const [selectedFilename, setSelectedFilename] = useState<string | null>(null);
  const [vulnDetails, setVulnDetails] = useState<Vulnerability[]>([]);
  const [loadingDetails, setLoadingDetails] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string | null>(null);
  const [expandedImages, setExpandedImages] = useState<Set<string>>(new Set());
  const [imageVulnDetails, setImageVulnDetails] = useState<Record<string, Vulnerability[]>>({});
  const [loadingImageDetails, setLoadingImageDetails] = useState<Record<string, boolean>>({});

  useEffect(() => {
    if (!API_BASE) return;
    setLoading(true);
    fetch(`${API_BASE}/api/projects`)
      .then(async (res) => {
        if (!res.ok) {
          throw new Error(`API error: ${res.status}`);
        }
        return res.json();
      })
      .then((data: ProjectSummary[]) => {
        setProjects(data);
        setError(null);
      })
      .catch((err) => {
        setError(err.message);
      })
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (!selectedProject || !API_BASE) return;
    setLoadingDetails(true);
    fetch(`${API_BASE}/api/projects/${selectedProject}`)
      .then(async (res) => {
        if (!res.ok) {
          throw new Error(`API error: ${res.status}`);
        }
        return res.json();
      })
      .then((data: ProjectSummary) => {
        setProjectDetails(data);
      })
      .catch((err) => {
        console.error('Failed to load project details:', err);
        setProjectDetails(null);
      })
      .finally(() => setLoadingDetails(false));
  }, [selectedProject]);

  useEffect(() => {
    if (!selectedFilename || !API_BASE) return;
    setLoadingDetails(true);
    fetch(`${API_BASE}/api/scans/${selectedFilename}`)
      .then(async (res) => {
        if (!res.ok) {
          throw new Error(`API error: ${res.status}`);
        }
        return res.json();
      })
      .then((data: { vulnerabilities: Vulnerability[] }) => {
        setVulnDetails(data.vulnerabilities || []);
      })
      .catch((err) => {
        console.error('Failed to load details:', err);
        setVulnDetails([]);
      })
      .finally(() => setLoadingDetails(false));
  }, [selectedFilename]);

  // Load vulnerabilities for expanded images
  useEffect(() => {
    if (!API_BASE || !projectDetails) return;

    expandedImages.forEach((filename) => {
      // Skip if already loaded
      if (imageVulnDetails[filename] || loadingImageDetails[filename]) return;

      setLoadingImageDetails((prev) => ({ ...prev, [filename]: true }));
      fetch(`${API_BASE}/api/scans/${filename}`)
        .then(async (res) => {
          if (!res.ok) {
            throw new Error(`API error: ${res.status}`);
          }
          return res.json();
        })
        .then((data: { vulnerabilities: Vulnerability[] }) => {
          setImageVulnDetails((prev) => ({
            ...prev,
            [filename]: data.vulnerabilities || []
          }));
        })
        .catch((err) => {
          console.error('Failed to load details:', err);
          setImageVulnDetails((prev) => ({ ...prev, [filename]: [] }));
        })
        .finally(() => {
          setLoadingImageDetails((prev) => ({ ...prev, [filename]: false }));
        });
    });
  }, [expandedImages, API_BASE, projectDetails]);

  // Calculate overall statistics
  const overallStats = useMemo(() => {
    const totalProjects = projects.length;
    const totalScans = projects.reduce((sum, p) => sum + p.totalScans, 0);
    const totalVulns = projects.reduce((sum, p) => sum + p.totalVulns, 0);
    const severityCount: Record<string, number> = {};
    projects.forEach((p) => {
      Object.keys(p.severityCount).forEach((severity) => {
        severityCount[severity] = (severityCount[severity] || 0) + p.severityCount[severity];
      });
    });
    return { totalProjects, totalScans, totalVulns, severityCount };
  }, [projects]);

  // Filter projects based on search query
  const filteredProjects = useMemo(() => {
    if (!searchQuery.trim()) return projects;
    const query = searchQuery.toLowerCase();
    return projects.filter((p) => p.projectName.toLowerCase().includes(query));
  }, [projects, searchQuery]);

  // Filter projects by selected severity (for dashboard)
  const projectsBySeverity = useMemo(() => {
    if (!selectedSeverity) return [];
    return projects.filter((p) => (p.severityCount[selectedSeverity] || 0) > 0);
  }, [projects, selectedSeverity]);

  if (currentPage === 'project-detail' && projectDetails) {
    return (
      <div className="min-h-screen bg-catppuccin-base text-catppuccin-text">
        <header className="border-b border-catppuccin-surface0 bg-catppuccin-mantle/70 backdrop-blur">
          <div className="mx-auto flex max-w-5xl items-center justify-between px-4 py-3">
            <div className="flex items-center gap-2">
              <button
                onClick={() => {
                  setCurrentPage('projects');
                  setSelectedProject(null);
                  setProjectDetails(null);
                  setExpandedImages(new Set());
                  setImageVulnDetails({});
                  setLoadingImageDetails({});
                }}
                className="text-catppuccin-overlay1 hover:text-catppuccin-text mr-2"
              >
                ← Geri
              </button>
              <span className="rounded bg-catppuccin-teal/10 px-2 py-1 text-xs font-semibold uppercase tracking-wide text-catppuccin-teal">
                {projectDetails.projectName}
              </span>
              <span className="text-lg font-semibold">Proje Detayları</span>
            </div>
            <span className="text-xs text-catppuccin-overlay1">Prototype UI</span>
          </div>
        </header>

        <main className="mx-auto max-w-5xl px-4 py-6 space-y-6">
          <section className="grid gap-4 md:grid-cols-4">
            <div className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
              <p className="text-xs font-medium uppercase tracking-wide text-catppuccin-overlay1">
                Toplam Tarama
              </p>
              <p className="mt-2 text-3xl font-semibold">{projectDetails.totalScans}</p>
            </div>
            <div className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
              <p className="text-xs font-medium uppercase tracking-wide text-catppuccin-overlay1">
                Toplam Açık
              </p>
              <p className="mt-2 text-3xl font-semibold">{projectDetails.totalVulns}</p>
            </div>
            <div className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
              <p className="text-xs font-medium uppercase tracking-wide text-catppuccin-overlay1">
                CRITICAL
              </p>
              <p className="mt-2 text-3xl font-semibold text-catppuccin-red">
                {projectDetails.severityCount['CRITICAL'] || 0}
              </p>
            </div>
            <div className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
              <p className="text-xs font-medium uppercase tracking-wide text-catppuccin-overlay1">HIGH</p>
              <p className="mt-2 text-3xl font-semibold text-catppuccin-peach">
                {projectDetails.severityCount['HIGH'] || 0}
              </p>
            </div>
          </section>

          <section className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
            <h2 className="text-sm font-semibold text-catppuccin-text mb-4">İmajlar ve Taramalar</h2>

            {projectDetails.images.length === 0 ? (
              <div className="text-center py-8 text-catppuccin-overlay1">Henüz tarama bulunamadı.</div>
            ) : (
              <div className="space-y-4">
                {projectDetails.images.map((image) => {
                  const isExpanded = expandedImages.has(image.filename);
                  const { grade, color } = calculateGrade(image.severityCount);
                  const toggleExpand = (e: React.MouseEvent) => {
                    e.stopPropagation();
                    setExpandedImages((prev) => {
                      const newSet = new Set(prev);
                      if (newSet.has(image.filename)) {
                        newSet.delete(image.filename);
                      } else {
                        newSet.add(image.filename);
                      }
                      return newSet;
                    });
                  };

                  return (
                    <div key={image.filename} className="space-y-0">
                      <div
                        className={`border rounded-lg p-4 cursor-pointer hover:opacity-90 transition-all ${
                          color === 'catppuccin-green'
                            ? 'border-catppuccin-green bg-catppuccin-green/10'
                            : color === 'catppuccin-blue'
                              ? 'border-catppuccin-blue bg-catppuccin-blue/10'
                              : color === 'catppuccin-yellow'
                                ? 'border-catppuccin-yellow bg-catppuccin-yellow/10'
                                : 'border-catppuccin-red bg-catppuccin-red/10'
                        }`}
                        onClick={toggleExpand}
                      >
                        <div className="flex items-center justify-between mb-3">
                          <div className="flex items-center gap-3">
                            <div
                              className={`w-16 h-16 rounded-lg flex items-center justify-center text-2xl font-bold ${
                                color === 'catppuccin-green'
                                  ? 'bg-catppuccin-green/20 text-catppuccin-green'
                                  : color === 'catppuccin-blue'
                                    ? 'bg-catppuccin-blue/20 text-catppuccin-blue'
                                    : color === 'catppuccin-yellow'
                                      ? 'bg-catppuccin-yellow/20 text-catppuccin-yellow'
                                      : 'bg-catppuccin-red/20 text-catppuccin-red'
                              }`}
                            >
                              {grade}
                            </div>
                            <div>
                              <h3 className="text-base font-semibold text-catppuccin-text">
                                {image.imageName}
                              </h3>
                              <p className="text-xs text-catppuccin-overlay1 mt-1">
                                {new Date(image.modifiedAt).toLocaleString()}
                              </p>
                            </div>
                          </div>
                          <div className="flex items-center gap-6 text-sm">
                            <div className="text-right">
                              <span className="text-catppuccin-overlay1 text-xs">Toplam: </span>
                              <span className="font-bold text-lg text-catppuccin-text">
                                {image.totalVulns}
                              </span>
                            </div>
                            <div className="flex gap-3">
                              {image.severityCount['CRITICAL'] > 0 && (
                                <span className="text-catppuccin-red font-bold text-base">
                                  C:{image.severityCount['CRITICAL']}
                                </span>
                              )}
                              {image.severityCount['HIGH'] > 0 && (
                                <span className="text-catppuccin-peach font-bold text-base">
                                  H:{image.severityCount['HIGH']}
                                </span>
                              )}
                              {image.severityCount['MEDIUM'] > 0 && (
                                <span className="text-catppuccin-yellow font-bold text-base">
                                  M:{image.severityCount['MEDIUM']}
                                </span>
                              )}
                              {image.severityCount['LOW'] > 0 && (
                                <span className="text-catppuccin-blue font-bold text-base">
                                  L:{image.severityCount['LOW']}
                                </span>
                              )}
                            </div>
                          </div>
                        </div>
                        <button
                          onClick={toggleExpand}
                          className="text-xs px-3 py-1 rounded border border-catppuccin-surface1 hover:bg-catppuccin-surface0 text-catppuccin-subtext0 transition-colors"
                        >
                          {isExpanded ? 'Açıkları Gizle ↑' : 'Açıkları Görüntüle ↓'}
                        </button>
                      </div>

                      {isExpanded && (
                        <div className="mt-2 border border-catppuccin-surface0 rounded-lg p-4 bg-catppuccin-mantle/60">
                          {loadingImageDetails[image.filename] ? (
                            <div className="text-center py-8 text-catppuccin-overlay1">
                              Yükleniyor...
                            </div>
                          ) : (imageVulnDetails[image.filename] || []).length === 0 ? (
                            <div className="text-center py-8 text-catppuccin-overlay1">
                              Bu raporda açık bulunamadı.
                            </div>
                          ) : (
                            <div className="space-y-3 max-h-[600px] overflow-y-auto">
                              {(imageVulnDetails[image.filename] || []).map((vuln, idx) => {
                                const severityColor =
                                  vuln.Severity === 'CRITICAL'
                                    ? 'text-catppuccin-red'
                                    : vuln.Severity === 'HIGH'
                                      ? 'text-catppuccin-peach'
                                      : vuln.Severity === 'MEDIUM'
                                        ? 'text-catppuccin-yellow'
                                        : vuln.Severity === 'LOW'
                                          ? 'text-catppuccin-blue'
                                          : 'text-catppuccin-overlay1';
                                return (
                                  <div
                                    key={`${vuln.VulnerabilityID}-${idx}`}
                                    className="border border-catppuccin-surface0 rounded-lg p-4 bg-catppuccin-base/60"
                                  >
                                    <div className="flex items-start justify-between mb-2">
                                      <div>
                                        <span className="font-mono text-xs text-catppuccin-teal">
                                          {vuln.VulnerabilityID}
                                        </span>
                                        <span className={`ml-2 text-xs font-semibold ${severityColor}`}>
                                          {vuln.Severity}
                                        </span>
                                      </div>
                                      {vuln.PrimaryURL && (
                                        <a
                                          href={vuln.PrimaryURL}
                                          target="_blank"
                                          rel="noopener noreferrer"
                                          className="text-xs text-catppuccin-blue hover:underline"
                                        >
                                          Detay →
                                        </a>
                                      )}
                                    </div>
                                    <h3 className="text-sm font-semibold text-catppuccin-text mb-1">
                                      {vuln.Title || vuln.VulnerabilityID}
                                    </h3>
                                    <div className="text-xs text-catppuccin-overlay1 mb-2">
                                      <span className="font-mono">{vuln.PkgName}</span>
                                      {vuln.InstalledVersion && (
                                        <span className="ml-2">
                                          v{vuln.InstalledVersion}
                                          {vuln.FixedVersion && (
                                            <span className="text-catppuccin-teal ml-1">
                                              → v{vuln.FixedVersion}
                                            </span>
                                          )}
                                        </span>
                                      )}
                                    </div>
                                    {vuln.Description && (
                                      <p className="text-xs text-catppuccin-subtext0 mt-2 line-clamp-3">
                                        {vuln.Description}
                                      </p>
                                    )}
                                  </div>
                                );
                              })}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </section>
        </main>
      </div>
    );
  }

  if (currentPage === 'projects') {
    return (
      <div className="min-h-screen bg-catppuccin-base text-catppuccin-text">
        <header className="border-b border-catppuccin-surface0 bg-catppuccin-mantle/70 backdrop-blur">
          <div className="mx-auto flex max-w-5xl items-center justify-between px-4 py-3">
            <div className="flex items-center gap-2">
              <button
                onClick={() => setCurrentPage('dashboard')}
                className="text-catppuccin-overlay1 hover:text-catppuccin-text mr-2"
              >
                ← Ana Sayfa
              </button>
              <span className="rounded bg-catppuccin-teal/10 px-2 py-1 text-xs font-semibold uppercase tracking-wide text-catppuccin-teal">
                Trivy
              </span>
              <span className="text-lg font-semibold">Projeler</span>
            </div>
            <span className="text-xs text-catppuccin-overlay1">Prototype UI</span>
          </div>
        </header>

        <main className="mx-auto max-w-5xl px-4 py-6 space-y-6">
          <section className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-semibold text-catppuccin-text">Projeler</h2>
              <span className="text-xs text-catppuccin-overlay0">
                {filteredProjects.length} / {projects.length} proje
              </span>
            </div>

            <div className="mb-4">
              <input
                type="text"
                placeholder="Proje ara..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full px-4 py-2 rounded-lg border border-catppuccin-surface1 bg-catppuccin-base text-catppuccin-text placeholder-catppuccin-overlay0 focus:outline-none focus:ring-2 focus:ring-catppuccin-teal focus:border-transparent"
              />
            </div>

            {filteredProjects.length === 0 && !loading && !error && (
              <div className="flex h-40 items-center justify-center text-sm text-catppuccin-overlay0">
                {searchQuery
                  ? 'Arama kriterlerine uygun proje bulunamadı.'
                  : 'Henüz proje bulunamadı. export klasörüne JSON dosyası koyduktan sonra sayfayı yenile.'}
              </div>
            )}

            {filteredProjects.length > 0 && (
              <div className="space-y-3">
                {filteredProjects.map((project) => (
                  <div
                    key={project.projectName}
                    className="border border-catppuccin-surface0 rounded-lg p-4 bg-catppuccin-base/60 hover:bg-catppuccin-mantle/40 cursor-pointer transition-colors"
                    onClick={() => {
                      setSelectedProject(project.projectName);
                      setCurrentPage('project-detail');
                    }}
                  >
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="text-lg font-semibold text-catppuccin-text">
                          {project.projectName}
                        </h3>
                        <p className="text-xs text-catppuccin-overlay1 mt-1">
                          {project.totalScans} tarama • Son tarama:{' '}
                          {new Date(project.lastScan).toLocaleString()}
                        </p>
                      </div>
                      <div className="flex items-center gap-4">
                        <div className="text-right">
                          <span className="text-xs text-catppuccin-overlay1">Toplam Açık</span>
                          <p className="text-2xl font-semibold text-catppuccin-text">
                            {project.totalVulns}
                          </p>
                        </div>
                        <div className="flex gap-3 text-sm">
                          {project.severityCount['CRITICAL'] > 0 && (
                            <div className="text-center">
                              <p className="text-xs text-catppuccin-overlay1">CRITICAL</p>
                              <p className="text-lg font-semibold text-catppuccin-red">
                                {project.severityCount['CRITICAL']}
                              </p>
                            </div>
                          )}
                          {project.severityCount['HIGH'] > 0 && (
                            <div className="text-center">
                              <p className="text-xs text-catppuccin-overlay1">HIGH</p>
                              <p className="text-lg font-semibold text-catppuccin-peach">
                                {project.severityCount['HIGH']}
                              </p>
                            </div>
                          )}
                          {project.severityCount['MEDIUM'] > 0 && (
                            <div className="text-center">
                              <p className="text-xs text-catppuccin-overlay1">MEDIUM</p>
                              <p className="text-lg font-semibold text-catppuccin-yellow">
                                {project.severityCount['MEDIUM']}
                              </p>
                            </div>
                          )}
                          {project.severityCount['LOW'] > 0 && (
                            <div className="text-center">
                              <p className="text-xs text-catppuccin-overlay1">LOW</p>
                              <p className="text-lg font-semibold text-catppuccin-blue">
                                {project.severityCount['LOW']}
                              </p>
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>
        </main>
      </div>
    );
  }

  // Dashboard page
  return (
    <div className="min-h-screen bg-catppuccin-base text-catppuccin-text">
      <header className="border-b border-catppuccin-surface0 bg-catppuccin-mantle/70 backdrop-blur">
        <div className="mx-auto flex max-w-5xl items-center justify-between px-4 py-3">
          <div className="flex items-center gap-2">
            <span className="rounded bg-catppuccin-teal/10 px-2 py-1 text-xs font-semibold uppercase tracking-wide text-catppuccin-teal">
              Trivy
            </span>
            <span className="text-lg font-semibold">Dashboard</span>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => setCurrentPage('projects')}
              className="px-3 py-1 text-xs rounded border border-catppuccin-surface1 hover:bg-catppuccin-surface0 text-catppuccin-subtext0"
            >
              Projeler →
            </button>
            <span className="text-xs text-catppuccin-overlay1">Prototype UI</span>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-5xl px-4 py-6 space-y-6">
        <section className="grid gap-4 md:grid-cols-4">
          <div className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
            <p className="text-xs font-medium uppercase tracking-wide text-catppuccin-overlay1">
              Toplam Proje
            </p>
            <p className="mt-2 text-3xl font-semibold">{overallStats.totalProjects}</p>
          </div>
          <div className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
            <p className="text-xs font-medium uppercase tracking-wide text-catppuccin-overlay1">
              Toplam Tarama
            </p>
            <p className="mt-2 text-3xl font-semibold">{overallStats.totalScans}</p>
          </div>
          <div className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
            <p className="text-xs font-medium uppercase tracking-wide text-catppuccin-overlay1">
              Toplam Açık
            </p>
            <p className="mt-2 text-3xl font-semibold">{overallStats.totalVulns}</p>
          </div>
          <div className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
            <p className="text-xs font-medium uppercase tracking-wide text-catppuccin-overlay1">
              Backend URL
            </p>
            <p className="mt-2 text-xs text-catppuccin-subtext0 break-all">
              {API_BASE || 'Tanımlı değil'}
            </p>
          </div>
        </section>

        <section className="grid gap-4 md:grid-cols-4">
          <div
            className={`rounded-xl border p-4 cursor-pointer transition-all ${
              selectedSeverity === 'CRITICAL'
                ? 'border-catppuccin-red bg-catppuccin-red/10'
                : 'border-catppuccin-surface0 bg-catppuccin-mantle/60 hover:bg-catppuccin-mantle/80'
            }`}
            onClick={() =>
              setSelectedSeverity(selectedSeverity === 'CRITICAL' ? null : 'CRITICAL')
            }
          >
            <p className="text-xs font-medium uppercase tracking-wide text-catppuccin-overlay1">
              CRITICAL
            </p>
            <p className="mt-2 text-3xl font-semibold text-catppuccin-red">
              {overallStats.severityCount['CRITICAL'] || 0}
            </p>
            {selectedSeverity === 'CRITICAL' && (
              <p className="mt-1 text-xs text-catppuccin-red">Tıklayarak kapat</p>
            )}
          </div>
          <div
            className={`rounded-xl border p-4 cursor-pointer transition-all ${
              selectedSeverity === 'HIGH'
                ? 'border-catppuccin-peach bg-catppuccin-peach/10'
                : 'border-catppuccin-surface0 bg-catppuccin-mantle/60 hover:bg-catppuccin-mantle/80'
            }`}
            onClick={() => setSelectedSeverity(selectedSeverity === 'HIGH' ? null : 'HIGH')}
          >
            <p className="text-xs font-medium uppercase tracking-wide text-catppuccin-overlay1">HIGH</p>
            <p className="mt-2 text-3xl font-semibold text-catppuccin-peach">
              {overallStats.severityCount['HIGH'] || 0}
            </p>
            {selectedSeverity === 'HIGH' && (
              <p className="mt-1 text-xs text-catppuccin-peach">Tıklayarak kapat</p>
            )}
          </div>
          <div
            className={`rounded-xl border p-4 cursor-pointer transition-all ${
              selectedSeverity === 'MEDIUM'
                ? 'border-catppuccin-yellow bg-catppuccin-yellow/10'
                : 'border-catppuccin-surface0 bg-catppuccin-mantle/60 hover:bg-catppuccin-mantle/80'
            }`}
            onClick={() => setSelectedSeverity(selectedSeverity === 'MEDIUM' ? null : 'MEDIUM')}
          >
            <p className="text-xs font-medium uppercase tracking-wide text-catppuccin-overlay1">MEDIUM</p>
            <p className="mt-2 text-3xl font-semibold text-catppuccin-yellow">
              {overallStats.severityCount['MEDIUM'] || 0}
            </p>
            {selectedSeverity === 'MEDIUM' && (
              <p className="mt-1 text-xs text-catppuccin-yellow">Tıklayarak kapat</p>
            )}
          </div>
          <div
            className={`rounded-xl border p-4 cursor-pointer transition-all ${
              selectedSeverity === 'LOW'
                ? 'border-catppuccin-blue bg-catppuccin-blue/10'
                : 'border-catppuccin-surface0 bg-catppuccin-mantle/60 hover:bg-catppuccin-mantle/80'
            }`}
            onClick={() => setSelectedSeverity(selectedSeverity === 'LOW' ? null : 'LOW')}
          >
            <p className="text-xs font-medium uppercase tracking-wide text-catppuccin-overlay1">LOW</p>
            <p className="mt-2 text-3xl font-semibold text-catppuccin-blue">
              {overallStats.severityCount['LOW'] || 0}
            </p>
            {selectedSeverity === 'LOW' && (
              <p className="mt-1 text-xs text-catppuccin-blue">Tıklayarak kapat</p>
            )}
          </div>
        </section>

        <section className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-catppuccin-text">Genel Özet</h2>
            <span className="text-xs text-catppuccin-overlay0">
              Tüm projelerin toplam istatistikleri
            </span>
          </div>

          <div className="text-sm text-catppuccin-subtext0 space-y-2">
            <p>
              <span className="text-catppuccin-overlay1">Durum:</span>{' '}
              {loading ? 'Yükleniyor...' : error ? `Hata: ${error}` : 'Hazır'}
            </p>
            <p>
              <span className="text-catppuccin-overlay1">Toplam Proje:</span> {overallStats.totalProjects}
            </p>
            <p>
              <span className="text-catppuccin-overlay1">Toplam Tarama:</span> {overallStats.totalScans}
            </p>
            <p>
              <span className="text-catppuccin-overlay1">Toplam Açık:</span> {overallStats.totalVulns}
            </p>
          </div>

          <div className="mt-4">
            <button
              onClick={() => setCurrentPage('projects')}
              className="px-4 py-2 rounded-lg border border-catppuccin-teal bg-catppuccin-teal/10 hover:bg-catppuccin-teal/20 text-catppuccin-teal font-medium transition-colors"
            >
              Tüm Projeleri Görüntüle →
            </button>
          </div>
        </section>

        {selectedSeverity && projectsBySeverity.length > 0 && (
          <section className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-semibold text-catppuccin-text">
                {selectedSeverity} Severity'ye Sahip Projeler ({projectsBySeverity.length})
              </h2>
              <button
                onClick={() => setSelectedSeverity(null)}
                className="px-3 py-1 text-xs rounded border border-catppuccin-surface1 hover:bg-catppuccin-surface0 text-catppuccin-subtext0"
              >
                Kapat
              </button>
            </div>

            <div className="space-y-3">
              {projectsBySeverity.map((project) => (
                <div
                  key={project.projectName}
                  className="border border-catppuccin-surface0 rounded-lg p-4 bg-catppuccin-base/60 hover:bg-catppuccin-mantle/40 cursor-pointer transition-colors"
                  onClick={() => {
                    setSelectedProject(project.projectName);
                    setCurrentPage('project-detail');
                  }}
                >
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-lg font-semibold text-catppuccin-text">
                        {project.projectName}
                      </h3>
                      <p className="text-xs text-catppuccin-overlay1 mt-1">
                        {project.totalScans} tarama • Son tarama:{' '}
                        {new Date(project.lastScan).toLocaleString()}
                      </p>
                    </div>
                    <div className="flex items-center gap-4">
                      <div className="text-right">
                        <span className="text-xs text-catppuccin-overlay1">Toplam Açık</span>
                        <p className="text-2xl font-semibold text-catppuccin-text">
                          {project.totalVulns}
                        </p>
                      </div>
                      <div className="flex gap-3 text-sm">
                        {project.severityCount['CRITICAL'] > 0 && (
                          <div className="text-center">
                            <p className="text-xs text-catppuccin-overlay1">CRITICAL</p>
                            <p className="text-lg font-semibold text-catppuccin-red">
                              {project.severityCount['CRITICAL']}
                            </p>
                          </div>
                        )}
                        {project.severityCount['HIGH'] > 0 && (
                          <div className="text-center">
                            <p className="text-xs text-catppuccin-overlay1">HIGH</p>
                            <p className="text-lg font-semibold text-catppuccin-peach">
                              {project.severityCount['HIGH']}
                            </p>
                          </div>
                        )}
                        {project.severityCount['MEDIUM'] > 0 && (
                          <div className="text-center">
                            <p className="text-xs text-catppuccin-overlay1">MEDIUM</p>
                            <p className="text-lg font-semibold text-catppuccin-yellow">
                              {project.severityCount['MEDIUM']}
                            </p>
                          </div>
                        )}
                        {project.severityCount['LOW'] > 0 && (
                          <div className="text-center">
                            <p className="text-xs text-catppuccin-overlay1">LOW</p>
                            <p className="text-lg font-semibold text-catppuccin-blue">
                              {project.severityCount['LOW']}
                            </p>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </section>
        )}

        {selectedSeverity && projectsBySeverity.length === 0 && (
          <section className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-semibold text-catppuccin-text">
                {selectedSeverity} Severity'ye Sahip Projeler
              </h2>
              <button
                onClick={() => setSelectedSeverity(null)}
                className="px-3 py-1 text-xs rounded border border-catppuccin-surface1 hover:bg-catppuccin-surface0 text-catppuccin-subtext0"
              >
                Kapat
              </button>
            </div>
            <div className="text-center py-8 text-catppuccin-overlay1">
              {selectedSeverity} severity'sine sahip proje bulunamadı.
            </div>
          </section>
        )}
      </main>
    </div>
  );
}

export default App;
