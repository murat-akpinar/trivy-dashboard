import React, { useEffect, useState, useMemo } from 'react';
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Legend,
  Tooltip,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  TooltipProps,
} from 'recharts';

type ProjectSummary = {
  projectName: string;
  totalScans: number;
  totalVulns: number;
  severityCount: Record<string, number>;
  images: ImageSummary[];
  lastScan: string;
};

type ScanSummary = {
  filename: string;
  size: number;
  modifiedAt: string;
  artifactName?: string;
  projectName?: string;
  imageName?: string;
  tag?: string;
  totalVulns: number;
  severityCount: Record<string, number>;
};

type ImageSummary = {
  imageName: string;
  totalVulns: number;
  severityCount: Record<string, number>;
  lastScan: string;
  scans: ScanSummary[]; // All scans for this image
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

// Custom tooltip for the unified timeline chart: show only series that have numeric value at this point
const TimelineTooltip: React.FC<TooltipProps<number, string>> = ({ active, payload, label }) => {
  if (!active || !payload || !payload.length) return null;

  // Only show series which have a numeric value at this point (skip null/undefined)
  const visible = payload.filter((item) => typeof item.value === 'number');
  if (!visible.length) return null;

  return (
    <div
      style={{
        backgroundColor: '#1e1e2e',
        border: '1px solid #313244',
        borderRadius: 8,
        padding: '8px 12px',
        boxShadow: '0 4px 12px rgba(0,0,0,0.4)',
        pointerEvents: 'none',
      }}
    >
      <div style={{ fontSize: 12, marginBottom: 4, color: '#cdd6f4' }}>{label}</div>
      {visible.map((item) => (
        <div key={String(item.dataKey)} style={{ fontSize: 12, color: item.color || '#cdd6f4' }}>
          <span>{item.name}</span>
          {': '}
          <strong>{item.value}</strong>
          <span> açık</span>
        </div>
      ))}
    </div>
  );
};

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
  const [allScans, setAllScans] = useState<ScanSummary[]>([]);

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

  // Fetch all scans for timeline chart
  useEffect(() => {
    if (!API_BASE) return;
    fetch(`${API_BASE}/api/scans`)
      .then(async (res) => {
        if (!res.ok) {
          throw new Error(`API error: ${res.status}`);
        }
        return res.json();
      })
      .then((data: ScanSummary[]) => {
        setAllScans(data);
      })
      .catch((err) => {
        console.error('Failed to load scans:', err);
      });
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

  // Load vulnerabilities for expanded scans (only for .json filenames)
  useEffect(() => {
    if (!API_BASE || !projectDetails) return;

    expandedImages.forEach((identifier) => {
      // Only load if it's a filename (contains .json), not an image name
      if (!identifier.includes('.json')) return;
      
      // Skip if already loaded
      if (imageVulnDetails[identifier] || loadingImageDetails[identifier]) return;

      setLoadingImageDetails((prev) => ({ ...prev, [identifier]: true }));
      
      // URL encode the path to handle subdirectories (e.g., "trivy-dashboard/backend.json")
      // Split by / and encode each segment, then join back
      const encodedPath = identifier
        .split('/')
        .map(segment => encodeURIComponent(segment))
        .join('/');
      
      fetch(`${API_BASE}/api/scans/${encodedPath}`)
        .then(async (res) => {
          if (!res.ok) {
            throw new Error(`API error: ${res.status}`);
          }
          return res.json();
        })
        .then((data: { vulnerabilities: Vulnerability[] }) => {
          setImageVulnDetails((prev) => ({
            ...prev,
            [identifier]: data.vulnerabilities || []
          }));
        })
        .catch((err) => {
          console.error('Failed to load details:', err);
          setImageVulnDetails((prev) => ({ ...prev, [identifier]: [] }));
        })
        .finally(() => {
          setLoadingImageDetails((prev) => ({ ...prev, [identifier]: false }));
        });
    });
  }, [expandedImages, API_BASE, projectDetails]);

  // Calculate overall statistics - aggregate from backend project summaries
  const overallStats = useMemo(() => {
    const totalProjects = projects.length;
    const totalScans = projects.reduce((sum, p) => sum + p.totalScans, 0);

    // En güncel açık sayılarını, her proje için her imajın "son taraması"na göre hesapla
    type LatestProjectStats = {
      totalVulns: number;
      severityCount: Record<string, number>;
    };

    const projectImageLatestScan: Record<string, Record<string, ScanSummary>> = {};

    allScans.forEach((scan) => {
      if (!scan.projectName || !scan.imageName) return;
      const proj = scan.projectName;
      const img = scan.imageName;

      if (!projectImageLatestScan[proj]) {
        projectImageLatestScan[proj] = {};
      }

      const existing = projectImageLatestScan[proj][img];
      if (
        !existing ||
        new Date(scan.modifiedAt).getTime() > new Date(existing.modifiedAt).getTime()
      ) {
        projectImageLatestScan[proj][img] = scan;
      }
    });

    const severityCount: Record<string, number> = {};
    let totalVulns = 0;

    projects.forEach((p) => {
      const perImage = projectImageLatestScan[p.projectName];
      if (!perImage) {
        return;
      }

      Object.values(perImage).forEach((scan) => {
        totalVulns += scan.totalVulns;
        Object.keys(scan.severityCount).forEach((severity) => {
          severityCount[severity] =
            (severityCount[severity] || 0) + scan.severityCount[severity];
        });
      });
    });

    return { totalProjects, totalScans, totalVulns, severityCount };
  }, [projects, allScans]);

  // Filter projects based on search query
  const filteredProjects = useMemo(() => {
    if (!searchQuery.trim()) return projects;
    const query = searchQuery.toLowerCase();
    return projects.filter((p) => p.projectName.toLowerCase().includes(query));
  }, [projects, searchQuery]);

  // Filter projects by selected severity (for dashboard)
  const projectsBySeverity = useMemo(() => {
    if (!selectedSeverity) return [];

    // Her proje için en son taramalardan severity hesaplamak için overallStats'taki aynı yapıyı kullan
    const projectImageLatestScan: Record<string, Record<string, ScanSummary>> = {};

    allScans.forEach((scan) => {
      if (!scan.projectName || !scan.imageName) return;
      const proj = scan.projectName;
      const img = scan.imageName;

      if (!projectImageLatestScan[proj]) {
        projectImageLatestScan[proj] = {};
      }
      const existing = projectImageLatestScan[proj][img];
      if (
        !existing ||
        new Date(scan.modifiedAt).getTime() > new Date(existing.modifiedAt).getTime()
      ) {
        projectImageLatestScan[proj][img] = scan;
      }
    });

    return projects.filter((p) => {
      const perImage = projectImageLatestScan[p.projectName];
      if (!perImage) return false;

      let totalForSeverity = 0;
      Object.values(perImage).forEach((scan) => {
        totalForSeverity += scan.severityCount[selectedSeverity] || 0;
      });
      return totalForSeverity > 0;
    });
  }, [projects, selectedSeverity, allScans]);

  // Prepare pie chart data for severity distribution
  const pieChartData = useMemo(() => {
    const data = [
      { name: 'CRITICAL', value: overallStats.severityCount['CRITICAL'] || 0, color: '#f38ba8' },
      { name: 'HIGH', value: overallStats.severityCount['HIGH'] || 0, color: '#fab387' },
      { name: 'MEDIUM', value: overallStats.severityCount['MEDIUM'] || 0, color: '#f9e2af' },
      { name: 'LOW', value: overallStats.severityCount['LOW'] || 0, color: '#89b4fa' },
    ].filter(item => item.value > 0);
    return data;
  }, [overallStats.severityCount]);

  // Prepare unified timeline chart data
  // Her satır "Proje - İmaj" ikilisi olacak şekilde ayrıştırılır,
  // her tarama ayrı bir nokta olarak gösterilir (iniş/çıkışları görebilmek için).
  const unifiedTimelineData = useMemo(() => {
    // Get unique series names (project-image)
    const seriesNames = Array.from(
      new Set(
        allScans
          .filter((s) => s.projectName)
          .map((s) => {
            if (s.imageName) {
              return `${s.projectName} - ${s.imageName}`;
            }
            return s.projectName as string;
          })
      )
    );
    const projectColors = [
      '#89b4fa', // blue
      '#f38ba8', // red
      '#a6e3a1', // green
      '#fab387', // peach
      '#cba6f7', // mauve
      '#f9e2af', // yellow
      '#94e2d5', // teal
      '#f5c2e7', // pink
    ];

    if (allScans.length === 0 || seriesNames.length === 0) {
      return { data: [], projectNames: seriesNames, projectColors };
    }

    // Zaman içinde tüm taramaları, tarih+saat bazlı noktalara dönüştür
    const sortedScans = [...allScans].sort(
      (a, b) => new Date(a.modifiedAt).getTime() - new Date(b.modifiedAt).getTime()
    );

    // Aynı zaman damgasına sahip çoklu taramalar için birleştirme yap
    const dataMap = new Map<string, Record<string, string | number | null>>();

    sortedScans.forEach((scan) => {
      if (!scan.projectName) return;

      const seriesKey = scan.imageName
        ? `${scan.projectName} - ${scan.imageName}`
        : (scan.projectName as string);

      const d = new Date(scan.modifiedAt);
      const key = d.toISOString(); // benzersiz zaman damgası

      if (!dataMap.has(key)) {
        const entry: Record<string, string | number | null> = {
          date: d.toLocaleString('tr-TR', {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
          }),
        };
        // Her seri için başlangıçta null ver (sadece veri olan seriler tooltip'te görünsün)
        seriesNames.forEach((name) => {
          entry[name] = null;
        });
        dataMap.set(key, entry);
      }

      const entry = dataMap.get(key)!;
      entry[seriesKey] = scan.totalVulns;
    });

    const data = Array.from(dataMap.entries())
      .sort(([a], [b]) => (a < b ? -1 : 1))
      .map(([, value]) => value);

    return { data, projectNames: seriesNames, projectColors };
  }, [allScans]);

  // Project-specific timeline data (only for selected project on detail page)
  const projectTimelineData = useMemo(() => {
    if (!selectedProject) {
      return { data: [], seriesNames: [] as string[] };
    }

    const projectScans = allScans.filter((s) => s.projectName === selectedProject);
    if (projectScans.length === 0) {
      return { data: [], seriesNames: [] as string[] };
    }

    const seriesNames = Array.from(
      new Set(
        projectScans.map((s) =>
          s.imageName ? `${s.projectName} - ${s.imageName}` : (s.projectName as string)
        )
      )
    );

    // Zaman içinde bu projeye ait tüm taramaları noktaya dönüştür
    const sortedScans = [...projectScans].sort(
      (a, b) => new Date(a.modifiedAt).getTime() - new Date(b.modifiedAt).getTime()
    );

    const dataMap = new Map<string, Record<string, string | number | null>>();

    sortedScans.forEach((scan) => {
      const seriesKey = scan.imageName
        ? `${scan.projectName} - ${scan.imageName}`
        : (scan.projectName as string);

      const d = new Date(scan.modifiedAt);
      const key = d.toISOString();

      if (!dataMap.has(key)) {
        const entry: Record<string, string | number | null> = {
          date: d.toLocaleString('tr-TR', {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
          }),
        };
        // Başlangıçta tüm seriler için null verelim; sadece o anda taraması olan seriler çizilsin
        seriesNames.forEach((name) => {
          entry[name] = null;
        });
        dataMap.set(key, entry);
      }

      const entry = dataMap.get(key)!;
      entry[seriesKey] = scan.totalVulns;
    });

    const data = Array.from(dataMap.entries())
      .sort(([a], [b]) => (a < b ? -1 : 1))
      .map(([, value]) => value);

    return { data, seriesNames };
  }, [allScans, selectedProject]);

  if (currentPage === 'project-detail' && projectDetails) {
    return (
      <div className="min-h-screen bg-catppuccin-base text-catppuccin-text">
        <header className="border-b border-catppuccin-surface0 bg-catppuccin-mantle/70 backdrop-blur">
          <div className="mx-auto flex max-w-5xl items-center justify-between px-4 py-3">
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-2 text-sm">
                <button
                  onClick={() => {
                    setCurrentPage('dashboard');
                    setSelectedProject(null);
                    setProjectDetails(null);
                    setExpandedImages(new Set());
                    setImageVulnDetails({});
                    setLoadingImageDetails({});
                  }}
                  className="px-3 py-1.5 rounded border border-catppuccin-surface1 hover:bg-catppuccin-surface0 hover:border-catppuccin-teal text-catppuccin-text transition-colors font-medium"
                >
                  Ana Sayfa
                </button>
                <span className="text-catppuccin-overlay1">/</span>
                <button
                  onClick={() => {
                    setCurrentPage('projects');
                    setSelectedProject(null);
                    setProjectDetails(null);
                    setExpandedImages(new Set());
                    setImageVulnDetails({});
                    setLoadingImageDetails({});
                  }}
                  className="px-3 py-1.5 rounded border border-catppuccin-surface1 hover:bg-catppuccin-surface0 hover:border-catppuccin-teal text-catppuccin-text transition-colors font-medium"
                >
                  Projeler
                </button>
                <span className="text-catppuccin-overlay1">/</span>
                <span className="px-3 py-1.5 rounded bg-catppuccin-teal/10 text-catppuccin-teal font-semibold">
                  {projectDetails.projectName}
                </span>
              </div>
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

          {/* Project-specific timeline chart */}
          <section className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
            <h2 className="text-sm font-semibold text-catppuccin-text mb-4">
              {projectDetails.projectName} – Açık Sayısı Zaman Çizelgesi
            </h2>
            {projectTimelineData.data.length > 0 ? (
              <>
                <ResponsiveContainer width="100%" height={260}>
                  <LineChart data={projectTimelineData.data}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#313244" />
                    <XAxis
                      dataKey="date"
                      stroke="#6c7086"
                      style={{ fontSize: '10px' }}
                      angle={-35}
                      textAnchor="end"
                      height={70}
                    />
                    <YAxis
                      stroke="#6c7086"
                      style={{ fontSize: '11px' }}
                      label={{
                        value: 'Açık Sayısı',
                        angle: -90,
                        position: 'insideLeft',
                        style: { fontSize: '11px', fill: '#6c7086' },
                      }}
                    />
                    <Tooltip content={<TimelineTooltip />} />
                    {projectTimelineData.seriesNames.map((seriesName, index) => (
                      <Line
                        key={seriesName}
                        type="monotone"
                        dataKey={seriesName}
                        stroke={
                          unifiedTimelineData.projectColors[
                            index % unifiedTimelineData.projectColors.length
                          ]
                        }
                        strokeWidth={2}
                        dot={{
                          fill:
                            unifiedTimelineData.projectColors[
                              index % unifiedTimelineData.projectColors.length
                            ],
                          r: 4,
                        }}
                        activeDot={{ r: 6 }}
                        connectNulls
                        name={seriesName}
                      />
                    ))}
                  </LineChart>
                </ResponsiveContainer>
                <div className="mt-3 flex flex-wrap gap-3 text-xs text-catppuccin-overlay1">
                  {projectTimelineData.seriesNames.map((seriesName, index) => (
                    <div key={seriesName} className="flex items-center gap-2">
                      <div
                        className="w-3 h-3 rounded"
                        style={{
                          backgroundColor:
                            unifiedTimelineData.projectColors[
                              index % unifiedTimelineData.projectColors.length
                            ],
                        }}
                      ></div>
                      <span>{seriesName}</span>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <div className="flex items-center justify-center h-[260px] text-catppuccin-overlay1 text-sm">
                Bu proje için henüz zaman çizelgesi oluşturulacak tarama verisi yok.
              </div>
            )}
          </section>

          <section className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
            <h2 className="text-sm font-semibold text-catppuccin-text mb-4">İmajlar ve Taramalar</h2>

            {projectDetails.images.length === 0 ? (
              <div className="text-center py-8 text-catppuccin-overlay1">Henüz tarama bulunamadı.</div>
            ) : (
              <div className="space-y-4">
                {projectDetails.images.map((image) => {
                  const isExpanded = expandedImages.has(image.imageName);
                  const { grade, color } = calculateGrade(image.severityCount);
                  const toggleExpand = (e: React.MouseEvent) => {
                    e.stopPropagation();
                    setExpandedImages((prev) => {
                      const newSet = new Set(prev);
                      if (newSet.has(image.imageName)) {
                        newSet.delete(image.imageName);
                      } else {
                        newSet.add(image.imageName);
                      }
                      return newSet;
                    });
                  };

                  return (
                    <div key={image.imageName} className="space-y-0">
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
                                {image.scans.length} tarama • Son tarama:{' '}
                                {new Date(image.lastScan).toLocaleString()}
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
                          {isExpanded ? 'Tarama Geçmişini Gizle ↑' : 'Tarama Geçmişini Göster ↓'}
                        </button>
                      </div>

                      {isExpanded && (
                        <div className="mt-2 border border-catppuccin-surface0 rounded-lg p-4 bg-catppuccin-mantle/60">
                          <h4 className="text-sm font-semibold text-catppuccin-text mb-3">
                            Tarama Geçmişi ({image.scans.length} tarama)
                          </h4>
                          <div className="space-y-2">
                            {image.scans.map((scan) => {
                              const scanGrade = calculateGrade(scan.severityCount);
                              const isScanExpanded = expandedImages.has(scan.filename);
                              const toggleScanExpand = (e: React.MouseEvent) => {
                                e.stopPropagation();
                                setExpandedImages((prev) => {
                                  const newSet = new Set(prev);
                                  if (newSet.has(scan.filename)) {
                                    newSet.delete(scan.filename);
                                  } else {
                                    newSet.add(scan.filename);
                                  }
                                  return newSet;
                                });
                              };

                              return (
                                <div key={scan.filename} className="space-y-0">
                                  <div
                                    className="border border-catppuccin-surface0 rounded-lg p-3 bg-catppuccin-base/60 cursor-pointer hover:bg-catppuccin-base/80 transition-colors"
                                    onClick={toggleScanExpand}
                                  >
                                    <div className="flex items-center justify-between">
                                      <div className="flex items-center gap-3">
                                        <div
                                          className={`w-10 h-10 rounded flex items-center justify-center text-sm font-bold ${
                                            scanGrade.color === 'catppuccin-green'
                                              ? 'bg-catppuccin-green/20 text-catppuccin-green'
                                              : scanGrade.color === 'catppuccin-blue'
                                                ? 'bg-catppuccin-blue/20 text-catppuccin-blue'
                                                : scanGrade.color === 'catppuccin-yellow'
                                                  ? 'bg-catppuccin-yellow/20 text-catppuccin-yellow'
                                                  : 'bg-catppuccin-red/20 text-catppuccin-red'
                                          }`}
                                        >
                                          {scanGrade.grade}
                                        </div>
                                        <div>
                                          <p className="text-sm font-semibold text-catppuccin-text">
                                            {scan.artifactName || 
                                             (scan.imageName 
                                               ? `${scan.imageName}${scan.tag ? ':' + scan.tag : ''}` 
                                               : scan.filename)}
                                          </p>
                                          <p className="text-xs text-catppuccin-overlay1 mt-0.5">
                                            {new Date(scan.modifiedAt).toLocaleString()}
                                          </p>
                                        </div>
                                      </div>
                                      <div className="flex items-center gap-4 text-xs">
                                        <div className="text-right">
                                          <span className="text-catppuccin-overlay1">Toplam: </span>
                                          <span className="font-semibold text-catppuccin-text">
                                            {scan.totalVulns}
                                          </span>
                                        </div>
                                        <div className="flex gap-2">
                                          {scan.severityCount['CRITICAL'] > 0 && (
                                            <span className="text-catppuccin-red font-semibold">
                                              C:{scan.severityCount['CRITICAL']}
                                            </span>
                                          )}
                                          {scan.severityCount['HIGH'] > 0 && (
                                            <span className="text-catppuccin-peach font-semibold">
                                              H:{scan.severityCount['HIGH']}
                                            </span>
                                          )}
                                          {scan.severityCount['MEDIUM'] > 0 && (
                                            <span className="text-catppuccin-yellow font-semibold">
                                              M:{scan.severityCount['MEDIUM']}
                                            </span>
                                          )}
                                          {scan.severityCount['LOW'] > 0 && (
                                            <span className="text-catppuccin-blue font-semibold">
                                              L:{scan.severityCount['LOW']}
                                            </span>
                                          )}
                                        </div>
                                        <button
                                          onClick={toggleScanExpand}
                                          className="text-xs px-2 py-1 rounded border border-catppuccin-surface1 hover:bg-catppuccin-surface0 text-catppuccin-subtext0"
                                        >
                                          {isScanExpanded ? '↑' : '↓'}
                                        </button>
                                      </div>
                                    </div>
                                  </div>

                                  {isScanExpanded && (
                                    <div className="mt-1 ml-4 border-l-2 border-catppuccin-surface0 pl-3">
                                      {loadingImageDetails[scan.filename] ? (
                                        <div className="text-center py-4 text-catppuccin-overlay1 text-xs">
                                          Yükleniyor...
                                        </div>
                                      ) : (imageVulnDetails[scan.filename] || []).length === 0 ? (
                                        <div className="text-center py-4 text-catppuccin-overlay1 text-xs">
                                          Bu raporda açık bulunamadı.
                                        </div>
                                      ) : (
                                        <div className="space-y-2 max-h-[400px] overflow-y-auto">
                                          {(imageVulnDetails[scan.filename] || []).map((vuln, idx) => {
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
                                                className="border border-catppuccin-surface0 rounded p-3 bg-catppuccin-base/40"
                                              >
                                                <div className="flex items-start justify-between mb-1">
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
                                                <h4 className="text-xs font-semibold text-catppuccin-text mb-1">
                                                  {vuln.Title || vuln.VulnerabilityID}
                                                </h4>
                                                <div className="text-xs text-catppuccin-overlay1">
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
            <div className="flex items-center gap-3">
              <button
                onClick={() => setCurrentPage('dashboard')}
                className="px-3 py-1.5 rounded border border-catppuccin-surface1 hover:bg-catppuccin-surface0 hover:border-catppuccin-teal text-catppuccin-text transition-colors font-medium"
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
                {filteredProjects.map((project) => {
                  // Bu projedeki her imajın en son taramalarını allScans üzerinden bul
                  const perImage: Record<string, ScanSummary> = {};
                  allScans.forEach((scan) => {
                    if (scan.projectName !== project.projectName || !scan.imageName) return;
                    const existing = perImage[scan.imageName];
                    if (
                      !existing ||
                      new Date(scan.modifiedAt).getTime() >
                        new Date(existing.modifiedAt).getTime()
                    ) {
                      perImage[scan.imageName] = scan;
                    }
                  });

                  let latestTotalVulns = 0;
                  const latestSeverity: Record<string, number> = {};
                  Object.values(perImage).forEach((scan) => {
                    latestTotalVulns += scan.totalVulns;
                    Object.keys(scan.severityCount).forEach((severity) => {
                      latestSeverity[severity] =
                        (latestSeverity[severity] || 0) + scan.severityCount[severity];
                    });
                  });

                  return (
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
                              {latestTotalVulns}
                            </p>
                          </div>
                          <div className="flex gap-3 text-sm">
                            {latestSeverity['CRITICAL'] > 0 && (
                              <div className="text-center">
                                <p className="text-xs text-catppuccin-overlay1">CRITICAL</p>
                                <p className="text-lg font-semibold text-catppuccin-red">
                                  {latestSeverity['CRITICAL']}
                                </p>
                              </div>
                            )}
                            {latestSeverity['HIGH'] > 0 && (
                              <div className="text-center">
                                <p className="text-xs text-catppuccin-overlay1">HIGH</p>
                                <p className="text-lg font-semibold text-catppuccin-peach">
                                  {latestSeverity['HIGH']}
                                </p>
                              </div>
                            )}
                            {latestSeverity['MEDIUM'] > 0 && (
                              <div className="text-center">
                                <p className="text-xs text-catppuccin-overlay1">MEDIUM</p>
                                <p className="text-lg font-semibold text-catppuccin-yellow">
                                  {latestSeverity['MEDIUM']}
                                </p>
                              </div>
                            )}
                            {latestSeverity['LOW'] > 0 && (
                              <div className="text-center">
                                <p className="text-xs text-catppuccin-overlay1">LOW</p>
                                <p className="text-lg font-semibold text-catppuccin-blue">
                                  {latestSeverity['LOW']}
                                </p>
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
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

  // Dashboard page
  return (
    <div className="min-h-screen bg-catppuccin-base text-catppuccin-text">
      <header className="border-b border-catppuccin-surface0 bg-catppuccin-mantle/70 backdrop-blur">
        <div className="mx-auto flex max-w-5xl items-center justify-between px-4 py-3">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setCurrentPage('projects')}
              className="px-3 py-1.5 rounded border border-catppuccin-surface1 hover:bg-catppuccin-surface0 hover:border-catppuccin-teal text-catppuccin-text transition-colors font-medium"
            >
              Projeler →
            </button>
            <span className="rounded bg-catppuccin-teal/10 px-2 py-1 text-xs font-semibold uppercase tracking-wide text-catppuccin-teal">
              Trivy
            </span>
            <span className="text-lg font-semibold">Dashboard</span>
          </div>
          <span className="text-xs text-catppuccin-overlay1">Prototype UI</span>
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
          </div>
        </section>

        {/* Charts Section */}
        <section className="grid gap-4 md:grid-cols-2">
          {/* Pie Chart - Severity Distribution */}
          <div className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
            <h2 className="text-sm font-semibold text-catppuccin-text mb-4">Severity Dağılımı (En Son Taramalar)</h2>
            {pieChartData.length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={pieChartData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {pieChartData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      // Açık, neredeyse beyaz tooltip arka planı
                      backgroundColor: '#eff1f5',
                      border: '1px solid #313244',
                      borderRadius: '8px',
                      color: '#11111b',
                    }}
                    labelStyle={{
                      color: '#1e1e2e',
                      fontWeight: 600,
                    }}
                    wrapperStyle={{ outline: 'none' }}
                  />
                  <Legend 
                    wrapperStyle={{ color: '#cdd6f4', fontSize: '12px' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-[300px] text-catppuccin-overlay1">
                Henüz veri yok
              </div>
            )}
          </div>

          {/* Unified Timeline Chart - All Projects */}
          <div className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
            <h2 className="text-sm font-semibold text-catppuccin-text mb-4">
              Tüm Projeler - Günlük Açık Sayısı Zaman Çizelgesi
            </h2>
            {unifiedTimelineData.data.length > 0 ? (
              <>
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={unifiedTimelineData.data}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#313244" />
                    <XAxis
                      dataKey="date"
                      stroke="#6c7086"
                      style={{ fontSize: '10px' }}
                      angle={-35}
                      textAnchor="end"
                      height={80}
                    />
                    <YAxis 
                      stroke="#6c7086"
                      style={{ fontSize: '11px' }}
                      label={{ value: 'Açık Sayısı', angle: -90, position: 'insideLeft', style: { fontSize: '11px', fill: '#6c7086' } }}
                    />
                    <Tooltip content={<TimelineTooltip />} />
                    {unifiedTimelineData.projectNames.map((projectName, index) => (
                      <Line
                        key={projectName}
                        type="monotone"
                        dataKey={projectName}
                        stroke={
                          unifiedTimelineData.projectColors[
                            index % unifiedTimelineData.projectColors.length
                          ]
                        }
                        strokeWidth={2}
                        dot={{
                          fill:
                            unifiedTimelineData.projectColors[
                              index % unifiedTimelineData.projectColors.length
                            ],
                          r: 4,
                        }}
                        activeDot={{ r: 6 }}
                        connectNulls
                        name={projectName}
                      />
                    ))}
                  </LineChart>
                </ResponsiveContainer>
                <div className="mt-3 flex flex-wrap gap-3 text-xs text-catppuccin-overlay1">
                  {unifiedTimelineData.projectNames.map((projectName, index) => (
                    <div key={projectName} className="flex items-center gap-2">
                      <div 
                        className="w-3 h-3 rounded" 
                        style={{ backgroundColor: unifiedTimelineData.projectColors[index % unifiedTimelineData.projectColors.length] }}
                      ></div>
                      <span>{projectName}</span>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <div className="flex items-center justify-center h-[300px] text-catppuccin-overlay1">
                Henüz veri yok
              </div>
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
                          {/* Seçili severity listesinde de son taramalara göre toplam açık gösterilir */}
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
