# Trivy Dashboard

[🇺🇸 English](README_EN.md) | [🇹🇷 Türkçe](README.md)

Trivy güvenlik tarama sonuçlarını toplayıp görselleştiren web dashboard uygulaması. CI/CD ortamlarında üretilen Trivy JSON çıktılarını tek bir merkezde toplayıp, kolayca incelemenizi sağlar.

![Dashboard](/images/dashboard.png)
![Project](/images/project.png)

## Özellikler

- **Proje Bazlı Görünüm**: Her proje için tüm Docker imajlarının taramalarını tek sayfada görüntüleme
- **Severity Filtreleme**: CRITICAL, HIGH, MEDIUM, LOW seviyelerine göre projeleri filtreleme
- **Harf Notu Sistemi**: Her imaj için otomatik güvenlik notu (A, B, C, D)
- **Detaylı Vulnerability Listesi**: Her açık için ID, açıklama, fixed version ve detay linkleri
- **Zaman Çizelgesi**: Taramaların zaman içindeki değişimini görselleştirme
- **Genel Dashboard**: Tüm projelerin toplam istatistiklerini görüntüleme

## Hızlı Başlangıç

### Gereksinimler

- Docker ve Docker Compose

### Kurulum

1. Projeyi klonlayın:
```bash
git clone git@github.com:murat-akpinar/Trivy-Dashboard.git
cd trivy-dashboard
```

2. Container'ları başlatın:
```bash
docker compose up -d --build
```

3. Dashboard'a erişin:
- Frontend: http://localhost:3000
- Backend API: http://localhost:8180

## Trivy Tarama Sonuçlarını Ekleme

### Dosya Formatı

Trivy JSON raporlarını `export/` klasörüne koyun. Backend, dosya adından veya JSON içindeki `ArtifactName` alanından proje, imaj ve tag bilgisini otomatik olarak çıkarır.

**Desteklenen Formatlar:**

1. **Düz Yapı** (Flat):
   ```
   export/{proje}-{imaj}.json
   export/{proje}-{imaj}-{YYYYMMDD-HHMMSS}.json
   ```
   Örnek: `export/trivy-dashboard-backend-20251126-182000.json`

2. **Dizin Yapısı** (Önerilen):
   ```
   export/{proje}/{imaj}.json
   export/{proje}/{imaj}-{YYYYMMDD-HHMMSS}.json
   ```
   Örnek: `export/trivy-dashboard/backend-20251126-182000.json`

3. **ArtifactName ile Otomatik Parse** (En Kolay):
   JSON dosyasının içindeki `ArtifactName` alanından otomatik parse edilir:
   - `ArtifactName: "trivy-dashboard-backend:latest"` → Proje: `trivy-dashboard`, İmaj: `backend`, Tag: `latest`

### Docker ile Test Taraması

Backend ve frontend için hazır scriptler:
```bash
./scan-backend.sh
./scan-frontend.sh
```

Manuel tarama:
```bash
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/export:/output \
  aquasec/trivy:latest image \
  --format json -o /output/trivy-dashboard/backend-${TIMESTAMP}.json \
  trivy-dashboard-backend:latest
```

### CI/CD Entegrasyonu (Jenkins Örneği)

```bash
# Tarama yap
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
trivy image --format json -o /tmp/backend-${TIMESTAMP}.json my-project-backend:latest

# Dashboard sunucusuna gönder
scp /tmp/backend-${TIMESTAMP}.json user@dashboard-host:/path/to/trivy-dashboard/export/my-project/
```

## Harf Notu Sistemi

Dashboard, her imaj için severity sayılarına göre otomatik olarak bir harf notu hesaplar:

| Not | Koşullar | Açıklama |
|-----|----------|----------|
| **A** | CRITICAL = 0, HIGH ≤ 2, MEDIUM ≤ 5 | Mükemmel |
| **B** | CRITICAL = 0, HIGH ≤ 5, MEDIUM ≤ 10 | İyi |
| **C** | CRITICAL ≤ 2, HIGH ≤ 8, MEDIUM ≤ 15 | Orta risk |
| **D** | Diğer durumlar | Yüksek risk |

## Yapılandırma

Ortam değişkenlerini ayarlamak için `.env` dosyası oluşturun:

```bash
BACKEND_PORT=8180              # Backend portu (varsayılan: 8180)
FRONTEND_PORT=3000             # Frontend portu (varsayılan: 3000)
EXPORT_DIR=./export            # JSON raporlarının klasörü (varsayılan: ./export)
VITE_API_BASE=http://localhost:8180  # Frontend'in backend'e erişimi
TZ=Europe/Istanbul             # Timezone
```

## API Endpoints

### Backend API (http://localhost:8180)

- `GET /` - Backend durum bilgisi
- `GET /health` - Health check
- `GET /api/projects` - Tüm projelerin listesi
- `GET /api/projects/{projectName}` - Proje detayları
- `GET /api/scans` - Tüm taramaların listesi
- `GET /api/scans/{filename}` - Tarama detayları (vulnerability listesi)

## Proje Yapısı

```
trivy-dashboard/
├── backend/           # Go backend
├── frontend/          # React frontend
├── export/            # Trivy JSON raporları (buraya koyun)
├── scan-backend.sh    # Backend tarama scripti
├── scan-frontend.sh   # Frontend tarama scripti
└── docker-compose.yml # Container orchestration
```

## Teknoloji Stack

- **Backend**: Go 1.23 + chi router
- **Frontend**: React 18 + Vite + TypeScript + TailwindCSS
- **Containerization**: Docker + Docker Compose
- **Web Server**: Nginx

## Geliştirme

### Backend Geliştirme

```bash
cd backend
go mod download
go run main.go
```

### Frontend Geliştirme

```bash
cd frontend
npm install
npm run dev
```

### Container'ları Yeniden Build

```bash
docker compose down --rmi all
docker compose build
docker compose up -d
```

## Health Check

Docker Compose, her servis için otomatik health check yapılandırması içerir:
- Backend: `/health` endpoint'ini kontrol eder
- Frontend: Nginx'in ana sayfasını kontrol eder
- Restart Policy: `unless-stopped` - Container çökerse otomatik restart

Health check durumunu kontrol etmek için:
```bash
docker compose ps
```

## Geliştirme Önerileri

### Gelecek Özellikler

- [ ] **Detaylı Karşılaştırma Analizi**: İki tarama arasında hangi açıkların kapandığını/yeni eklendiğini gösterme, delta hesaplama (versiyon içi ve versiyonlar arası karşılaştırma desteği)
- [ ] **Trend Analizi**: Son taramaya göre artış/azalış yüzdeleri, kartlarda trend göstergeleri (↑↓ okları), "Son taramaya göre %X değişti" bilgisi
- [ ] **Versiyon Gruplama Modu**: Zaman çizelgesinde aynı imajın farklı versiyonlarını birleştirme/ayrı gösterme toggle'ı (varsayılan: birleştirilmiş, genel trend için daha kullanışlı)
- [ ] **E-posta Bildirimleri**: Yeni CRITICAL/HIGH açıklar bulunduğunda bildirim gönderme
- [ ] **Export/Import**: Tarama sonuçlarını yedekleme ve geri yükleme
- [ ] **API Authentication**: Backend API'sine erişim kontrolü
- [ ] **Database Entegrasyonu**: SQLite/PostgreSQL ile tarama geçmişini saklama
- [ ] **Webhook Desteği**: CI/CD pipeline'lardan otomatik tarama tetikleme
- [ ] **Filtreleme ve Sıralama**: Vulnerability listesinde gelişmiş filtreleme
- [ ] **Yan Yana Karşılaştırma Modu**: İki tarama sonucunu detaylı olarak yan yana gösterme
- [ ] **Otomatik Temizlik**: Eski tarama dosyalarını otomatik silme (retention policy)

### Mevcut Özellikler

- ✅ Proje bazlı görünüm
- ✅ Severity filtreleme
- ✅ Harf notu sistemi (A, B, C, D)
- ✅ Zaman damgası ile çoklu tarama desteği
- ✅ Okunabilir tarama gösterimi (imaj adı ve tag, dosya adı yerine)
- ✅ Catppuccin Mocha tema
- ✅ Responsive tasarım
- ✅ Docker Compose desteği
- ✅ Zaman çizelgesi grafikleri

## Lisans

GPL-3.0

## Katkıda Bulunma

Pull request'ler memnuniyetle karşılanır. Büyük değişiklikler için önce bir issue açın.

## İletişim

Proje sahibi: [murat-akpinar](https://github.com/murat-akpinar)
