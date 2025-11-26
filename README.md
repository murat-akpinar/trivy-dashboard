# Trivy Dashboard

Trivy güvenlik tarama sonuçlarını toplayıp görselleştiren bir web dashboard uygulaması. CI/CD ortamlarında (Jenkins vb.) üretilen Trivy JSON çıktılarını tek bir merkezde toplayıp, SonarQube benzeri bir arayüz üzerinden kolayca incelemenizi sağlar.

---

## Özellikler

- **Proje Bazlı Görünüm**: Her proje için tüm imajların (backend, frontend, vs.) taramalarını tek sayfada görüntüleme
- **Severity Filtreleme**: CRITICAL, HIGH, MEDIUM, LOW severity'lerine göre projeleri filtreleme
- **Harf Notu Sistemi**: Her imaj için otomatik güvenlik notu (A, B, C, D) - severity sayılarına göre hesaplanır
- **Detaylı Vulnerability Listesi**: Her vulnerability için ID, açıklama, fixed version ve detay linkleri
- **Genel Dashboard**: Tüm projelerin toplam istatistiklerini görüntüleme
- **Arama Özelliği**: Proje listesinde arama yapma
- **Docker Compose Desteği**: Tek komutla çalıştırma
- **Catppuccin Mocha Tema**: Modern ve göz yormayan dark theme
- **Cascadia Mono Font**: Monospace font desteği

---

## Teknoloji Stack

- **Backend**: Go 1.23 + chi router + CORS
- **Frontend**: React 18 + Vite + TypeScript + TailwindCSS
- **Containerization**: Docker + Docker Compose
- **Web Server**: Nginx (frontend), Go HTTP server (backend)

---

## Hızlı Başlangıç

### Gereksinimler

- Docker ve Docker Compose
- Trivy (test için)

### Kurulum

1. Projeyi klonlayın:
```bash
git clone git@github.com:murat-akpinar/Trivy-Dashboard.git
cd trivy-dashboard
```

2. (Opsiyonel) Environment değişkenlerini ayarlayın:
```bash
cp .example.env .env
# .env dosyasını ihtiyacınıza göre düzenleyin
```

3. Container'ları başlatın:
```bash
docker compose up -d --build
```

4. Dashboard'a erişin:
- Frontend: http://localhost:3000 (veya `.env` dosyasındaki `FRONTEND_PORT`)
- Backend API: http://localhost:8180 (veya `.env` dosyasındaki `BACKEND_PORT`)

---

## Environment Variables

Projeyi özelleştirmek için `.env` dosyası oluşturabilirsiniz:

```bash
cp .example.env .env
```

### Mevcut Değişkenler

- `BACKEND_PORT`: Backend'in host'ta dinleyeceği port (varsayılan: 8180)
- `FRONTEND_PORT`: Frontend'in host'ta dinleyeceği port (varsayılan: 3000)
- `EXPORT_DIR`: Trivy JSON raporlarının bulunduğu klasör (varsayılan: ./export)
- `VITE_API_BASE`: Frontend'in backend API'sine erişmek için kullanacağı URL (varsayılan: http://localhost:8180)
- `TZ`: Timezone (varsayılan: Europe/Istanbul)

**Not**: `.env` dosyası Git'e eklenmez (`.gitignore`'da). `.example.env` dosyası template olarak kullanılır.

---

## Kullanım

### Dosya Adı Formatı

Trivy JSON raporlarını `export/` klasörüne koyarken şu formatı kullanın:

```
{proje-ismi}-{imaj-ismi}.json
```

**Örnekler:**
- `trivy-dashboard-backend.json` → Proje: `trivy-dashboard`, İmaj: `backend`
- `trivy-dashboard-frontend.json` → Proje: `trivy-dashboard`, İmaj: `frontend`
- `my-service-api.json` → Proje: `my-service`, İmaj: `api`

### Jenkins Pipeline Örneği

```bash
# Trivy taraması yap ve JSON çıktısı al
trivy image --format json -o /tmp/my-project-backend.json my-project-backend:latest

# Dashboard sunucusuna gönder
scp /tmp/my-project-backend.json user@dashboard-host:/path/to/trivy-dashboard/export/
```

### Docker ile Test

```bash
# Backend image'ini tara
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/export:/output \
  aquasec/trivy:latest image \
  --format json -o /output/trivy-dashboard-backend.json \
  trivy-dashboard-backend:latest

# Frontend image'ini tara
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/export:/output \
  aquasec/trivy:latest image \
  --format json -o /output/trivy-dashboard-frontend.json \
  trivy-dashboard-frontend:latest
```

---

## API Endpoints

### Backend API (http://localhost:8180)

- `GET /` - Backend durum bilgisi
- `GET /health` - Health check
- `GET /api/projects` - Tüm projelerin listesi (severity özetleri ile)
- `GET /api/projects/{projectName}` - Belirli bir projenin detayları
- `GET /api/scans` - Tüm taramaların listesi
- `GET /api/scans/{filename}` - Belirli bir taramanın vulnerability detayları

---

## Proje Yapısı

```
trivy-dashboard/
├── backend/
│   ├── main.go          # Go backend kodu
│   ├── go.mod           # Go dependencies
│   └── Dockerfile       # Backend container
├── frontend/
│   ├── src/
│   │   └── App.tsx      # React ana component
│   ├── package.json     # npm dependencies
│   └── Dockerfile       # Frontend container
├── export/              # Trivy JSON raporları buraya konur
├── docker-compose.yml   # Container orchestration
└── README.md
```

---

## Özellikler Detayı

### Ana Sayfa (Dashboard)

- **Genel İstatistikler**: Toplam proje, toplam tarama, toplam açık sayıları
- **Severity Kartları**: CRITICAL, HIGH, MEDIUM, LOW sayıları (tıklanabilir)
- **Severity Filtreleme**: Severity kartına tıklayınca o severity'ye sahip projeleri listeleme

### Projeler Sayfası

- **Proje Listesi**: Tüm projeler severity özetleri ile
- **Arama Kutusu**: Proje adına göre filtreleme
- **Proje Detayı**: Projeye tıklayınca o projenin tüm imajlarını görüntüleme

### Proje Detay Sayfası

- **İmaj Listesi**: Projenin tüm imajları (backend, frontend, vs.)
- **Tarama Özetleri**: Her imaj için son tarama tarihi ve açık sayıları
- **Vulnerability Detayları**: "Açıkları Görüntüle" butonu ile detaylı liste
- **Harf Notu Sistemi**: Her imaj için otomatik güvenlik notu (A, B, C, D)

#### Harf Notu Matrisi

Dashboard, her imaj için severity sayılarına göre otomatik olarak bir harf notu hesaplar:

| Not | Koşullar | Renk | Açıklama |
|-----|----------|------|----------|
| **A** | CRITICAL = 0<br>HIGH ≤ 2<br>MEDIUM ≤ 5 | 🟢 Yeşil | Mükemmel güvenlik durumu |
| **B** | CRITICAL = 0<br>HIGH ≤ 5<br>MEDIUM ≤ 10 | 🔵 Mavi | İyi güvenlik durumu |
| **C** | CRITICAL ≤ 2<br>HIGH ≤ 8<br>MEDIUM ≤ 15 | 🟡 Sarı | Orta seviye güvenlik riski |
| **D** | Diğer durumlar<br>(CRITICAL > 2 veya<br>HIGH > 8 veya<br>MEDIUM > 15) | 🔴 Kırmızı | Yüksek güvenlik riski |

**Örnekler:**
- 0 CRITICAL, 2 HIGH, 3 MEDIUM → **A** (Yeşil)
- 0 CRITICAL, 4 HIGH, 8 MEDIUM → **B** (Mavi)
- 1 CRITICAL, 5 HIGH, 10 MEDIUM → **C** (Sarı)
- 4 CRITICAL, 5 MEDIUM, 2 LOW, 1 HIGH → **D** (Kırmızı)

**Not**: LOW severity sayıları harf notu hesaplamasına dahil edilmez, sadece bilgilendirme amaçlı gösterilir.

---

## Güvenlik

- Backend ve frontend dependencies güncel tutulur
- Alpine Linux base image'leri güvenlik güncellemeleri ile güncellenir
- `npm audit` ve `go mod` ile düzenli güvenlik kontrolleri yapılır

---

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

### Container'ları Yeniden Build Etme

```bash
# Tüm container'ları sıfırdan build et
docker compose down --rmi all
docker compose build
docker compose up -d
```

---

## Lisans

GPL-3.0

---

## Katkıda Bulunma

Pull request'ler memnuniyetle karşılanır. Büyük değişiklikler için önce bir issue açarak neyi değiştirmek istediğinizi tartışın.

---

## İletişim

Proje sahibi: [murat-akpinar](https://github.com/murat-akpinar)
