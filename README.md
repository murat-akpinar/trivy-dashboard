# Trivy Dashboard

Trivy güvenlik tarama sonuçlarını toplayıp görselleştiren bir web dashboard uygulaması. CI/CD ortamlarında (Jenkins vb.) üretilen Trivy JSON çıktılarını tek bir merkezde toplayıp, SonarQube benzeri bir arayüz üzerinden kolayca incelemenizi sağlar.


![Dashboard](/images/dashboard.png)
![Project](/images/project.png)
---

## Proje Amacı

- Trivy tarama sonuçlarını (vulnerability, misconfiguration vb.) kullanıcı dostu bir web arayüzünde görüntülemek.
- CI/CD süreçlerinden veya manuel taramalardan çıkan JSON çıktılarının okunabilir ve analiz edilebilir hale getirilmesi.
- Birden fazla proje ve Docker imajının güvenlik durumunu tek bir dashboard üzerinden takip etmek.
- Açıkların önem derecesine (CRITICAL / HIGH / MEDIUM / LOW) göre filtreleme ve sınıflandırma imkânı sağlamak.
- Her imaj için genel güvenlik seviyesini özetleyen "harf notu (A/B/C/D)" sistemi sunmak.
- Projeler arası karşılaştırma yapabilmek ve güvenlik durumunu hızlıca değerlendirebilmek.
- Tarama sonuçlarını düzenli, tekrar erişilebilir ve merkezi bir yapıda saklamak.
- Güvenlik açıklarının detaylarına hızlı erişim, arama ve inceleme kolaylığı sağlamak.
- Kurum içinde güvenlik farkındalığını artırmak ve süreçleri daha şeffaf hale getirmek.

---

## Özellikler

- **Proje Bazlı Görünüm**: Her proje için tüm imajların (backend, frontend, vs.) taramalarını tek sayfada görüntüleme
- **Severity Filtreleme**: CRITICAL, HIGH, MEDIUM, LOW severity'lerine göre projeleri filtreleme
- **Harf Notu Sistemi**: Her imaj için otomatik güvenlik notu (A, B, C, D) - severity sayılarına göre hesaplanır
- **Detaylı Vulnerability Listesi**: Her vulnerability için ID, açıklama, fixed version ve detay linkleri
- **Genel Dashboard**: Tüm projelerin toplam istatistiklerini görüntüleme
- **Arama Özelliği**: Proje listesinde arama yapma
- **Okunabilir Tarama Gösterimi**: Tarama geçmişinde dosya adı yerine imaj adı ve tag bilgisi gösterilir (örn: `backend:latest`)
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

### Health Check ve Otomatik Restart

Docker Compose, her servis için health check yapılandırması içerir:
- **Backend**: `/health` endpoint'ini kontrol eder (30 saniyede bir)
- **Frontend**: Nginx'in ana sayfasını kontrol eder (30 saniyede bir)
- **Restart Policy**: `unless-stopped` - Container çökerse otomatik restart yapar
- **Dependencies**: Frontend, backend'in sağlıklı olmasını bekler (`depends_on`)

Health check başarısız olursa ve container çökerse, Docker otomatik olarak container'ı yeniden başlatır.

**Health Check Durumunu Kontrol Etme:**
```bash
# Container durumlarını görüntüle
docker compose ps

# Health check loglarını görüntüle
docker inspect trivy-dashboard-backend | grep -A 10 Health
docker inspect trivy-dashboard-frontend | grep -A 10 Health
```

---

## Environment Variables

Projeyi özelleştirmek için `.env` dosyası oluşturabilirsiniz:

### Mevcut Değişkenler

- `BACKEND_PORT`: Backend'in host'ta dinleyeceği port (varsayılan: 8180)
- `FRONTEND_PORT`: Frontend'in host'ta dinleyeceği port (varsayılan: 3000)
- `EXPORT_DIR`: Trivy JSON raporlarının bulunduğu klasör (varsayılan: ./export)
- `VITE_API_BASE`: Frontend'in backend API'sine erişmek için kullanacağı URL (varsayılan: http://localhost:8180)
- `TZ`: Timezone (varsayılan: Europe/Istanbul)

---

## Kullanım

### Dosya Adı Formatı

**Önemli:** Backend artık JSON dosyasının içindeki `ArtifactName` alanından proje, imaj ve tag bilgisini otomatik olarak parse ediyor. Bu sayede dosya adı formatından bağımsız olarak çalışır.

**Örnek:** `ArtifactName: "trivy-dashboard-backend:latest"` → Proje: `trivy-dashboard`, İmaj: `backend`, Tag: `latest`

Trivy JSON raporlarını `export/` klasörüne koyarken şu formatları kullanabilirsiniz (dosya adı artık sadece organizasyon için):

#### Yapı 1: Düz Yapı (Flat Structure)

**Format 1: Basit (Tek tarama)**
```
export/{proje-ismi}-{imaj-ismi}.json
```

**Format 2: Zaman Damgası ile (Çoklu tarama)**
```
export/{proje-ismi}-{imaj-ismi}-{YYYYMMDD-HHMMSS}.json
```

**Örnekler:**
- `export/trivy-dashboard-backend.json` → Proje: `trivy-dashboard`, İmaj: `backend`
- `export/trivy-dashboard-backend-20251126-182000.json` → Proje: `trivy-dashboard`, İmaj: `backend` (26 Kasım 2025, 18:20:00)
- `export/trivy-dashboard-frontend.json` → Proje: `trivy-dashboard`, İmaj: `frontend`
- `export/my-service-api-20251126-120000.json` → Proje: `my-service`, İmaj: `api` (26 Kasım 2025, 12:00:00)

#### Yapı 2: Dizin Yapısı (Directory Structure) - Önerilen

**Format 1: Basit (Tek tarama)**
```
export/{proje-ismi}/{imaj-ismi}.json
```

**Format 2: Zaman Damgası ile (Çoklu tarama)**
```
export/{proje-ismi}/{imaj-ismi}-{YYYYMMDD-HHMMSS}.json
```

**Örnekler:**
- `export/trivy-dashboard/backend.json` → Proje: `trivy-dashboard`, İmaj: `backend`
- `export/trivy-dashboard/backend-20251126-182000.json` → Proje: `trivy-dashboard`, İmaj: `backend` (26 Kasım 2025, 18:20:00)
- `export/trivy-dashboard/frontend.json` → Proje: `trivy-dashboard`, İmaj: `frontend`
- `export/my-service/api-20251126-120000.json` → Proje: `my-service`, İmaj: `api` (26 Kasım 2025, 12:00:00)

**Avantajlar:**
- ✅ Daha düzenli dosya organizasyonu
- ✅ Proje bazında kolay yönetim
- ✅ Çok sayıda proje olduğunda daha temiz yapı
- ✅ Her iki yapı da desteklenir (düz ve dizin)

**Not**: 
- Zaman damgası formatı `YYYYMMDD-HHMMSS` şeklindedir
- Aynı proje-imaj kombinasyonu için birden fazla tarama yaparsanız, tüm taramalar dashboard'da görüntülenecektir
- Backend otomatik olarak tüm alt dizinlerdeki JSON dosyalarını tarar (recursive)

#### ArtifactName'den Otomatik Parse (Önerilen)

Backend artık JSON dosyasının içindeki `ArtifactName` alanından proje, imaj ve tag bilgisini otomatik olarak çıkarıyor. Bu sayede dosya adı formatından bağımsız çalışır.

**Format:** `{proje-ismi}-{imaj-ismi}:{tag}`

**Örnekler:**
- `ArtifactName: "trivy-dashboard-backend:latest"` → Proje: `trivy-dashboard`, İmaj: `backend`, Tag: `latest`
- `ArtifactName: "my-service-api:v1.0.0"` → Proje: `my-service`, İmaj: `api`, Tag: `v1.0.0`
- `ArtifactName: "git-effort-frontend:dev"` → Proje: `git-effort`, İmaj: `frontend`, Tag: `dev`

**Avantajlar:**
- ✅ Dosya adı formatından bağımsız (istediğin gibi isimlendirebilirsin)
- ✅ Tag bilgisi otomatik olarak yakalanır
- ✅ JSON içindeki gerçek veriyi kullanır (daha güvenilir)
- ✅ Eğer `ArtifactName` parse edilemezse, dosya adından fallback yapar (geriye uyumlu)
- ✅ Dashboard'da tarama geçmişinde dosya adı yerine imaj adı ve tag gösterilir (daha okunabilir)

**Dosya adı örnekleri (organizasyon için):**
- `export/git-effort/backend-latest-20251126-215219.json`
- `export/git-effort/frontend-v1.0.0-20251126-215219.json`
- `export/git-effort/api-dev-20251126-215219.json`
- Veya sadece: `export/git-effort/scan-20251126-215219.json` (ArtifactName'den parse edilir)

### Jenkins Pipeline Örneği

**Düz Yapı için:**
```bash
# Trivy taraması yap ve JSON çıktısı al
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
trivy image --format json -o /tmp/my-project-backend-${TIMESTAMP}.json my-project-backend:latest

# Dashboard sunucusuna gönder
scp /tmp/my-project-backend-${TIMESTAMP}.json user@dashboard-host:/path/to/trivy-dashboard/export/
```

**Dizin Yapısı için (Önerilen):**
```bash
# Proje dizinini oluştur (ilk kez ise)
ssh user@dashboard-host "mkdir -p /path/to/trivy-dashboard/export/my-project"

# Trivy taraması yap ve JSON çıktısı al
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
trivy image --format json -o /tmp/backend-${TIMESTAMP}.json my-project-backend:latest

# Dashboard sunucusuna gönder (dizin yapısına)
scp /tmp/backend-${TIMESTAMP}.json user@dashboard-host:/path/to/trivy-dashboard/export/my-project/
```

### Docker ile Test

**Hızlı Tarama (Script Kullanımı - Önerilen):**
```bash
# Backend için tarama (zaman damgası otomatik eklenir)
./scan-backend.sh

# Frontend için tarama (zaman damgası otomatik eklenir)
./scan-frontend.sh
```

**Manuel Tarama (Zaman Damgası ile - Dizin Yapısı):**
```bash
# Zaman damgası oluştur
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

# Backend image'ini tara (dizin yapısı: export/trivy-dashboard/backend-YYYYMMDD-HHMMSS.json)
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/export:/output \
  aquasec/trivy:latest image \
  --format json -o /output/trivy-dashboard/backend-${TIMESTAMP}.json \
  trivy-dashboard-backend:latest

# Frontend image'ini tara (dizin yapısı: export/trivy-dashboard/frontend-YYYYMMDD-HHMMSS.json)
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/export:/output \
  aquasec/trivy:latest image \
  --format json -o /output/trivy-dashboard/frontend-${TIMESTAMP}.json \
  trivy-dashboard-frontend:latest
```

**Örnek Tarama:**
```bash
# Backend için örnek tarama komutu
# Bu komut zaman damgası ile yeni bir tarama oluşturur ve önceki taramaları korur

TIMESTAMP=$(date +%Y%m%d-%H%M%S)

docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /home/shyuuhei/GIT/trivy-dashboard/export:/output \
  aquasec/trivy:latest image \
  --format json -o /output/trivy-dashboard/backend-${TIMESTAMP}.json \
  trivy-dashboard-backend:latest

# Sonuç: export/trivy-dashboard/backend-20251126-224009.json gibi bir dosya oluşur
# Dashboard'da bu yeni tarama otomatik olarak görüntülenir
```

**Basit Tarama (Tek dosya, üzerine yazar - Önerilmez):**
```bash
# ⚠️ Bu komut eski dosyayı üzerine yazar, tarama geçmişi kaybolur
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/export:/output \
  aquasec/trivy:latest image \
  --format json -o /output/trivy-dashboard/backend.json \
  trivy-dashboard-backend:latest
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
├── scan-backend.sh      # Backend tarama scripti (zaman damgası ile)
├── scan-frontend.sh     # Frontend tarama scripti (zaman damgası ile)
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
- **Tarama Geçmişi**: Her imaj için tüm taramaların geçmişi (imaj adı ve tag ile gösterilir, dosya adı yerine)
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

## Proje Geliştirme Önerileri

### Gelecek Özellikler

- [ ] **Zaman Serisi Analizi**: Aynı imaj için farklı zamanlardaki taramaları karşılaştırma
- [ ] **Trend Grafikleri**: Vulnerability sayılarının zaman içindeki değişimini görselleştirme
- [ ] **E-posta Bildirimleri**: Yeni CRITICAL/HIGH açıklar bulunduğunda bildirim gönderme
- [ ] **Export/Import**: Tarama sonuçlarını yedekleme ve geri yükleme
- [ ] **API Authentication**: Backend API'sine erişim kontrolü
- [ ] **Database Entegrasyonu**: SQLite/PostgreSQL ile tarama geçmişini saklama
- [ ] **Webhook Desteği**: CI/CD pipeline'lardan otomatik tarama tetikleme
- [ ] **Filtreleme ve Sıralama**: Vulnerability listesinde gelişmiş filtreleme
- [ ] **Karşılaştırma Modu**: İki tarama sonucunu yan yana karşılaştırma
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

## Güvenlik

- Backend ve frontend dependencies güncel tutulur
- Alpine Linux base image'leri güvenlik güncellemeleri ile güncellenir
- `npm audit` ve `go mod` ile düzenli güvenlik kontrolleri yapılır
- Go 1.25 ve Alpine 3.22 kullanılarak en güncel güvenlik yamaları sağlanır

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
