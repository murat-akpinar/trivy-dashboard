## Trivy Dashboard

Bu proje, **Trivy güvenlik tarama sonuçlarını toplayıp görselleştiren basit bir web dashboard** uygulamasıdır. Amaç, özellikle CI/CD ortamlarında (Jenkins vb.) üretilen Trivy JSON çıktılarının tek bir merkezde toplanması, saklanması ve SonarQube benzeri bir arayüz üzerinden kolayca incelenebilmesidir.

---

## Amaç

- **Merkezi görünürlük**: Farklı projeler ve pipeline’lardan gelen Trivy raporlarını tek bir ekranda görmek.
- **Tarihsel inceleme**: Aynı proje için farklı zamanlarda üretilen raporları saklayıp trend analizi yapabilmek.
- **Hızlı inceleme**: Proje bazlı, branch bazlı ve severity bazlı filtrelerle zafiyetleri hızlıca bulmak.
- **Basit entegrasyon**: Jenkins gibi CI/CD araçlarından yalnızca bir `scp` veya benzeri mekanizma ile raporu göndererek entegrasyon sağlamak.

---

## Hedefler

- **Trivy JSON çıktısını desteklemek**
  - `trivy image` / `trivy fs` / `trivy repo` çıktılarının JSON formatını okuyabilmek.
  - Raporları, proje adı / branch / zaman bilgisi ile ilişkilendirmek.
- **Dosya tabanlı ingest akışı**
  - CI/CD pipeline’ının Trivy raporunu JSON formatında üretmesi.
  - Rapor dosyasının dashboard sunucusuna belirli bir dizine (örn. `export/`) kopyalanması.
  - Dashboard backend’inin bu dizini periyodik olarak tarayıp yeni raporları içeri alması.
- **Web arayüzü**
  - Proje listesi ve her proje için son tarama özetleri.
  - Toplam zafiyet ve severity dağılımı (CRITICAL/HIGH/MEDIUM/LOW).
  - Seçilen bir rapor için detay sayfası (package, vulnerability ID, fixed version vb. bilgilerin listesi).

---

## Yüksek Seviye Mimarî (İlk Taslak)

- **Trivy (CI/CD tarafı)**
  - Jenkins pipeline’ı Trivy ile imaj / kod taraması yapar.
  - Çıktı: `--format json` ile üretilen rapor dosyası.
  - Rapor dosyası `scp` veya benzeri bir yöntemle dashboard makinesindeki `export/` dizinine kopyalanır.

- **Dashboard Backend**
  - `export/` dizinini belirli aralıklarla tarar.
  - Yeni gelen JSON raporlarını parse eder.
  - Rapor meta verilerini (proje, branch, tarih, artifact name, severity sayıları vb.) kalıcı bir depoya (örn. dosya veya basit bir veritabanı) kaydeder.
  - REST API veya benzeri bir arayüz ile frontend’e veri sunar.

- **Dashboard Frontend**
  - Proje / rapor listelerini gösterir.
  - Severity dağılımlarını grafikler halinde gösterir.
  - Seçilen raporun detay sayfasını listeler.

İlk aşamada mimari minimum karmaşıklıkla (örneğin tek bir süreçte basit bir backend + minimal bir web UI) tasarlanacak, daha sonra ihtiyaçlara göre ölçeklenip geliştirilebilir.

---

## Geliştirme Yol Haritası (Kaba Taslak)

1. **Temel proje iskeleti**
   - Backend için teknoloji seçimi (örn. Python/FastAPI, Node.js/NestJS, Go vb.).
   - Basit bir API: “export dizinini tara ve mevcut raporları JSON olarak döndür”.
2. **Trivy JSON parser**
   - Örnek Trivy JSON dosyalarını okuyup anlamlı alanlara ayırma (severity sayıları, proje adı, branch, tarih vb.).
3. **Veri depolama**
   - İlk etapta dosya üzerinden, ileride gerekirse veritabanı (SQLite, PostgreSQL vb.).
4. **Minimal web arayüzü**
   - Proje listesi, son rapor, severity özetleri.
5. **Jenkins entegrasyon dokümantasyonu**
   - Örnek Jenkins pipeline adımları ve `scp` komutları.

Bu README, proje ilerledikçe genişletilecek ve teknik detaylar (API tasarımı, veri şeması, kurulum adımları vb.) eklenecektir.


