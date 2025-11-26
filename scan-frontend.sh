#!/bin/bash
# Frontend için zaman damgası ile Trivy taraması yapar
# Dizin yapısı: export/trivy-dashboard/frontend-YYYYMMDD-HHMMSS.json

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_DIR="trivy-dashboard"
OUTPUT_FILE="frontend-${TIMESTAMP}.json"

echo "🔍 Frontend taraması başlatılıyor..."
echo "📁 Çıktı dosyası: ${OUTPUT_DIR}/${OUTPUT_FILE}"

# Dizin yapısını kullan
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/export:/output \
  aquasec/trivy:latest image \
  --format json -o /output/${OUTPUT_DIR}/${OUTPUT_FILE} \
  trivy-dashboard-frontend:latest

if [ $? -eq 0 ]; then
  echo "✅ Tarama tamamlandı: ${OUTPUT_DIR}/${OUTPUT_FILE}"
else
  echo "❌ Tarama başarısız oldu"
  exit 1
fi

