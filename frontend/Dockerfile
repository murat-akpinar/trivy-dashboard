FROM node:20-alpine AS build

WORKDIR /app

# Update Alpine packages for security and fix libpng CVE vulnerabilities
RUN apk update && apk upgrade --no-cache && \
    apk add --no-cache ca-certificates && \
    rm -rf /var/cache/apk/*

# Vite, build anında VITE_* env değişkenlerini okur
ARG VITE_API_BASE
ENV VITE_API_BASE=${VITE_API_BASE}

# Sadece gerekli dosyaları kopyala; host'taki node_modules'u içeri taşımayın
COPY package.json package-lock.json* ./

# Build aşamasında Vite gibi devDependencies'in de kurulmasını sağla
RUN npm ci --include=dev

COPY tsconfig.json vite.config.ts tailwind.config.ts postcss.config.cjs ./
COPY index.html ./
COPY public ./public
COPY src ./src

RUN npm run build

FROM nginx:alpine AS runtime

# Update Alpine packages and install security updates, fix libpng CVE vulnerabilities
RUN apk update && apk upgrade --no-cache && \
    apk add --no-cache ca-certificates wget && \
    rm -rf /var/cache/apk/*

COPY --from=build /app/dist /usr/share/nginx/html

# Copy custom nginx config for SPA routing
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]


