FROM golang:1.25-alpine AS build

WORKDIR /app

# Update Alpine packages for security (latest versions)
RUN apk update && apk upgrade --no-cache && apk add --no-cache ca-certificates

COPY go.mod go.sum* ./
RUN go mod download || true

COPY . .

RUN go build -o /trivy-dashboard-backend ./...

FROM alpine:3.22 AS runtime

WORKDIR /app

# Update Alpine packages and install security updates (aggressive update)
RUN apk update && \
    apk upgrade --no-cache && \
    apk add --no-cache ca-certificates tzdata wget && \
    apk fix --no-cache && \
    rm -rf /var/cache/apk/* /tmp/* /var/tmp/*

COPY --from=build /trivy-dashboard-backend /usr/local/bin/trivy-dashboard-backend

EXPOSE 8080

CMD ["trivy-dashboard-backend"]


