FROM golang:1.23-alpine AS build

WORKDIR /app

COPY go.mod go.sum* ./
RUN go mod download || true

COPY . .

RUN go build -o /trivy-dashboard-backend ./...

FROM alpine:3.20 AS runtime

WORKDIR /app

COPY --from=build /trivy-dashboard-backend /usr/local/bin/trivy-dashboard-backend

EXPOSE 8080

CMD ["trivy-dashboard-backend"]


