# Image for cmd/viewer, the web page over audit_logs. The audit package itself
# is a library and is not built here.
FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /viewer ./cmd/viewer

FROM scratch
COPY --from=builder /viewer /viewer
USER 65534
EXPOSE 3000
CMD ["/viewer"]
