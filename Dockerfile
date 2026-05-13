FROM golang:1.26-alpine AS builder

WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-s -w" -o /olaitan ./cmd/olaitan

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /olaitan /olaitan

USER nonroot:nonroot
ENTRYPOINT ["/olaitan"]
