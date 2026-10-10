# syntax=docker/dockerfile:1

FROM golang:1.27 AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags "-s -w \
      -X github.com/sentinel-iam/sentinel/internal/cli.version=${VERSION} \
      -X github.com/sentinel-iam/sentinel/internal/cli.commit=${COMMIT} \
      -X github.com/sentinel-iam/sentinel/internal/cli.date=${DATE}" \
    -o /out/sentinel ./cmd/sentinel

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/sentinel /usr/local/bin/sentinel

ENV SENTINEL_HTTP_ADDR=":8080" \
    SENTINEL_DATA_DIR="/data" \
    SENTINEL_STORE="file" \
    SENTINEL_LOG_LEVEL="info"

VOLUME ["/data"]
EXPOSE 8080
USER nonroot:nonroot

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/sentinel", "healthcheck", "--url", "http://127.0.0.1:8080/healthz"]

ENTRYPOINT ["/usr/local/bin/sentinel"]
CMD ["serve"]
