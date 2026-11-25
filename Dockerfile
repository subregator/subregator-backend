# syntax=docker/dockerfile:1
ARG GO_IMAGE=golang:1.26-alpine@sha256:ecb67f987aa1a57794c91d19ade7ae0209f2f0f5496aaef9e6ae85ddf92d02ab
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG REVISION=unknown
RUN mkdir /data && chown 65532:65532 /data
RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -buildvcs=false -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -o /subregator ./cmd/subregator

FROM scratch
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="Subregator Backend" \
      org.opencontainers.image.description="Read-only IP resource comparison API" \
      org.opencontainers.image.source="https://github.com/subregator/subregator-backend" \
      org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.revision=$REVISION
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /subregator /subregator
COPY THIRD_PARTY_NOTICES.txt /THIRD_PARTY_NOTICES.txt
COPY --from=build --chown=65532:65532 /data /var/lib/subregator
ENV SUBREGATOR_ADDR=0.0.0.0:8080 \
    SUBREGATOR_SNAPSHOT=/var/lib/subregator/catalog.json \
    SUBREGATOR_LOG_FORMAT=json
USER 65532:65532
VOLUME ["/var/lib/subregator"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD ["/subregator", "healthcheck"]
ENTRYPOINT ["/subregator"]
