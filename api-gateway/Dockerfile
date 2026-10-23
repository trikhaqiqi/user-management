# Build context is the repository root (it needs ../pkg):
#   docker build -f api-gateway/Dockerfile .
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY pkg/go.mod pkg/go.sum ./pkg/
COPY api-gateway/go.mod api-gateway/go.sum ./api-gateway/
RUN cd api-gateway && go mod download
COPY pkg ./pkg
COPY api-gateway ./api-gateway
RUN cd api-gateway && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/app .

# distroless: no shell or package manager; runs as an unprivileged user.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/app /app
COPY docs/openapi.yaml /docs/openapi.yaml
ENV OPENAPI_SPEC_PATH=/docs/openapi.yaml
USER nonroot:nonroot
ENTRYPOINT ["/app"]
