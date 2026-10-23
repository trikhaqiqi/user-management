# Build context is the repository root (it needs ../pkg):
#   docker build -f auth-service/Dockerfile .
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY pkg/go.mod pkg/go.sum ./pkg/
COPY auth-service/go.mod auth-service/go.sum ./auth-service/
RUN cd auth-service && go mod download
COPY pkg ./pkg
COPY auth-service ./auth-service
RUN cd auth-service && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/app .

# distroless: no shell or package manager; runs as an unprivileged user.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/app /app
USER nonroot:nonroot
ENTRYPOINT ["/app"]
