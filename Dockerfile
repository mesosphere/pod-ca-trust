FROM golang:1.19 AS builder
WORKDIR /workdir
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags '-s -w' -tags 'osusergo netgo' -o entrypoint

FROM gcr.io/distroless/static AS final
COPY --from=builder /workdir/entrypoint /
ENTRYPOINT ["/entrypoint"]
