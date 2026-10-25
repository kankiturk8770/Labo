FROM golang:1.27-alpine AS build

WORKDIR /src

COPY go.mod ./
COPY main.go ./
COPY tuning.go ./

RUN CGO_ENABLED=0 GOOS=linux \
    go build -buildvcs=false -trimpath -ldflags="-s -w" \
    -o /out/edge-gateway .

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/edge-gateway /edge-gateway

USER nonroot
EXPOSE 8443

ENTRYPOINT ["/edge-gateway"]
