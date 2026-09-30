FROM golang:1.22-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /out/gate .

FROM alpine:3.21

RUN apk add --no-cache util-linux \
	&& adduser -D -H -u 65532 gate
WORKDIR /data
COPY --from=build /out/gate /usr/local/bin/gate
COPY config.example.yaml /tmp/config.example.yaml
RUN sed 's#geoip_db: "GeoLite2-Country.mmdb"#geoip_db: ""#' /tmp/config.example.yaml > /data/config.yaml \
	&& rm /tmp/config.example.yaml \
	&& chown -R gate:gate /data
USER gate

EXPOSE 8080
VOLUME /data
ENTRYPOINT ["/usr/local/bin/gate", "-config", "/data/config.yaml"]
