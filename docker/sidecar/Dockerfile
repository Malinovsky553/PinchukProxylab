FROM golang:1.21-alpine

WORKDIR /app

COPY go.mod ./
COPY sidecar ./sidecar

RUN go build -o sidecar-app ./sidecar

EXPOSE 8090

CMD ["./sidecar-app"]
