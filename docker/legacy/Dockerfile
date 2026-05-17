FROM golang:1.21-alpine

WORKDIR /app

COPY go.mod ./
COPY legacy ./legacy

RUN go build -o legacy-app ./legacy

EXPOSE 9000

CMD ["./legacy-app"]
