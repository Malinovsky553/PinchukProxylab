FROM golang:1.21-alpine

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .

RUN go build -o security-app ./security

EXPOSE 8080

CMD ["./security-app"]
