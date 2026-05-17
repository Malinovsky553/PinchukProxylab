FROM golang:1.21-alpine

WORKDIR /app

COPY go.mod ./
COPY security ./security

RUN go build -o security-app ./security

EXPOSE 8080

CMD ["./security-app"]