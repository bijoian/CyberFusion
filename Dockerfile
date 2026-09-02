FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o cyberfusion ./cmd/cyberfusion

FROM alpine:latest

RUN apk --no-cache add ca-certificates nmap nuclei

WORKDIR /root/

COPY --from=builder /app/cyberfusion .

ENTRYPOINT ["./cyberfusion"]
