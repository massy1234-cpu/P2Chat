# STAGE 1: Build
FROM golang:1.22-alpine AS builder
WORKDIR /app

#Copia in cache cio che ha gia compilato
COPY go.mod go.sum ./
RUN go mod download

# Copiamo il codice del client
COPY . .

# Compiliamo il binario del client
# Usiamo le stesse flag del server per la portabilità
RUN CGO_ENABLED=0 GOOS=linux go build -o client-bin .

# STAGE 2: Run
FROM alpine:latest
RUN apk add --no-cache ca-certificates
WORKDIR /root/

# Copiamo il binario dal builder
COPY --from=builder /app/client-bin .

# Il client non "espone" porte come un server, 
# ma deve poter uscire sulla rete.
CMD ["./client-bin"]