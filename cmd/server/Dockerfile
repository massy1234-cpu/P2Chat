#BUILD
FROM golang:1.22-alpine AS builder 
#scarichiamo alpine che è una versione super basica di Linux ( ricordo che Docker è Linux ) e chiamo tutto cio builder

WORKDIR /app
#/app sarà la cartella di lavoro del docker, dove verranno inseriti tutti i file temporanei necessari alla compilazione

COPY go.mod go.sum ./
RUN go mod download
# Copiamo il resto del codice e compiliamo
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o main .
#CGO sono pacchetti C per GO ( per evitare che librerie C nel dispositivo possano mandare in crash il tutto , isolazione completa )
#mentre GOOS sarebbe il sistema operativo che useremo per questo docker

# STAGE 2: Run
FROM alpine:latest
WORKDIR /root/
# Copiamo solo il binario compilato dallo stage precedente

COPY --from=builder /app/main .
#trasporto solo cio che mi serve nella cartella /root/

EXPOSE 8080
CMD ["./main"]
#eseguiamo il binario compilato