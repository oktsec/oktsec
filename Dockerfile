FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /oktsec ./cmd/oktsec

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -h /home/oktsec oktsec

COPY --from=builder /oktsec /usr/local/bin/oktsec

USER oktsec
WORKDIR /home/oktsec

EXPOSE 8080

ENTRYPOINT ["oktsec"]
CMD ["serve"]
