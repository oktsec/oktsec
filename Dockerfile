FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -h /home/oktsec oktsec

COPY oktsec /usr/local/bin/oktsec

USER oktsec
WORKDIR /home/oktsec

EXPOSE 8080

ENTRYPOINT ["oktsec"]
CMD ["serve"]
