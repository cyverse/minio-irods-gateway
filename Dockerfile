FROM golang:1.17.3-stretch

LABEL maintainer="Illyoung Choi <iychoi@email.arizona.edu>"
LABEL version="0.1"
LABEL description="MinIO iRODS Gateway Image"

ENV MINIO_UPDATE off
ENV MINIO_ACCESS_KEY_FILE=access_key \
    MINIO_SECRET_KEY_FILE=secret_key 

RUN git clone https://github.com/minio/minio
WORKDIR minio

# copy new files
COPY cmd/gateway-interface.go cmd/
COPY cmd/gateway/gateway.go cmd/gateway/
COPY cmd/gateway/irods cmd/gateway/irods

# get go-irodsclient
RUN go get github.com/cyverse/go-irodsclient && \
    go mod tidy

RUN go install -v -ldflags "$(go run buildscripts/gen-ldflags.go)"
RUN cp dockerscripts/docker-entrypoint.sh /usr/bin/

EXPOSE 9000

ENTRYPOINT ["/usr/bin/docker-entrypoint.sh"]

CMD ["minio"]