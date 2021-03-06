FROM golang:1.17.3-stretch

LABEL maintainer="Illyoung Choi <iychoi@email.arizona.edu>"
LABEL version="0.1"
LABEL description="MinIO iRODS Gateway Image"

ENV MINIO_UPDATE off
ENV MINIO_ACCESS_KEY_FILE=access_key \
    MINIO_SECRET_KEY_FILE=secret_key 

RUN git clone https://github.com/minio/minio
WORKDIR minio
# check out to a particular commit that works
# e3e0532613699b5c5c51ae9536e90167b9e4d6b9 on Feb 15, 2022
RUN git checkout e3e0532613699b5c5c51ae9536e90167b9e4d6b9
RUN go mod tidy

# build minio for the first time (to cache)
RUN go install -v -ldflags "$(go run buildscripts/gen-ldflags.go)"
RUN cp dockerscripts/docker-entrypoint.sh /usr/bin/

# copy new files
COPY cmd/gateway-interface.go cmd/
COPY cmd/gateway/gateway.go cmd/gateway/
COPY cmd/gateway/irods cmd/gateway/irods

# get go-irodsclient
RUN go get github.com/cyverse/go-irodsclient@v0.6.2-0.20220208222243-e124797927f0 && \
    go mod tidy

# rebuild
RUN go install -v -ldflags "$(go run buildscripts/gen-ldflags.go)"


EXPOSE 9000

ENTRYPOINT ["/usr/bin/docker-entrypoint.sh"]

CMD ["minio"]