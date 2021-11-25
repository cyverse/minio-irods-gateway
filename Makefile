DOCKER_IMAGE?=cyverse/minio-irods-gateway
VERSION=v0.1.0
GIT_COMMIT?=$(shell git rev-parse HEAD)
BUILD_DATE?=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GO111MODULE=on
GOPROXY=direct
GOPATH=$(shell go env GOPATH)

IRODS_USER_NAME=iychoi
IRODS_USER_PASSWORD=
IRODS_END_POINT=irods://data.cyverse.org:1247
IRODS_PATH=/iplant/home/iychoi

SERVICE_PORT=9001

.EXPORT_ALL_VARIABLES:

.PHONY: image
image:
	docker build -t $(DOCKER_IMAGE):latest .

.PHONY: run
run:
	@docker run -p $(SERVICE_PORT):$(SERVICE_PORT) \
	-e "MINIO_ROOT_USER=$(IRODS_USER_NAME)" \
	-e "MINIO_ROOT_PASSWORD=$(IRODS_USER_PASSWORD)" \
	$(DOCKER_IMAGE):latest gateway --console-address :$(SERVICE_PORT) irods \
	$(IRODS_END_POINT)$(IRODS_PATH)

