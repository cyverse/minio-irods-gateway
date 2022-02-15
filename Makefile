DOCKER_IMAGE?=cyverse/minio-irods-gateway
VERSION=v0.1.0
GIT_COMMIT?=$(shell git rev-parse HEAD)
BUILD_DATE?=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GO111MODULE=on
GOPROXY=direct
GOPATH=$(shell go env GOPATH)

MINIO_ROOT_USER=${IRODS_USER_NAME}
MINIO_ROOT_PASSWORD=${IRODS_USER_PASSWORD}
IRODS_END_POINT=irods://data.cyverse.org:1247
IRODS_PATH=/iplant/home/iychoi

API_SERVICE_PORT=9000
CONSOLE_SERVICE_PORT=9001

.EXPORT_ALL_VARIABLES:

.PHONY: image
image:
	docker build -t $(DOCKER_IMAGE):latest .

.PHONY: push
push: image
	docker push $(DOCKER_IMAGE):latest

.PHONY: run
run:
	@docker run -p $(API_SERVICE_PORT):$(API_SERVICE_PORT) \
	-p $(CONSOLE_SERVICE_PORT):$(CONSOLE_SERVICE_PORT) \
	-e "MINIO_ROOT_USER=$(MINIO_ROOT_USER)" \
	-e "MINIO_ROOT_PASSWORD=$(MINIO_ROOT_PASSWORD)" \
	$(DOCKER_IMAGE):latest gateway --address :$(API_SERVICE_PORT) --console-address :$(CONSOLE_SERVICE_PORT) irods \
	$(IRODS_END_POINT)$(IRODS_PATH)

.PHONY: run_ticket
run_ticket:
	@docker run -p $(API_SERVICE_PORT):$(API_SERVICE_PORT) \
	-p $(CONSOLE_SERVICE_PORT):$(CONSOLE_SERVICE_PORT) \
	-e "MINIO_ROOT_USER=ticket" \
	-e "MINIO_ROOT_PASSWORD=${IRODS_TICKET}" \
	$(DOCKER_IMAGE):latest gateway --address :$(API_SERVICE_PORT) --console-address :$(CONSOLE_SERVICE_PORT) irods \
	$(IRODS_END_POINT)
