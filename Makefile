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

SERVICE_PORT=9001

.EXPORT_ALL_VARIABLES:

.PHONY: image
image:
	docker build -t $(DOCKER_IMAGE):latest .

.PHONY: run
run:
	@docker run -p $(SERVICE_PORT):$(SERVICE_PORT) \
	-e "MINIO_ROOT_USER=$(MINIO_ROOT_USER)" \
	-e "MINIO_ROOT_PASSWORD=$(MINIO_ROOT_PASSWORD)" \
	$(DOCKER_IMAGE):latest gateway --console-address :$(SERVICE_PORT) irods \
	$(IRODS_END_POINT)$(IRODS_PATH)

.PHONY: run_ticket
run_ticket:
	@docker run -p $(SERVICE_PORT):$(SERVICE_PORT) \
	-e "MINIO_ROOT_USER=ticket" \
	-e "MINIO_ROOT_PASSWORD=${IRODS_TICKET}" \
	$(DOCKER_IMAGE):latest gateway --console-address :$(SERVICE_PORT) irods \
	irods://data.cyverse.org:1247/iplant/home/iychoi/ticket_test

.PHONY: run_ticket2
run_ticket2:
	@docker run -p $(SERVICE_PORT):$(SERVICE_PORT) \
	-e "MINIO_ROOT_USER=ticket_test_user" \
	-e "MINIO_ROOT_PASSWORD=ticket_test_pass" \
	$(DOCKER_IMAGE):latest gateway --console-address :$(SERVICE_PORT) irods \
	irods://${IRODS_TICKET}@data.cyverse.org:1247/iplant/home/iychoi/ticket_test