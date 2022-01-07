MUTABLE_VERSION ?= canary
VERSION ?= git-$(shell git rev-parse --short HEAD)

IMAGE := ${DEIS_REGISTRY}${IMAGE_PREFIX}/${SHORT_NAME}:${VERSION}
IMAGE_S6 := ${DEIS_REGISTRY}${IMAGE_PREFIX}/${SHORT_NAME}-s6:${VERSION}
MUTABLE_IMAGE := ${DEIS_REGISTRY}${IMAGE_PREFIX}/${SHORT_NAME}:${MUTABLE_VERSION}
MUTABLE_IMAGE_S6 := ${DEIS_REGISTRY}${IMAGE_PREFIX}/${SHORT_NAME}-s6:${MUTABLE_VERSION}

info:
	@echo "Build tag:       ${VERSION}"
	@echo "Registry:        ${DEIS_REGISTRY}"
	@echo "Immutable tag:   ${IMAGE}"
	@echo "Mutable tag:     ${MUTABLE_IMAGE}"

.PHONY: docker-push
docker-push: docker-immutable-push docker-mutable-push

.PHONY: docker-immutable-push
docker-immutable-push:
	docker push ${IMAGE}

.PHONY: docker-mutable-push
docker-mutable-push:
	docker push ${MUTABLE_IMAGE}
