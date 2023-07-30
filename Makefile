.SHELLFLAGS += -x -e
.ONESHELL:
PY_SOURCES = custom_components scripts
HASS_VERSION = $(shell pip freeze | grep \^homeassistant | sed 's/==/\n/g' | tail -n 1)
COMPOSE_ARGS = -f scripts/docker-compose.yml -p hass-auth-header

all: lint-fix lint

lint-fix:
	isort $(PY_SOURCES)
	black $(PY_SOURCES)
	ruff $(PY_SOURCES)

lint:
	pylint $(PY_SOURCES)

test-env-start:
	VERSION=${HASS_VERSION} docker-compose $(COMPOSE_ARGS)  up -d

test-env-stop:
	VERSION=${HASS_VERSION} docker compose $(COMPOSE_ARGS) down

test-env-remove:
	VERSION=${HASS_VERSION} docker compose $(COMPOSE_ARGS) down -v

hass-restart:
	docker-compose $(COMPOSE_ARGS) exec homeassistant killall -HUP python3
