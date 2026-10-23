SHELL := /bin/bash
SERVICES := pkg auth-service core-service api-gateway
MIGRATE := go run -tags postgres github.com/golang-migrate/migrate/v4/cmd/migrate@v4.18.1
LOAD_ENV := set -a; source ./.env; set +a

.PHONY: env migrate-up migrate-down build test vet run stop restart status logs e2e docker-up docker-down monitoring-up monitoring-down

env:            ## create .env with generated secrets
	./scripts/init-env.sh

migrate-up:     ## apply database migrations
	$(LOAD_ENV); $(MIGRATE) -path migrations -database "$$DATABASE_URL" up

migrate-down:   ## roll back the last migration
	$(LOAD_ENV); $(MIGRATE) -path migrations -database "$$DATABASE_URL" down 1

build:
	@for s in auth-service core-service api-gateway; do (cd $$s && go build -o bin/$$s .) || exit 1; done

vet:
	@for s in $(SERVICES); do (cd $$s && go vet ./...) || exit 1; done

test:           ## unit tests for every module
	@for s in $(SERVICES); do (cd $$s && go test ./...) || exit 1; done

run:            ## run all services locally in the background
	./scripts/run-local.sh start

stop:
	./scripts/run-local.sh stop

restart:
	./scripts/run-local.sh restart

status:
	./scripts/run-local.sh status

logs:
	tail -f tmp/logs/*.log

e2e:            ## end-to-end scenarios against the running gateway
	./scripts/e2e.sh

docker-up:      ## full stack in Docker (Postgres, Redis, Mailpit, migrations, services)
	docker compose up -d --build

docker-down:
	docker compose down

monitoring-up:  ## Loki + Alloy + Grafana only (works with `make run` or the compose app stack)
	mkdir -p tmp/logs
	docker compose --profile monitoring up -d loki alloy grafana
	@echo "Grafana: http://localhost:$${GRAFANA_HOST_PORT:-3030}  (admin / GRAFANA_ADMIN_PASSWORD in .env)"

monitoring-down:
	docker compose --profile monitoring stop loki alloy grafana
