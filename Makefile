.PHONY: all build run test clean cert docker-up docker-down migrate-up migrate-down

# Переменные
BINARY_NAME=auth-service
DOCKER_COMPOSE=docker-compose

all: clean build

build:
	go build -o $(BINARY_NAME) ./cmd/server

run: build
	./$(BINARY_NAME)

test:
	go test -v ./...

clean:
	go clean
	rm -f $(BINARY_NAME)

cert:
	./scripts/generate_cert.sh

docker-up:
	$(DOCKER_COMPOSE) up -d

docker-down:
	$(DOCKER_COMPOSE) down

migrate-up:
	go run cmd/migrate/main.go -direction up

migrate-down:
	go run cmd/migrate/main.go -direction down

# Полная установка
setup: cert docker-up migrate-up build run 