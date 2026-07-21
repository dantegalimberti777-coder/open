# NGAV — tareas de desarrollo
.PHONY: all build test agent cloud fmt clean selftest run-cloud

all: build test

build: ## Compila agente (Rust) y servicio de reputación (Go)
	cd endpoint/agent-core && cargo build --release
	cd cloud/reputation && go build -o bin/reputation .

test: ## Ejecuta todos los tests
	cd endpoint/agent-core && cargo test
	cd cloud/reputation && go test ./...
	cd cloud/licensing && go test ./...

run-license: ## Levanta el servicio de licencias (modo demo) en :8090
	cd cloud/licensing && go run .

agent: ## Solo el agente
	cd endpoint/agent-core && cargo build --release

cloud: ## Solo el servicio de reputación
	cd cloud/reputation && go build -o bin/reputation .

selftest: agent ## Verifica el motor con EICAR
	./endpoint/agent-core/target/release/ngav selftest

run-cloud: ## Levanta el servicio de reputación en :8080
	cd cloud/reputation && go run .

fmt: ## Formatea el código
	cd endpoint/agent-core && cargo fmt
	cd cloud/reputation && gofmt -w .

clean:
	cd endpoint/agent-core && cargo clean
	rm -rf cloud/reputation/bin
