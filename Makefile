.PHONY: build test clean lint run-ingest run-correlate run-query install dev demo dashboard

BINDIR := bin
MODULE := github.com/SentinelSIEM/sentinel-siem

all: build

build:
	-@if not exist $(BINDIR) mkdir $(BINDIR)
	go build -o $(BINDIR)/sentinel-ingest.exe ./cmd/sentinel-ingest
	go build -o $(BINDIR)/sentinel-correlate.exe ./cmd/sentinel-correlate
	go build -o $(BINDIR)/sentinel-query.exe ./cmd/sentinel-query
	go build -o $(BINDIR)/sentinel-cli.exe ./cmd/sentinel-cli
	@echo All binaries built in $(BINDIR)/

test:
	go test ./...

lint:
	go vet ./...

clean:
	-@if exist $(BINDIR) rmdir /s /q $(BINDIR)
	-@docker compose down -v 2>nul || docker-compose down -v 2>nul || echo Docker not available
	@echo Cleaned build artifacts and Docker volumes

# install: Full installation — build binaries, start Docker, apply ES templates,
# create admin user, print credentials and dashboard URL.
install:
	bash scripts/install.sh

# dev: Hot-reload development mode — starts Docker services, runs ingest + query
# servers, and starts the React dev server with live reload.
dev: build
	@echo Starting Docker services...
	-@docker compose up -d 2>nul || docker-compose up -d 2>nul || echo Docker not available
	@echo Waiting for Elasticsearch...
	-@bash scripts/wait-for-es.sh http://localhost:9200 20 || echo ES not ready
	@echo Starting sentinel-ingest...
	@start /b $(BINDIR)/sentinel-ingest.exe --config sentinel.toml
	@echo Starting sentinel-query...
	@start /b $(BINDIR)/sentinel-query.exe --config sentinel.toml
	@echo Starting React dev server...
	@cd web && npm run dev

# demo: Full demo setup — install + create demo analyst accounts + replay all
# fixture datasets + trigger correlation rules + populate dashboard.
demo:
	bash scripts/demo.sh

# dashboard: Build the React dashboard for production.
dashboard:
	cd web && npm install && npm run build

run-ingest: build
	$(BINDIR)/sentinel-ingest.exe

run-correlate: build
	$(BINDIR)/sentinel-correlate.exe

run-query: build
	$(BINDIR)/sentinel-query.exe
