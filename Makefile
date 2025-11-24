# Makefile for Shelf

.PHONY: help install test lint format format-fix typecheck check clean build

help: ## Show help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "%-15s %s\n", $$1, $$2}'

install: ## Install shelf command
	python3 -m venv venv
	. venv/bin/activate && pip3 install -e .

test: ## Test basic functionality
	python3 -m shelf status

lint: ## Run ruff linter
	@echo "Running ruff lint check..."
	@ruff check shelf/

format: ## Check code formatting (fails if issues found)
	@echo "Checking code formatting..."
	@ruff format --check shelf/ || (echo "Code formatting issues found. Run 'make format-fix' to fix." && exit 1)

format-fix: ## Apply code formatting
	@echo "Applying code formatting..."
	@ruff format shelf/
	@echo "Applying lint fixes..."
	@ruff check --fix shelf/

typecheck: ## Run type checker
	@echo "Running pyrefly type check..."
	@pyrefly check shelf/

check: format lint typecheck ## Run all checks (format, lint, typecheck)

clean: ## Clean build artifacts
	rm -rf build/ dist/ *.egg-info/
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

build: clean ## Build package
	python3 -m build

.DEFAULT_GOAL := help
