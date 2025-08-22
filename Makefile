# Makefile for Shelf

.PHONY: help install test lint format clean build demo standalone patch minor major

help: ## Show help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "%-15s %s\n", $$1, $$2}'

install: ## Install shelf command
	pip install -e .

test: ## Test basic functionality
	python3 shelf.py status

lint: ## Run linters
	@command -v black >/dev/null && black --check shelf.py || true
	@command -v flake8 >/dev/null && flake8 shelf.py --max-line-length=100 --ignore=E203,W503 || true

format: ## Format code
	@command -v black >/dev/null && black shelf.py || true

clean: ## Clean build artifacts
	rm -rf build/ dist/ *.egg-info/
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

build: clean ## Build package
	python3 -m build

.DEFAULT_GOAL := help
