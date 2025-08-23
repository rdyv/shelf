# Makefile for Shelf

.PHONY: help install test lint format format-fix clean build

help: ## Show help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "%-15s %s\n", $$1, $$2}'

install: ## Install shelf command
	pip install -e .

test: ## Test basic functionality
	python3 shelf.py status

lint: ## Run linters
	@if command -v black >/dev/null 2>&1; then \
		echo "Running black format check..."; \
		black --check shelf.py; \
	else \
		echo "black not found, skipping format check"; \
	fi
	@if command -v flake8 >/dev/null 2>&1; then \
		echo "Running flake8 lint check..."; \
		flake8 shelf.py --max-line-length=100 --ignore=E203,W503; \
	else \
		echo "flake8 not found, skipping lint check"; \
	fi

format: ## Check code formatting (fails if issues found)
	@if command -v black >/dev/null 2>&1; then \
		echo "Checking code formatting..."; \
		black --check shelf.py || (echo "Code formatting issues found. Run 'make format-fix' to fix." && exit 1); \
	else \
		echo "black not found, cannot check formatting"; \
		exit 1; \
	fi

format-fix: ## Apply code formatting
	@if command -v black >/dev/null 2>&1; then \
		echo "Applying code formatting..."; \
		black shelf.py; \
	else \
		echo "black not found, cannot format code"; \
		exit 1; \
	fi

clean: ## Clean build artifacts
	rm -rf build/ dist/ *.egg-info/
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

build: clean ## Build package
	python3 -m build

.DEFAULT_GOAL := help
