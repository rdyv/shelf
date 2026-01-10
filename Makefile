.PHONY: help install test lint format format-fix typecheck check clean build

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "%-15s %s\n", $$1, $$2}'

install:
	python3 -m venv venv
	. venv/bin/activate && pip3 install -e .

test:
	@echo "Running unit tests..."
	@python3 -m unittest discover -s tests -v

test-quick:
	@python3 -m unittest discover -s tests -q

smoke-test:
	@echo "Running smoke test..."
	@python3 -m shelf status

lint:
	@echo "Running ruff lint check..."
	@ruff check shelf/

format:
	@echo "Checking code formatting..."
	@ruff format --check shelf/ || (echo "Code formatting issues found. Run 'make format-fix' to fix." && exit 1)

format-fix:
	@echo "Applying code formatting..."
	@ruff format shelf/
	@echo "Applying lint fixes..."
	@ruff check --fix shelf/

typecheck:
	@echo "Running pyrefly type check..."
	@pyrefly check shelf/

check: format lint typecheck

clean:
	rm -rf build/ dist/ *.egg-info/
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

build: clean
	python3 -m build

.DEFAULT_GOAL := help
