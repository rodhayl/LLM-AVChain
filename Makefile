.PHONY: install format lint typecheck test run-dev docker-build docker-up docker-down clean

install:
	python -m pip install --upgrade pip
	python -m pip install -e ".[dev,test]"

format:
	ruff format src tests

lint:
	ruff check src tests

typecheck:
	mypy src

test:
	pytest --cov=src/avchain --cov-report=term-missing --cov-fail-under=80

run-dev:
	python src/avchain/scripts/start_services.py

docker-build:
	docker compose build

docker-up:
	docker compose up -d

docker-down:
	docker compose down

clean:
	rm -rf .venv build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache htmlcov data evidence
