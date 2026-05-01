.PHONY: install install-dev lint test run clean

install:
	pip install -r requirements.txt

install-dev:
	pip install -r requirements-dev.txt

lint:
	flake8 scanner/ tests/

test:
	pytest tests/ -v --tb=short

test-cov:
	pytest tests/ -v --tb=short --cov=scanner --cov-report=term-missing

run:
	python -m scanner.cli --profile default --region eu-west-2

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	rm -f misconfig_report_*.json
