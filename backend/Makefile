dev:
	uv run uvicorn src.vulnrisk.api.main:app --reload --host 0.0.0.0 --port 8000

test:
	uv run pytest src/tests

lint:
	uv run black src && uv run flake8 src && uv run mypy src

lock-check:
	uv lock --check

build:
	docker build -t vulnrisk-backend .

deploy-staging:
	echo "Deploy to staging not yet implemented."
