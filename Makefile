.PHONY: sync lint format typecheck test check clean

sync:
	uv sync --extra dev

lint:
	uv run ruff check .

format:
	uv run ruff format .

typecheck:
	uv run mypy src

test:
	uv run pytest -v

check: lint typecheck test

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache dist build *.egg-info
