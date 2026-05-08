.PHONY: lint format typecheck test check

lint:
	uv run ruff check ai_codescan tests

format:
	uv run ruff format ai_codescan tests

typecheck:
	uv run ty check --error-on-warning

test:
	uv run pytest

check: lint typecheck test
