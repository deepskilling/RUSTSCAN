.PHONY: help build-python install-python test-python clean-python python-dev python-wheel

help:
	@echo "NrMAP Build Commands"
	@echo "===================="
	@echo ""
	@echo "Rust Commands:"
	@echo "  make build          - Build Rust project"
	@echo "  make test           - Run Rust tests"
	@echo "  make run            - Run the project"
	@echo "  make clean          - Clean build artifacts"
	@echo ""
	@echo "Python Bindings Commands:"
	@echo "  make python-dev     - Build and install Python bindings (development mode)"
	@echo "  make python-wheel   - Build Python wheel for distribution"
	@echo "  make install-python - Install Python dependencies"
	@echo "  make test-python    - Run Python tests"
	@echo "  make clean-python   - Clean Python build artifacts"
	@echo ""
	@echo "Combined Commands:"
	@echo "  make all            - Build Rust and Python"
	@echo "  make test-all       - Run all tests"

# Rust commands
build:
	cargo build --release

test:
	cargo test --all-features

run:
	cargo run

clean:
	cargo clean
	rm -rf target/

# Python binding commands
python-dev:
	@echo "Building Python bindings (development mode)..."
	pip install maturin
	maturin develop --release --features python
	@echo "✓ Python bindings installed in development mode"

python-wheel:
	@echo "Building Python wheel..."
	pip install maturin
	maturin build --release --features python
	@echo "✓ Wheel built in target/wheels/"

install-python:
	@echo "Installing Python dependencies..."
	pip install python-dotenv pytest pytest-asyncio pytest-cov black mypy
	@echo "✓ Python dependencies installed"

test-python: python-dev
	@echo "Running Python tests..."
	cd python && pytest tests/ -v --cov=nrmap --cov-report=term-missing
	@echo "✓ Python tests completed"

clean-python:
	@echo "Cleaning Python build artifacts..."
	rm -rf python/build/
	rm -rf python/dist/
	rm -rf python/nrmap.egg-info/
	rm -rf python/**/__pycache__/
	rm -rf python/**/.pytest_cache/
	rm -rf .pytest_cache/
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	@echo "✓ Python artifacts cleaned"

# Combined commands
all: build python-dev

test-all: test test-python

# Format code
format:
	cargo fmt
	cd python && black .

# Lint
lint:
	cargo clippy -- -D warnings
	cd python && flake8 .

# Development setup
setup: install-python python-dev
	@echo "✓ Development environment ready"

# Documentation
docs:
	cargo doc --no-deps --open
	@echo "Python docs at: python/README.md"

