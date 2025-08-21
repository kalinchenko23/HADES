FROM python:3.10-slim

# Set working directory inside the container 
WORKDIR /app

# Install Poetry
RUN pip install --no-cache-dir poetry

# Copy Poetry files for dependency installation
COPY pyproject.toml poetry.lock* /app/

# Install dependencies
RUN poetry config virtualenvs.create false && poetry install --no-interaction --no-ansi

# Copy the rest of the application code
COPY . /app

# Command to run the backend (overridden in docker-compose for dev)
CMD ["poetry", "run", "python", "main.py"]