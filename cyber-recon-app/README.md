# Cyber Reconnaissance Application (HADES)

HADES is a cyber reconnaissance tool designed to automate the process of network scanning, vulnerability detection, and potential exploitation. It leverages a LangGraph-based workflow for intelligent decision-making and integrates with various Large Language Models (LLMs) to provide detailed reports and actionable insights.

## Features

*   **Automated Reconnaissance:** Scans target IP addresses for open ports, services, and vulnerabilities.
*   **LLM Integration:** Utilizes various LLM providers (OpenAI, Anthropic, Gemini, Grok, Ollama) for intelligent analysis and report generation. If using Ollama be advised that models that are smaller then 14b parameters tend to perform poorly. Also, make sure that the chosen model support tool calling. 
*   **Vulnerability Detection:** Identifies potential security weaknesses based on scan results.
*   **Exploitation Attempt (Optional):** Can attempt to exploit identified vulnerabilities (under ideal circumstances).
*   **Detailed Reporting:** Generates comprehensive reconnaissance reports in JSON format.
*   **Message Queuing (RabbitMQ):** Uses RabbitMQ for asynchronous processing of reconnaissance requests and results.
*   **Configurable LLM Settings:** Allows users to specify LLM provider, API key, and local models.
*   **CLI Interface:** A command-line interface for easy interaction and initiation of reconnaissance tasks.

## Project Structure

The project consists of the following main components:

*   **`backend/`**: Contains the core Python logic for the reconnaissance workflow, LLM integration, and RabbitMQ consumer.
    *   `main.py`: The main entry point for the backend service, responsible for connecting to RabbitMQ, processing requests, and publishing results.
    *   `graph.py`: Implements the LangGraph workflow for orchestrating reconnaissance tasks.
    *   `nodes.py`: Defines individual nodes/steps within the LangGraph workflow (e.g., scanning, vulnerability analysis).
    *   `tools.py`: Contains helper functions and tools used by the LangGraph nodes.
*   **`cli/`**: A Go-based command-line interface for interacting with the backend.
    *   `main.go`: Handles command-line arguments, validates input, publishes reconnaissance requests to RabbitMQ, and consumes results.
*   **`docker/`**: Contains Dockerfiles for building various services.
    *   `backend.dockerfile`: Dockerfile for the Python backend service.
    *   `nmap.dockerfile`: Dockerfile for the Nmap scanning tool.
*   **`docker-compose.yml`**: Defines the multi-container Docker environment, including RabbitMQ and the backend service.
*   **`config.json`**: Example configuration file for LLM settings.
*   **`reports/`**: Directory where reconnaissance reports are saved.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

*   Docker and Docker Compose
*   Go (for the CLI)
*   Python 3.x and Poetry (for the backend)

### Installation

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/your-username/HADES.git
    cd HADES/cyber-recon-app
    ```

2.  **Start Docker services:**

    ```bash
    docker-compose up -d
    ```

    This will start the RabbitMQ server and the backend service.

3.  **Install Python dependencies for the backend:**

    ```bash
    cd backend
    poetry install
    cd ..
    ```

4.  **Install Go dependencies and build the CLI:**

    ```bash
    cd cli
    go mod tidy
    go build -o hades-cli main.go
    cd ..
    ```

## Configuration

The `config.json` file is used to configure the LLM provider and API key. An example is provided:

```json
{
    "provider":"openai",
    "api_key":"YOUR_OPENAI_API_KEY",
    "local_model":"qwen3:14b"
}
```

*   `provider`: Specify your LLM provider (e.g., "openai", "anthropic", "gemini", "grok", "ollama").
*   `api_key`: Your API key for the chosen LLM provider.
*   `local_model`: (Optional) Specify a local model if using a provider like Ollama.

**Note:** For Ollama, the `api_key` field can be left empty as it typically runs locally without an API key.

## Usage

You can use the Go CLI to initiate reconnaissance tasks.

```bash
./cli/hades-cli recon --ip <TARGET_IP> --config <PATH_TO_CONFIG_FILE>
```

**Example:**

```bash
./cli/hades-cli recon --ip 192.168.1.1 --config config.json
```

The results of the reconnaissance will be saved as a JSON file in the `reports/` directory.

## Backend Service

The Python backend service `cyber-recon-app/backend/main.py` runs as a consumer for RabbitMQ messages. It listens for `recon_requests` and publishes `recon_results`.

To run the backend service manually (outside of Docker Compose), which is reccomended so you can interact with a shell on the target:

```bash
cd cyber-recon-app/backend
poetry run python main.py
```

## CLI Application

The Go CLI application `cyber-recon-app/cli/main.go` is responsible for:

1.  Validating the input IP address and LLM configuration.
2.  Connecting to RabbitMQ.
3.  Publishing reconnaissance requests to the `recon_requests` queue.
4.  Consuming and saving the results from the `recon_results` queue.

### CLI Commands

*   `recon`: Initiates a reconnaissance task.
    *   `--ip <TARGET_IP>` (required): The IP address of the target.
    *   `--config <PATH_TO_CONFIG_FILE>` (required): Path to the LLM configuration JSON file.

