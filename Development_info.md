<h1 align="center">High-Level Components and Architecture</h1>

## Frontend (CLI Microservice Client)

**Language**: GoLang

**Libraries**:
  - `github.com/urfave/cli`: For CLI implementation
  - `github.com/rabbitmq/amqp091-go`: For RabbitMQ producer/consumer

**Functionality**: Sends recon requests (e.g., IP) to RabbitMQ queue (`recon_requests`) and listens to `recon_results` for reports/shell info

**Deployment**: Can run locally or as a containerized binary

## Backend Microservice

**Language**: Python 3.10+

**Orchestration**: LangGraph for execution graphs

**Agents**: AutoGen for multi-agent collaboration within graph nodes

**LLM Integration**:
  - Configurable via environment variables or YAML config
  - **Commercial**: LangChain/OpenAI/Grok wrappers
  - **Local**: Ollama (via `langchain_ollama`) or Hugging Face Transformers for on-prem models
  - **Toggle**: Config flag (e.g., `LLM_PROVIDER=groq` vs. `LLM_PROVIDER=ollama`)

**Message Broker**: RabbitMQ for decoupling frontend and backend
  - Queues: `recon_requests`, `recon_results`, and status updates

**Containerization**: Docker (via `docker-py`) for ephemeral containers (e.g., Kali Linux image) running tools like:
  - Nmap (`python-nmap`)
  - Metasploit (`pymetasploit3`)
  - No offensive code runs outside containers

**Additional Libraries**:
  - `pika`: RabbitMQ client
  - `fastapi`: Optional internal API for health checks
  - `pydantic`: State validation
  - `docker`: Docker client

**Workflow**:
  1. Consumes from `recon_requests`
  2. Executes LangGraph workflow with AutoGen agents
  3. Spins up Docker containers (e.g., `kalilinux/kali-rolling`) to execute tools (e.g., `container.exec_run('nmap -A ' + ip)`)
  4. Captures output, destroys containers
  5. AutoGen agents analyze in graph nodes
  6. Publishes results to `recon_results`

## Configuration Management
- **Format**: YAML files (e.g., `config.yaml`) for LLM keys, RabbitMQ credentials, and deployment modes
- **Secrets**: Managed via environment variables

## Microservice Components
- **CLI Client**:
  - User-facing, sends JSON messages to RabbitMQ (e.g., `{"ip": "192.168.1.1"}`)
  - Listens to `recon_results` for reports/shell info
- **Backend Service**:
  - Consumes `recon_requests`, initializes LangGraph state
  - Uses configured LLM for agents
  - Executes containerized tools, analyzes output, and publishes results
  - Horizontally scalable (multiple instances consuming from the queue)

<h1 align="center">Dvelopment Phases</h1>

### Phase 1: Core Setup and Local Development (2-3 weeks)
- **Repo Structure**:
  - `/cli`: Go-based CLI
  - `/backend`: Python backend
  - `/docker`: Docker images and scripts
  - `/config`: YAML configuration files
- **Tasks**:
  - Basic RabbitMQ integration: CLI publisher/consumer, backend consumer echoing messages
  - LangGraph skeleton: Define state, add planning node with AutoGen (using dummy LLM)
  - LLM toggle: Test with Ollama locally and a commercial API
  - Containerized mock: Run `echo 'scan'` in a Docker container
  - Test message flow and container execution via CLI

### Phase 2: Recon Logic and Tool Integration (3-4 weeks)
- **Tasks**:
  - Expand LangGraph: Add nodes for scanning, vulnerability assessment, and exploitation (all containerized)
  - Integrate tools: Nmap and Metasploit in Kali containers
  - Handle shell attempts (e.g., Metasploit reverse shell listener in container, proxy output)
  - Enhance AutoGen: Agents for planning and analysis
  - Add fallback: Generate report from state if shell fails
  - Ensure seamless LLM switching (commercial for speed, local for privacy)

### Phase 3: Microservice Polish and Security (2-3 weeks)
- **Tasks**:
  - Add RabbitMQ features: Queues, acknowledgments, and dead-letter queues for errors
  - Implement logging/monitoring: Backend `/health` endpoint, log container outputs
  - Security audit: Ensure no host execution of tools, add queue rate limiting
  - CLI enhancements: Progress updates via status queue, handle timeouts

### Phase 4: Deployment and Testing (1-2 weeks)
- **Tasks**:
  - Deployment strategies (see below)
  - End-to-end testing with safe IPs and mock containers
  - Stress test with multiple requests

<h1 align="center">Deployment Strategies</h1>

### Shared Foundation
- **Containerization**:
  - Dockerfile for CLI (as binary), backend (Python app), RabbitMQ (official image), and Ollama
- **Local/Dev**: Docker Compose with a single `docker-compose.yml` to spin up all services
- **Production**: Kubernetes manifests for pods (backend deployment, RabbitMQ statefulset)

### On-Premise Deployment
- **Hardware**: Local machine or VM with Docker/K8s
- **Setup**: Docker Compose for simplicity (`docker-compose up`)
- **LLM**: Local models via Ollama container (e.g., Llama3)
- **Access**: CLI runs on user’s