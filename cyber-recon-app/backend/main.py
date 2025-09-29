import json
import pika
import time
import logging
from datetime import datetime, timezone
from graph import run_reconnaissance

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def process_recon(data):
    """
    Process reconnaissance request using LangGraph workflow.
    """
    logger.info(f"Starting reconnaissance for IP: {data.get('ip', 'Unknown')}")
    
    try:
        # Extract parameters with defaults
        ip = data.get('ip')
        if not ip:
            raise ValueError("IP address is required")
        
        user_input = data.get('user_input', f"Perform security assessment on {ip}")
        llm_provider = data.get('llm_provider', 'openai')
        api_key = data.get('api_key', '')
        local_model = data.get('local_model', '')
        
        # Validate required fields based on provider
        if llm_provider != 'ollama' and not api_key:
            raise ValueError(f"API key is required for {llm_provider}")
        
        logger.info(f"Using LLM provider: {llm_provider}")
        
        # Run reconnaissance using LangGraph workflow
        final_state = run_reconnaissance(
            ip=ip,
            user_input=user_input,
            llm_provider=llm_provider,
            api_key=api_key,
            local_model=local_model
        )
        
        # Determine the status based on the presence of errors in the final state
        if final_state.get('errors'):
            status = "error"
            error_message = str(final_state['errors'][-1])
        else:
            status = "success"
            error_message = ""

        logger.info(f"Reconnaissance completed with status: {status}")

        # Build a structured response from the final state
        response = {
            "status": status,
            "ip": final_state.get('ip'),
            "error_message": error_message,
            "current_step": final_state.get('current_step'),
            "scan_results": final_state.get('scan_results', {}),
            "vulnerabilities": final_state.get('vulns', []),
            "exploitation_attempted": final_state.get('exploitation_attempt', False),
            "shell_success": final_state.get('shell_success', False),
            "report": final_state.get('report', ''),
            "errors": final_state.get('errors', [])
        }
        
        return response
        
    except Exception as e:
        logger.error(f"Error in process_recon: {str(e)}")
        return {
            "status": "error",
            "ip": data.get('ip', 'Unknown'),
            "error_message": str(e),
            "current_step": "initialization_failed",
            "scan_results": {},
            "vulnerabilities": [],
            "exploitation_attempted": False,
            "shell_success": False,
            "report": f"Reconnaissance initialization failed: {str(e)}",
            "errors": [str(e)],
            "timestamp": time.time()
        }

def connect_with_retry(max_retries=5, retry_delay=2):
    """
    Connect to RabbitMQ with retry logic
    """
    logger.info("Attempting to connect to RabbitMQ...")
    
    for attempt in range(max_retries):
        try:
            connection = pika.BlockingConnection(
                pika.ConnectionParameters(
                    'localhost',
                    heartbeat=600,
                    blocked_connection_timeout=300
                )
            )
            logger.info("Successfully connected to RabbitMQ")
            return connection
        except pika.exceptions.AMQPConnectionError as e:
            logger.warning(f"Connection attempt {attempt + 1} failed: {e}")
            if attempt < max_retries - 1:
                logger.info(f"Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
            else:
                logger.error("All connection attempts failed")
                raise Exception(f"Failed to connect to RabbitMQ after {max_retries} attempts")

def setup_queues(channel):
    """
    Declare and configure RabbitMQ queues
    """
    # Declare queues with durability for persistence
    channel.queue_declare(queue='recon_requests', durable=True)
    channel.queue_declare(queue='recon_results', durable=True)
    logger.info("Queues declared successfully")

def callback(ch, method, properties, body):
    """
    Callback function for processing RabbitMQ messages
    The heart of the RabbitMQ consumer - executed for each message
    """
    start_time = time.time()
    correlation_id = properties.correlation_id if properties.correlation_id else "unknown"
    
    logger.info(f"Received message with correlation_id: {correlation_id}")
    
    try:
        # Parse incoming JSON
        data = json.loads(body.decode('utf-8'))
        logger.info(f"Processing request: {data}")
        
        # Validate message format
        if not isinstance(data, dict):
            raise ValueError("Message must be a JSON object")
        
        # Process reconnaissance request
        result = process_recon(data)
        
        # Add processing metadata
        result.update({
            "correlation_id": correlation_id,
            "processing_time": time.time() - start_time,
            "processed_at": datetime.now(timezone.utc).isoformat() # FIX: Used timezone-aware datetime
        })
        
        # Serialize and send response
        response = json.dumps(result, indent=2)
        
        # Publish result with correlation_id for tracing
        ch.basic_publish(
            exchange='',
            routing_key='recon_results',
            body=response,
            properties=pika.BasicProperties(
                correlation_id=correlation_id,
                content_type='application/json'
            )
        )
        
        # Acknowledge message as processed
        ch.basic_ack(delivery_tag=method.delivery_tag)
        
        logger.info(f"Successfully processed message {correlation_id} in {time.time() - start_time:.2f}s")
        
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in message {correlation_id}: {e}")
        error_response = {
            "status": "error",
            "error_message": f"Invalid JSON format: {str(e)}",
            "correlation_id": correlation_id,
            "timestamp": time.time()
        }
        
        # Send error response
        ch.basic_publish(
            exchange='',
            routing_key='recon_results',
            body=json.dumps(error_response),
            properties=pika.BasicProperties(
                correlation_id=correlation_id,
                content_type='application/json'
            )
        )
        
        # Acknowledge to remove from queue (don't requeue invalid JSON)
        ch.basic_ack(delivery_tag=method.delivery_tag)
        
    except Exception as e:
        logger.error(f"Error processing message {correlation_id}: {str(e)}")
        
        try:
            # Try to send error response
            error_response = {
                "status": "error",
                "error_message": str(e),
                "correlation_id": correlation_id,
                "processing_time": time.time() - start_time,
                "timestamp": time.time()
            }
            
            ch.basic_publish(
                exchange='',
                routing_key='recon_results',
                body=json.dumps(error_response),
                properties=pika.BasicProperties(
                    correlation_id=correlation_id,
                    content_type='application/json'
                )
            )
        except Exception as publish_error:
            logger.error(f"Failed to publish error response: {publish_error}")
        
        # Negative acknowledge - don't requeue to prevent infinite loops
        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)

def main():
    """
    Main function to start the RabbitMQ consumer
    """
    logger.info("Starting Reconnaissance Backend Service...")
    
    try:
        # Connect to RabbitMQ
        connection = connect_with_retry()
        channel = connection.channel()
        
        # Setup queues
        setup_queues(channel)
        
        # Configure consumer
        # QoS: Process one message at a time for better resource management
        channel.basic_qos(prefetch_count=1)
        
        # Start consuming
        channel.basic_consume(
            queue='recon_requests',
            on_message_callback=callback
        )
        
        logger.info("Backend waiting for reconnaissance requests...")
        logger.info("To stop the service, press CTRL+C")
        
        # Start consuming messages
        channel.start_consuming()
        
    except KeyboardInterrupt:
        logger.info("Received interrupt signal, shutting down gracefully...")
        try:
            channel.stop_consuming()
            connection.close()
            logger.info("Shutdown complete")
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")
            
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        raise

if __name__ == "__main__":
    main()