import json
import pika
import time
from graph import app

# Placeholder for LangGraph (expanded in next steps)
def process_recon(data):
    result=app.invoke({"ip": data['ip'], "llm_provider" : data["llm_provider"],"api_key" : data["api_key"],"local_model" : data["local_model"]})['result']
    return result

# This function is responsible for connecting to the RabbitMQ 
def connect_with_retry():
    for _ in range(5):
        try:
            return pika.BlockingConnection(pika.ConnectionParameters('localhost'))
        except pika.exceptions.AMQPConnectionError:
            time.sleep(2)
    raise Exception("Failed to connect to RabbitMQ")


connection = connect_with_retry()
channel = connection.channel()

# Declaring queues
channel.queue_declare(queue='recon_requests', durable=True)
channel.queue_declare(queue='recon_results', durable=True)

# This function tells what to do with the message and how to publish it back to the results queue 
# The callback function is the heart of the RabbitMQ consumer - it's what gets executed every time a message arrives.
def callback(ch, method, properties, body):
    try:
        data = json.loads(body) # Parse incoming JSON
        result = process_recon(data)
        response = json.dumps(result) # Serialize response
        ch.basic_publish(exchange='', routing_key='recon_results', body=response) # Send result
        ch.basic_ack(delivery_tag=method.delivery_tag) # Acknowledge message processed
    except Exception as e:
        print(f"Error processing message on the request consumer side: {e}")
        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
        
# Consumer Configuration
channel.basic_qos(prefetch_count=1)
channel.basic_consume(queue='recon_requests', on_message_callback=callback)
print('Backend waiting for messages...')
channel.start_consuming()