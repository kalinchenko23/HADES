import json
import pika
from graph import app

# Placeholder for LangGraph (expanded in next steps)
def process_recon(data):
    result=app.invoke({"ip": data['ip']})['result']
    return result

connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
channel = connection.channel()
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