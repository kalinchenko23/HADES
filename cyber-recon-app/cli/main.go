package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/rabbitmq/amqp091-go"
	"github.com/urfave/cli/v2"
)

// Error handling message
func failOnError(err error, msg string) {
	if err != nil {
		log.Panicf("%s: %s", msg, err)
	}
}

func main() {
	app := &cli.App{
		Name: "cyber-recon-cli",
		Commands: []*cli.Command{
			{
				Name: "recon",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "ip", Required: true},
				},
				Action: func(c *cli.Context) error {

					//setting up rebbit
					conn, err := amqp091.Dial("amqp://guest:guest@localhost:5672/")
					if err != nil {
						failOnError(err, "Failed to connect to RabbitMQ")
					}
					defer conn.Close()

					//connecting to a channel
					ch, err := conn.Channel()
					if err != nil {
						failOnError(err, "Failed to connect to RabbitMQ channel")
					}
					defer ch.Close()

					// Declare queues args: name, durable, delete when unused, exclusive, no waint, arguments
					_, err = ch.QueueDeclare("recon_requests", true, false, false, false, nil)
					if err != nil {
						failOnError(err, "Failed to create to recon_requests queu")
					}
					_, err = ch.QueueDeclare("recon_results", true, false, false, false, nil)
					if err != nil {
						failOnError(err, "Failed to create to recon_results queu")
					}

					// Publish
					msg := map[string]string{"ip": c.String("ip"), "task": "recon"}
					body, _ := json.Marshal(msg)
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()

					//Arguments: context, exchange, queu name, mandatory, immediate, message
					err = ch.PublishWithContext(ctx, "", "recon_requests", false, false, amqp091.Publishing{
						ContentType: "application/json",
						Body:        body,
					})
					if err != nil {
						failOnError(err, "Failed to publish message")
					}
					fmt.Println("Request sent. Waiting for results...")

					// Consume (blocking for simplicity)
					msgs, err := ch.Consume("recon_results", "", true, false, false, false, nil)
					if err != nil {
						failOnError(err, "Failed to consume message")
					}
					for d := range msgs {
						fmt.Printf("Received: %s\n", d.Body)
						break
					}
					return nil
				},
			},
		},
	}
	app.Run(os.Args)
}
