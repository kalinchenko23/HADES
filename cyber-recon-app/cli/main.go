package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/rabbitmq/amqp091-go"
	"github.com/urfave/cli/v2"
)

type LLMConfig struct {
	Provider   string `json:"provider"`
	APIKey     string `json:"api_key"`
	LocalModel string `json:"local_model"`
}

type ValidationError struct {
	Field   string
	Message string
}

// Custom error interface
func (e ValidationError) Error() string {
	return fmt.Sprintf("validation error for field '%s': %s", e.Field, e.Message)
}

// Helper function for list of providers validation
func llmpPoviderContains(validProviders []string, provider string) bool {
	for _, s := range validProviders {
		if s == provider {
			return true
		}
	}
	return false
}

// Validate method belongs to LLMConfig struct and performs comprehensive
// validation on the config
func (c *LLMConfig) Validate() []ValidationError {
	var errors []ValidationError

	// Validate provider for presence
	if c.Provider == "" {
		errors = append(errors, ValidationError{
			Field:   "provider",
			Message: "provider is required",
		})

	// Validate provider for validity
	} else {
		validProviders := []string{"ollama", "openai", "anthropic", "gemini", "grok"}
		if !llmpPoviderContains(validProviders, c.Provider) {
			errors = append(errors, ValidationError{
				Field:   "provider",
				Message: fmt.Sprintf("provider must be one of: %s", strings.Join(validProviders, ", ")),
			})
		}

	}

	// Validate api_key for presence
	if c.APIKey == "" {
		errors = append(errors, ValidationError{
			Field:   "api_key",
			Message: "api_key is required",
		})

	// Validate api_key for validity (if less than 12 most likeley a placeholder)
	} else if len(c.APIKey) < 8 {
		errors = append(errors, ValidationError{
			Field:   "api_key",
			Message: "api_key is too short, must be a valid key",
		})
	}

	// Validate local_model for presence
	if c.LocalModel == "" {
		errors = append(errors, ValidationError{
			Field:   "local_model",
			Message: "local_model is required",
		})
	}

	return errors
}

// Main validation function for a config JSON data and validates the structure
func ParseAndValidateJSON(jsonData []byte) (*LLMConfig, []ValidationError, error) {

	//SECTION1: Checks JSON structure
	var raw map[string]interface{}

	if err := json.Unmarshal(jsonData, &raw); err != nil {
		return nil, nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	requiredFields := []string{"provider", "api_key", "local_model"}

	for _, field := range requiredFields {
		if _, exists := raw[field]; !exists {
			return nil, nil, fmt.Errorf("missing required field: %s", field)
		}
	}
	// Check for unexpected fields
	allowedFields := map[string]bool{
		"provider":    true,
		"api_key":     true,
		"local_model": true,
	}

	for field := range raw {
		if !allowedFields[field] {
			return nil, nil, fmt.Errorf("unexpected field: %s", field)
		}
	}

	//SECTION2: Checks JSON fields validity
	var config LLMConfig
	if err := json.Unmarshal(jsonData, &config); err != nil {
		return nil, nil, fmt.Errorf("failed to parse JSON: %w", err)
	}
	// Validate the fields by calling Validate method on LLMConfig structure
	validationErrors := config.Validate()

	return &config, validationErrors, nil
}

// Error handling message
func failOnError(err error, msg string) {
	if err != nil {
		log.Panicf("%s: %s", msg, err)
	}
}

// Validates IPv4
func validateIP(ip string) bool {
	re := regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)
	return re.MatchString(ip)
}

func main() {
	app := &cli.App{
		Name:  "HADES",
		Usage: "This tool is designed for reconnaissance and, under ideal circumstances, can establish a shell. At the very least, it will generate a detailed report.",
		
		//Defining main command and supporting arguments 
		Commands: []*cli.Command{
			{
				Name: "recon",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "ip", Required: true, Usage: "IP address `VALUE` of a target"},
					&cli.StringFlag{
						Name:     "config",
						Aliases:  []string{"c"},
						Required: true,
						Usage:    "Load LLM configuration from `FILE`",
					},
				},

				//Defining action that should be taken upon calling the command
				Action: func(c *cli.Context) error {

					//opening JSON file
					jsonData, err := os.ReadFile(c.String("config"))
					if err != nil {
						fmt.Printf("Error reading cofig file: %v\n", err)
						return nil
					}

					//Validating JSON
					llm_config, validationErrors, err := ParseAndValidateJSON(jsonData)
					if err != nil {
						return err
					}
					if len(validationErrors) > 0 {
						fmt.Println("Validation errors found:")
						for _, ve := range validationErrors {
							fmt.Printf("  - %s\n", ve.Error())
						}
						return fmt.Errorf("validation failed with %d errors", len(validationErrors))
					}

					//validate IP
					if !validateIP(c.String("ip")) {
						println("Please provide IP in range 0-255.0-255.0-255.0-255")
						return nil
					}

					//Setting up rebbitMQ
					conn, err := amqp091.Dial("amqp://guest:guest@localhost:5672/")
					if err != nil {
						failOnError(err, "Failed to connect to RabbitMQ")
						return nil
					}
					defer conn.Close()

					//Connecting to a rebbitMQ channel
					ch, err := conn.Channel()
					if err != nil {
						failOnError(err, "Failed to connect to RabbitMQ channel")
						return nil
					}
					defer ch.Close()

					//Declare queues args: name, durable, delete when unused, exclusive, no waint, arguments
					_, err = ch.QueueDeclare("recon_requests", true, false, false, false, nil)
					if err != nil {
						failOnError(err, "Failed to create to recon_requests queu")
						return nil
					}
					_, err = ch.QueueDeclare("recon_results", true, false, false, false, nil)
					if err != nil {
						failOnError(err, "Failed to create to recon_results queu")
						return nil
					}

					//Publish tp rebbitMQ queue
					msg := map[string]string{"ip": c.String("ip"), "llm_provider": llm_config.Provider, "api_key": llm_config.APIKey, "local_model": llm_config.LocalModel}
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
						return nil
					}
					fmt.Println("Request sent. Waiting for results...")

					//Consume from rebbitMQ queue(blocking for simplicity)
					msgs, err := ch.Consume("recon_results", "", true, false, false, false, nil)
					if err != nil {
						failOnError(err, "Failed to consume message")
						return nil
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
	//Calling the cli app
	if err := app.Run(os.Args); err != nil {
		fmt.Println(err)
	}
}
