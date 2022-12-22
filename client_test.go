package abuseipdbgo

import (
	"fmt"
	"testing"
)

const apiKey = "YOUR_API_KEY_HERE"

var client = New(apiKey)

func TestNewClient(t *testing.T) {
	expected := Client{
		apiKey,
	}

	if client != expected {
		t.Fatalf(`Client generated incorrectly: expected %v, got %v`, expected, client)
	}
}

func TestCheck(t *testing.T) {
	res, err := client.Check("1.1.1.1")

	if err != nil {
		panic(err)
	}

	fmt.Println(res)
}

func TestGetReports(t *testing.T) {
	res, err := client.GetReports("1.1.1.1", 1, 100)

	if err != nil {
		panic(err)
	}

	fmt.Println(res)
}
