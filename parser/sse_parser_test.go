package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

func TestParseCodeWhispererEvents(t *testing.T) {
	data, err := os.ReadFile("response.raw")
	if err != nil {
		t.Skip("response.raw is a local debug fixture")
	}

	events := ParseEvents(data)

	for _, e := range events {
		fmt.Printf("event: %s\n", e.Event)
		json, _ := json.Marshal(e.Data)

		fmt.Printf("data: %s\n\n", string(json))
	}
}
