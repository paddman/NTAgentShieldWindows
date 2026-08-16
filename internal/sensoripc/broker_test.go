package sensoripc

import (
	"fmt"
	"testing"

	"github.com/paddman/NTAgentShieldWindows/internal/model"
)

func TestBrokerReplaysUntilExactAcknowledgement(t *testing.T) {
	broker, err := NewBroker(128, nil)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 3; index++ {
		if err := broker.Add(model.Event{ID: fmt.Sprintf("evt-%d", index), Kind: "process.exec", Trust: model.TrustOperator}); err != nil {
			t.Fatal(err)
		}
	}
	first, err := broker.Poll(PollRequest{MaxEvents: 2})
	if err != nil || len(first.Events) != 2 || first.BatchID == "" {
		t.Fatalf("first poll: %#v err=%v", first, err)
	}
	if first.Events[0].Trust != model.TrustUntrustedTelemetry {
		t.Fatal("helper telemetry did not remain untrusted")
	}
	replay, err := broker.Poll(PollRequest{MaxEvents: 2})
	if err != nil || replay.BatchID != first.BatchID || replay.Events[0].ID != first.Events[0].ID {
		t.Fatalf("unacknowledged batch was not replayed: %#v err=%v", replay, err)
	}
	if _, err := broker.Poll(PollRequest{AckBatchID: "wrong", MaxEvents: 2}); err == nil {
		t.Fatal("incorrect batch acknowledgement was accepted")
	}
	next, err := broker.Poll(PollRequest{AckBatchID: first.BatchID, MaxEvents: 2})
	if err != nil || len(next.Events) != 1 || next.Events[0].ID != "evt-2" {
		t.Fatalf("acknowledged poll did not advance: %#v err=%v", next, err)
	}
	retriedAck, err := broker.Poll(PollRequest{AckBatchID: first.BatchID, MaxEvents: 2})
	if err != nil || retriedAck.BatchID != next.BatchID || retriedAck.Events[0].ID != "evt-2" {
		t.Fatalf("lost ACK response was not idempotent: %#v err=%v", retriedAck, err)
	}
}

func TestBrokerBoundsQueueAndCountsLoss(t *testing.T) {
	broker, err := NewBroker(128, nil)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 130; index++ {
		_ = broker.Add(model.Event{ID: fmt.Sprintf("evt-%03d", index), Kind: "file.write"})
	}
	response, err := broker.Poll(PollRequest{MaxEvents: 128})
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Events) != 128 || response.Health.QueueDropped != 2 || response.Events[0].ID != "evt-002" {
		t.Fatalf("unexpected bounded queue state: events=%d health=%#v first=%s", len(response.Events), response.Health, response.Events[0].ID)
	}
	if err := broker.Add(model.Event{ID: "evt-full", Kind: "file.write"}); err == nil {
		t.Fatal("new event was accepted while the entire bound was pending")
	}
}
