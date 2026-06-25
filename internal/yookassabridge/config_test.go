package yookassabridge

import "testing"

func TestParsePlans(t *testing.T) {
	plans, err := parsePlans("100,250:9000", 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 2 {
		t.Fatalf("len = %d, want 2", len(plans))
	}
	if plans[0] != (Plan{AmountRUB: 100, Quota: 5000}) {
		t.Fatalf("first plan = %+v", plans[0])
	}
	if plans[1] != (Plan{AmountRUB: 250, Quota: 9000}) {
		t.Fatalf("second plan = %+v", plans[1])
	}
}
