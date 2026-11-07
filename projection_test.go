package openplatform

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestQQProjectionNeverLeaksNumberForStatus(t *testing.T) {
	for _, bound := range []bool{false, true} {
		input := Data{QQBinding: &QQBinding{Bound: bound, Number: "123456"}}
		out, err := project("qq_binding_status", input)
		encoded, _ := json.Marshal(out)
		if err != nil || out.QQBinding == nil || out.QQBinding.Bound != bound || strings.Contains(string(encoded), "number") || input.QQBinding.Number != "123456" {
			t.Fatal(string(encoded), err)
		}
	}
	for _, scope := range []string{"qq_binding_status", "qq_binding_details"} {
		if _, err := project(scope, Data{}); !errors.Is(err, ErrUnavailable) {
			t.Fatal(scope, err)
		}
	}
	if _, err := project("qq_binding_details", Data{QQBinding: &QQBinding{Bound: true}}); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if _, err := validateScopes([]string{"qq_binding"}, false); !errors.Is(err, ErrInput) {
		t.Fatal(err)
	}
	if len(qqTiers([]string{"profile"})) != 0 || len(qqTiers([]string{"qq_binding_status", "qq_binding_details"})) != 2 {
		t.Fatal("incorrect consent tiers")
	}
}
