package openplatform

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
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

func TestPublicReviewsProjectionValidatesOptionalTermID(t *testing.T) {
	items := []ReviewItem{
		{ID: "r1", Kind: "course", TargetID: "c1", TermID: "2024-fall", Body: "Good course", Ratings: [5]int{9, 8, 6, 6, 9}, CreatedAt: time.Unix(1700000000, 0).UTC()},
		{ID: "r2", Kind: "mentor", TargetID: "t1", Body: "Helpful advisor", Ratings: [5]int{0, 0, 0, 0, 0}, CreatedAt: time.Unix(1700000100, 0).UTC()},
	}
	out, err := project("public_reviews", Data{Reviews: &items})
	if err != nil || out.Reviews == nil || len(*out.Reviews) != 2 {
		t.Fatalf("unexpected public_reviews projection: %+v err=%v", out, err)
	}
	raw1, _ := json.Marshal((*out.Reviews)[0])
	raw2, _ := json.Marshal((*out.Reviews)[1])
	if !strings.Contains(string(raw1), `"term_id":"2024-fall"`) || strings.Contains(string(raw2), `"term_id"`) {
		t.Fatalf("unexpected term_id serialization: r1=%s r2=%s", raw1, raw2)
	}

	var nilSlice []ReviewItem
	emptyOut, err := project("public_reviews", Data{Reviews: &nilSlice})
	if err != nil || emptyOut.Reviews == nil {
		t.Fatalf("expected nil slice normalized to empty slice: %+v err=%v", emptyOut, err)
	}
	rawEmpty, _ := json.Marshal(emptyOut)
	if !strings.Contains(string(rawEmpty), `"public_reviews":[]`) {
		t.Fatalf("expected non-null empty public_reviews array: %s", rawEmpty)
	}

	for _, bad := range []ReviewItem{
		{ID: "r3", Kind: "course", TargetID: "c1", TermID: strings.Repeat("x", 129), Body: "b"},
		{ID: "r4", Kind: "course", TargetID: "c1", TermID: "2024\nfall", Body: "b"},
		{ID: "r5", Kind: "course", TargetID: "c1", TermID: string([]byte{0xff}), Body: "b"},
		{ID: "r6", Kind: "course", TargetID: "c1", Body: "b", Ratings: [5]int{11, 0, 0, 0, 0}},
	} {
		list := []ReviewItem{bad}
		if _, err := project("public_reviews", Data{Reviews: &list}); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("expected ErrUnavailable for invalid review item %+v, got %v", bad, err)
		}
	}
}
