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

func TestAllScopesProjectionsNormalizeNilSlicesFilterInactiveScheduleAndValidateBounds(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

	// 1. student_status
	if _, err := project("student_status", Data{StudentStatus: &StudentStatus{Verified: true}}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable for zero EvaluatedAt, got %v", err)
	}
	st, err := project("student_status", Data{StudentStatus: &StudentStatus{Verified: true, EvaluatedAt: now}, Profile: &Profile{Nickname: "leak"}})
	if err != nil || st.StudentStatus == nil || !st.StudentStatus.Verified || st.Profile != nil {
		t.Fatal(st, err)
	}

	// 2. schools (nil slice normalized to [], bounds checked)
	var nilSchools []School
	sc, err := project("schools", Data{Schools: &nilSchools})
	rawSc, _ := json.Marshal(sc)
	if err != nil || strings.Contains(string(rawSc), `"schools":null`) || !strings.Contains(string(rawSc), `"schools":[]`) {
		t.Fatalf("nil schools slice serialized as null: %s err=%v", string(rawSc), err)
	}
	if _, err := project("schools", Data{Schools: &[]School{{ID: "", Name: "Bad"}}}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable for empty School.ID, got %v", err)
	}

	// 3. profile (20 rune nickname, 120 rune bio)
	if _, err := project("profile", Data{Profile: &Profile{Nickname: strings.Repeat("北", 20), Bio: strings.Repeat("简", 120)}}); err != nil {
		t.Fatalf("valid 20/120 rune profile rejected: %v", err)
	}
	if _, err := project("profile", Data{Profile: &Profile{Nickname: strings.Repeat("北", 21)}}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable for >20 rune nickname, got %v", err)
	}

	// 4. schedule (nil Meetings normalized to [], Active==false filtered out, >100 meetings rejected)
	schedIn := []ScheduleItem{
		{ID: "enr-1", CourseID: "c-1", CourseName: "Calculus", TermID: "2026-fall", ClassID: "cls-1", Meetings: nil, FetchedAt: now, Active: true},
		{ID: "enr-dropped", CourseID: "c-2", CourseName: "Dropped", TermID: "2026-fall", ClassID: "cls-2", Meetings: []ScheduleMeeting{{ID: "m-2", TimeText: "Tue", Location: "R2"}}, FetchedAt: now, Active: false},
	}
	schedOut, err := project("schedule", Data{Schedule: &schedIn})
	rawSched, _ := json.Marshal(schedOut)
	if err != nil || len(*schedOut.Schedule) != 1 || (*schedOut.Schedule)[0].ID != "enr-1" || strings.Contains(string(rawSched), `"meetings":null`) || !strings.Contains(string(rawSched), `"meetings":[]`) {
		t.Fatalf("schedule projection failed nil-meetings normalization or inactive filtering: %s err=%v", string(rawSched), err)
	}
	tooManyMeetings := make([]ScheduleMeeting, 101)
	for i := range tooManyMeetings {
		tooManyMeetings[i] = ScheduleMeeting{ID: "m", TimeText: "Mon", Location: "Room"}
	}
	if _, err := project("schedule", Data{Schedule: &[]ScheduleItem{{ID: "enr-x", CourseID: "c-1", CourseName: "X", TermID: "t", ClassID: "cl", Meetings: tooManyMeetings, FetchedAt: now, Active: true}}}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable for >100 meetings, got %v", err)
	}

	// 5. catalog (nil slice normalized, required fields checked)
	var nilCatalog []CatalogItem
	catOut, err := project("catalog", Data{Catalog: &nilCatalog})
	rawCat, _ := json.Marshal(catOut)
	if err != nil || !strings.Contains(string(rawCat), `"catalog":[]`) {
		t.Fatalf("nil catalog slice serialized as null: %s err=%v", string(rawCat), err)
	}
	if _, err := project("catalog", Data{Catalog: &[]CatalogItem{{ID: "course-1", Kind: "course", SchoolID: "buaa", Name: "OS", Revision: 1}}}); err != nil {
		t.Fatal(err)
	}

	// 6. public_reviews (nil slice normalized, Ratings 0..10 and CreatedAt checked)
	var nilReviews []ReviewItem
	revOut, err := project("public_reviews", Data{Reviews: &nilReviews})
	rawRev, _ := json.Marshal(revOut)
	if err != nil || !strings.Contains(string(rawRev), `"public_reviews":[]`) {
		t.Fatalf("nil reviews slice serialized as null: %s err=%v", string(rawRev), err)
	}
	if _, err := project("public_reviews", Data{Reviews: &[]ReviewItem{{ID: "rev-1", Kind: "course", TargetID: "course-1", Body: "Great course", Ratings: [5]int{5, 5, 5, 5, 11}, CreatedAt: now}}}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable for out-of-range rating 11, got %v", err)
	}
	if _, err := project("public_reviews", Data{Reviews: &[]ReviewItem{{ID: "rev-1", Kind: "course", TargetID: "course-1", Body: "Great course", Ratings: [5]int{5, 4, 5, 4, 5}, CreatedAt: now}}}); err != nil {
		t.Fatal(err)
	}
}
