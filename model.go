// Package openplatform owns approved applications and separately consented business grants.
package openplatform

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

var (
	ErrInput           = errors.New("invalid_input")
	ErrUnauthenticated = errors.New("unauthenticated")
	ErrForbidden       = errors.New("forbidden")
	ErrNotFound        = errors.New("not_found")
	ErrConflict        = errors.New("conflict")
	ErrUnavailable     = errors.New("unavailable")
	ErrQuota           = errors.New("quota_exceeded")
	ErrClient          = errors.New("invalid_client")
)
var Scopes = []string{"student_status", "schools", "qq_binding_status", "qq_binding_details", "profile", "schedule", "catalog", "public_reviews"}

type Principal struct {
	Owner string
	Admin bool
}
type Policy struct {
	GrantSeconds int `json:"grant_seconds"`
	TokenSeconds int `json:"token_seconds"`
	DailyQuota   int `json:"daily_quota"`
}
type ApplicationInput struct {
	Name            string   `json:"name"`
	Purpose         string   `json:"purpose"`
	RedirectURIs    []string `json:"redirect_uris"`
	RequestedScopes []string `json:"requested_scopes"`
	ClientType      string   `json:"client_type"`
	Revision        int64    `json:"revision,omitempty"`
}
type Application struct {
	ID                 string    `json:"id"`
	Name               string    `json:"name"`
	Purpose            string    `json:"purpose"`
	RedirectURIs       []string  `json:"redirect_uris"`
	RequestedScopes    []string  `json:"requested_scopes"`
	ApprovedScopes     []string  `json:"approved_scopes"`
	ClientType         string    `json:"client_type"`
	State              string    `json:"state"`
	Note               string    `json:"note"`
	Revision           int64     `json:"revision"`
	CredentialRevision int64     `json:"credential_revision"`
	Policy             Policy    `json:"policy"`
	CreatedAt          time.Time `json:"created_at"`
}
type AppRecord struct {
	View              Application
	Owner, SecretHash string
}
type ReviewInput struct {
	Revision       int64    `json:"revision"`
	Decision       string   `json:"decision"`
	ApprovedScopes []string `json:"approved_scopes"`
	Policy         Policy   `json:"policy"`
	Note           string   `json:"note"`
}
type Credential struct {
	AppID       string `json:"app_id"`
	Revision    int64  `json:"revision"`
	Secret      string `json:"client_secret,omitempty"`
	Retrievable bool   `json:"retrievable"`
}
type ConsentInput struct {
	ClientID    string   `json:"client_id"`
	RedirectURI string   `json:"redirect_uri"`
	State       string   `json:"state"`
	Scopes      []string `json:"scope"`
	Challenge   string   `json:"code_challenge"`
	Method      string   `json:"code_challenge_method"`
}
type Consent struct {
	QQTiers     []string    `json:"qq_tiers"`
	ID          string      `json:"id"`
	Application Application `json:"application"`
	Scopes      []string    `json:"requested_scopes"`
	RedirectURI string      `json:"redirect_uri"`
	ExpiresAt   time.Time   `json:"expires_at"`
}
type ConsentRecord struct {
	View          Consent
	Owner         string
	Input         ConsentInput
	Decision      string
	Selected      []string
	CodeHash      string
	CodeExpiresAt time.Time
	Consumed      bool
	GrantID       string
	GrantRevision int64
}
type ConsentDecision struct {
	Decision string   `json:"decision"`
	Scopes   []string `json:"scopes"`
}
type AuthorizationResult struct {
	RedirectURI string `json:"redirect_uri"`
}
type TokenInput struct{ GrantType, ClientID, RedirectURI, Code, Verifier, ClientSecret string }
type Token struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope"`
	Subject     string `json:"subject"`
}
type TokenRecord struct {
	Hash, GrantID, ConsentID   string
	GrantRevision, AppRevision int64
	ExpiresAt                  time.Time
}
type Grant struct {
	ID        string    `json:"id"`
	AppID     string    `json:"app_id"`
	AppName   string    `json:"app_name"`
	Subject   string    `json:"subject"`
	Scopes    []string  `json:"scopes"`
	State     string    `json:"state"`
	ExpiresAt time.Time `json:"expires_at"`
	Revision  int64     `json:"revision"`
}
type GrantRecord struct {
	View        Grant
	Owner       string
	AppRevision int64
}
type RevokeInput struct {
	Revision int64    `json:"revision"`
	Scopes   []string `json:"scopes"`
}
type Notice struct {
	Sequence        int64      `json:"sequence"`
	ID              string     `json:"id"`
	AppID           string     `json:"app_id"`
	Subject         string     `json:"subject"`
	Scopes          []string   `json:"scopes"`
	Reason          string     `json:"reason"`
	CreatedAt       time.Time  `json:"created_at"`
	SeenAt          *time.Time `json:"seen_at,omitempty"`
	Acknowledgement string     `json:"acknowledgement,omitempty"`
	Note            string     `json:"note,omitempty"`
	AcknowledgedAt  *time.Time `json:"acknowledged_at,omitempty"`
}
type Acknowledgement struct {
	Status string `json:"status"`
	Note   string `json:"note"`
}
type Page[T any] struct {
	Items []T    `json:"items"`
	Next  string `json:"next,omitempty"`
}
type Query struct {
	ID, Kind, Query, TermID, TargetID, After string
	Limit                                    int
}
type StudentStatus struct {
	Verified    bool      `json:"verified"`
	EvaluatedAt time.Time `json:"evaluated_at"`
}
type School struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type QQBinding struct {
	Bound  bool   `json:"bound"`
	Number string `json:"number,omitempty"`
}
type Profile struct {
	ID       string `json:"id"`
	Nickname string `json:"nickname"`
	Bio      string `json:"bio"`
}
type ScheduleMeeting struct {
	ID       string `json:"id"`
	TimeText string `json:"time_text"`
	Location string `json:"location"`
}
type ScheduleItem struct {
	ID         string            `json:"id"`
	CourseID   string            `json:"course_id"`
	CourseName string            `json:"course_name"`
	TermID     string            `json:"term_id"`
	ClassID    string            `json:"class_id"`
	Meetings   []ScheduleMeeting `json:"meetings"`
	FetchedAt  time.Time         `json:"fetched_at"`
	Active     bool              `json:"active"`
}
type CatalogItem struct {
	ID           string `json:"id"`
	Kind         string `json:"kind"`
	SchoolID     string `json:"school_id"`
	Name         string `json:"name"`
	CourseID     string `json:"course_id,omitempty"`
	TermID       string `json:"term_id,omitempty"`
	DepartmentID string `json:"department_id,omitempty"`
	Biography    string `json:"biography,omitempty"`
	Revision     int64  `json:"revision"`
}
type ReviewItem struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	TargetID  string    `json:"target_id"`
	Body      string    `json:"body"`
	Ratings   [5]int    `json:"ratings"`
	CreatedAt time.Time `json:"created_at"`
}

// Data uses closed projections so a provider cannot accidentally return raw credentials or verification material.
type Data struct {
	Subject       string          `json:"subject"`
	Scope         string          `json:"scope"`
	StudentStatus *StudentStatus  `json:"student_status,omitempty"`
	Schools       *[]School       `json:"schools,omitempty"`
	QQBinding     *QQBinding      `json:"qq_binding,omitempty"`
	Profile       *Profile        `json:"profile,omitempty"`
	Schedule      *[]ScheduleItem `json:"schedule,omitempty"`
	Catalog       *[]CatalogItem  `json:"catalog,omitempty"`
	Reviews       *[]ReviewItem   `json:"public_reviews,omitempty"`
	Next          string          `json:"next,omitempty"`
}

// Source receives only the verified grant owner; content sources must enforce current admission.
type Source interface {
	Read(context.Context, string, string, Query) (Data, error)
}
type Repository interface {
	Transaction(context.Context, string, string, func(Transaction) error) error
	LocateConsent(context.Context, string) (ConsentRecord, error)
	LocateCode(context.Context, string) (ConsentRecord, error)
	LocateToken(context.Context, string) (TokenRecord, GrantRecord, error)
	LocateGrant(context.Context, string) (GrantRecord, error)
	WorkCandidates(context.Context, time.Time, int) ([]GrantRecord, error)
}
type Transaction interface {
	Closed(string) (bool, error)
	CloseOwner(string, string) error
	App(string) (AppRecord, error)
	Apps(string, bool, string, int) ([]AppRecord, error)
	SaveApp(AppRecord) error
	CountApps(string) (int, error)
	SuspendOwnedApps(string) error
	Consent(string) (ConsentRecord, error)
	PendingConsents(string, time.Time) (int, error)
	SaveConsent(ConsentRecord) error
	Grant(string) (GrantRecord, error)
	OwnerGrant(string, string) (GrantRecord, error)
	Grants(string, string, int) ([]GrantRecord, error)
	SaveGrant(GrantRecord) error
	Token(string) (TokenRecord, error)
	SaveToken(TokenRecord) error
	RevokeCodeTokens(string, string) error
	Quota(string, string, int) error
	Notice(string) (Notice, error)
	Notices(string, string, int) ([]Notice, error)
	SaveNotice(Notice) error
	Replay(string, string) (string, json.RawMessage, error)
	SaveReplay(string, string, string, json.RawMessage) error
	Event(string, string, string, string) error
}
