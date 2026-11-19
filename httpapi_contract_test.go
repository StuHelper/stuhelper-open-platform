package openplatform_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	op "github.com/StuHelper/stuhelper-open-platform"
	"github.com/StuHelper/stuhelper-open-platform/httpapi"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

type openAPIDoc struct {
	Paths      map[string]map[string]openAPIOperation `json:"paths"`
	Components struct {
		Parameters map[string]map[string]any `json:"parameters"`
		Responses  map[string]openAPIResp    `json:"responses"`
		Schemas    map[string]map[string]any `json:"schemas"`
	} `json:"components"`
}

type openAPIOperation struct {
	OperationID string                 `json:"operationId"`
	Parameters  []map[string]any       `json:"parameters"`
	Responses   map[string]openAPIResp `json:"responses"`
}

type openAPIResp struct {
	Ref     string `json:"$ref"`
	Content map[string]struct {
		Schema map[string]any `json:"schema"`
	} `json:"content"`
}

func validateAgainstOpenAPI(t *testing.T, doc openAPIDoc, schema map[string]any, value any) {
	t.Helper()
	if ref, ok := schema["$ref"].(string); ok {
		name := strings.TrimPrefix(ref, "#/components/schemas/")
		target, exists := doc.Components.Schemas[name]
		if !exists {
			t.Fatalf("missing schema ref %s", ref)
		}
		validateAgainstOpenAPI(t, doc, target, value)
		return
	}
	typ, _ := schema["type"].(string)
	switch typ {
	case "object":
		obj, ok := value.(map[string]any)
		if !ok {
			t.Fatalf("expected JSON object, got %T (%v)", value, value)
		}
		props, _ := schema["properties"].(map[string]any)
		if reqList, ok := schema["required"].([]any); ok {
			for _, rawReq := range reqList {
				key, _ := rawReq.(string)
				if _, present := obj[key]; !present {
					t.Fatalf("missing required field %q in %v", key, obj)
				}
			}
		}
		if addl, ok := schema["additionalProperties"].(bool); ok && !addl {
			for k := range obj {
				if _, declared := props[k]; !declared {
					t.Fatalf("undeclared property %q in %v", k, obj)
				}
			}
		}
		for k, v := range obj {
			if propSchema, ok := props[k].(map[string]any); ok {
				validateAgainstOpenAPI(t, doc, propSchema, v)
			}
		}
	case "array":
		arr, ok := value.([]any)
		if !ok {
			t.Fatalf("expected JSON array, got %T (%v)", value, value)
		}
		itemSchema, _ := schema["items"].(map[string]any)
		for _, item := range arr {
			validateAgainstOpenAPI(t, doc, itemSchema, item)
		}
	case "string":
		str, ok := value.(string)
		if !ok {
			t.Fatalf("expected string, got %T (%v)", value, value)
		}
		if enumVals, ok := schema["enum"].([]any); ok {
			matched := false
			for _, ev := range enumVals {
				if ev == str {
					matched = true
					break
				}
			}
			if !matched {
				t.Fatalf("string %q not in enum %v", str, enumVals)
			}
		}
	case "integer":
		num, ok := value.(float64)
		if !ok || num != float64(int64(num)) {
			t.Fatalf("expected integer, got %T (%v)", value, value)
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			t.Fatalf("expected boolean, got %T (%v)", value, value)
		}
	}
}

func TestGeneratedServerBindingAndOpenAPIContractValidation(t *testing.T) {
	var doc openAPIDoc
	if err := json.Unmarshal(op.OpenAPI(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Components.Responses) == 0 || len(doc.Components.Parameters) == 0 {
		t.Fatal("expected reusable components.responses and components.parameters in OpenAPI")
	}
	// Verify all $ref in responses and parameters resolve, and /data/{scope} query descriptions are distinct.
	dataOp := doc.Paths["/api/v1/open-platform/data/{scope}"]["get"]
	seenDescriptions := map[string]bool{}
	for _, p := range dataOp.Parameters {
		if ref, ok := p["$ref"].(string); ok {
			key := strings.TrimPrefix(ref, "#/components/parameters/")
			if _, exists := doc.Components.Parameters[key]; !exists {
				t.Fatalf("unresolved parameter ref %s", ref)
			}
			continue
		}
		desc, _ := p["description"].(string)
		if desc == "" || seenDescriptions[desc] {
			t.Fatalf("duplicate or empty /data/{scope} parameter description: %q", desc)
		}
		seenDescriptions[desc] = true
	}

	x := setup(t)
	s := x.s
	baseHandler := httpapi.Handler{Service: s, Authenticate: func(r *http.Request) (op.Principal, error) {
		switch r.Header.Get("Authorization") {
		case "Bearer admin":
			return admin, nil
		case "Bearer dev":
			return dev, nil
		case "Bearer alice":
			return alice, nil
		default:
			return op.Principal{}, op.ErrUnauthenticated
		}
	}}

	callChecked := func(routeTemplate, method, reqPath, auth, key, body, contentType string, wantStatus int) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, "/api/v1/open-platform"+reqPath, strings.NewReader(body))
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		if key != "" {
			req.Header.Set("Idempotency-Key", key)
		}
		w := httptest.NewRecorder()
		baseHandler.ServeHTTP(w, req)
		if w.Code != wantStatus {
			t.Fatalf("%s %s: status=%d want=%d body=%s", method, reqPath, w.Code, wantStatus, w.Body.String())
		}
		if routeTemplate != "" {
			specOp := doc.Paths["/api/v1/open-platform"+routeTemplate][strings.ToLower(method)]
			respSpec, ok := specOp.Responses[strconv.Itoa(w.Code)]
			if !ok {
				t.Fatalf("undeclared status %d for %s %s", w.Code, method, routeTemplate)
			}
			if respSpec.Ref != "" {
				refKey := strings.TrimPrefix(respSpec.Ref, "#/components/responses/")
				resolved, exists := doc.Components.Responses[refKey]
				if !exists {
					t.Fatalf("missing response component %s", respSpec.Ref)
				}
				respSpec = resolved
			}
			var decoded any
			if err := json.Unmarshal(w.Body.Bytes(), &decoded); err != nil {
				t.Fatalf("invalid JSON response on %s %s: %v", method, reqPath, err)
			}
			validateAgainstOpenAPI(t, doc, respSpec.Content["application/json"].Schema, decoded)
		}
		return w
	}

	// Non-list endpoints reject undeclared ?after=&limit= parameters; non-canonical paths return 404 (not 301).
	wCreate := callChecked("/apps", http.MethodPost, "/apps", "Bearer dev", "k-create", `{"name":"ContractApp","purpose":"Verify generated router","redirect_uris":["https://client.example/cb"],"requested_scopes":["profile"],"client_type":"confidential"}`, "application/json", http.StatusOK)
	var created op.Application
	_ = json.Unmarshal(wCreate.Body.Bytes(), &created)

	callChecked("/apps", http.MethodPost, "/apps?limit=10", "Bearer dev", "k-bad-q", `{"name":"ContractApp","purpose":"p","redirect_uris":["https://client.example/cb"],"requested_scopes":["profile"],"client_type":"public"}`, "application/json", http.StatusBadRequest)
	callChecked("/apps/{id}", http.MethodGet, "/apps/"+created.ID+"?after=cursor", "Bearer dev", "", "", "", http.StatusBadRequest)
	callChecked("/apps/{id}", http.MethodGet, "/apps/"+created.ID, "Bearer dev", "", "", "", http.StatusOK)
	callChecked("/apps", http.MethodGet, "/apps?limit=10", "Bearer dev", "", "", "", http.StatusOK)
	callChecked("/admin/apps", http.MethodGet, "/admin/apps?limit=10", "Bearer admin", "", "", "", http.StatusOK)

	wRev := callChecked("/admin/apps/{id}/review", http.MethodPost, "/admin/apps/"+created.ID+"/review", "Bearer admin", "k-rev", fmt.Sprintf(`{"revision":%d,"decision":"approve","approved_scopes":["profile"],"policy":{"grant_seconds":600,"token_seconds":600,"daily_quota":50},"note":"ok"}`, created.Revision), "application/json", http.StatusOK)
	_ = json.Unmarshal(wRev.Body.Bytes(), &created)

	wCred := callChecked("/apps/{id}/credential", http.MethodPost, "/apps/"+created.ID+"/credential", "Bearer dev", "k-cred", `{"revision":0}`, "application/json", http.StatusOK)
	var cred op.Credential
	_ = json.Unmarshal(wCred.Body.Bytes(), &cred)

	verifier := strings.Repeat("z", 43)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	wCon := callChecked("/consents", http.MethodPost, "/consents", "Bearer alice", "k-con", fmt.Sprintf(`{"client_id":%q,"redirect_uri":%q,"state":%q,"scope":["profile"],"code_challenge":%q,"code_challenge_method":"S256"}`, created.ID, created.RedirectURIs[0], strings.Repeat("s", 16), challenge), "application/json", http.StatusOK)
	var con op.Consent
	_ = json.Unmarshal(wCon.Body.Bytes(), &con)

	callChecked("/consents/{id}", http.MethodGet, "/consents/"+con.ID+"?limit=5", "Bearer alice", "", "", "", http.StatusBadRequest)
	callChecked("/consents/{id}", http.MethodGet, "/consents/"+con.ID, "Bearer alice", "", "", "", http.StatusOK)

	wDec := callChecked("/consents/{id}/decision", http.MethodPost, "/consents/"+con.ID+"/decision", "Bearer alice", "k-dec", `{"decision":"approve","scopes":["profile"]}`, "application/json", http.StatusOK)
	var dec op.AuthorizationResult
	_ = json.Unmarshal(wDec.Body.Bytes(), &dec)
	parsedURL, _ := url.Parse(dec.RedirectURI)

	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {created.ID}, "redirect_uri": {created.RedirectURIs[0]}, "code": {parsedURL.Query().Get("code")}, "code_verifier": {verifier}}.Encode()
	basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(created.ID+":"+cred.Secret))
	wTok := callChecked("/token", http.MethodPost, "/token", basicAuth, "", form, "application/x-www-form-urlencoded", http.StatusOK)
	var tok op.Token
	_ = json.Unmarshal(wTok.Body.Bytes(), &tok)

	callChecked("/data/{scope}", http.MethodGet, "/data/profile", "Bearer "+tok.AccessToken, "", "", "", http.StatusOK)
	wGrants := callChecked("/grants", http.MethodGet, "/grants", "Bearer alice", "", "", "", http.StatusOK)
	var grantsPage op.Page[op.Grant]
	_ = json.Unmarshal(wGrants.Body.Bytes(), &grantsPage)
	callChecked("/grants/{id}/revoke", http.MethodPost, "/grants/"+grantsPage.Items[0].ID+"/revoke", "Bearer alice", "k-revoke", fmt.Sprintf(`{"revision":%d,"scopes":["profile"]}`, grantsPage.Items[0].Revision), "application/json", http.StatusOK)

	wNotices := callChecked("/apps/{id}/notices", http.MethodGet, "/apps/"+created.ID+"/notices", basicAuth, "", "", "", http.StatusOK)
	var noticesPage op.Page[op.Notice]
	_ = json.Unmarshal(wNotices.Body.Bytes(), &noticesPage)
	callChecked("/apps/{id}/notices/{notice_id}/ack", http.MethodPost, "/apps/"+created.ID+"/notices/"+noticesPage.Items[0].ID+"/ack", basicAuth, "k-ack", `{"status":"deleted","note":""}`, "application/json", http.StatusOK)

	// Double-slash and unsupported HTTP methods return 404 Problem JSON without redirects.
	callChecked("", http.MethodGet, "//apps", "Bearer dev", "", "", "", http.StatusNotFound)
	callChecked("", http.MethodDelete, "/apps", "Bearer dev", "", "", "", http.StatusNotFound)
}
