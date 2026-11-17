package openplatform

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"
)

func (s *Service) PrepareConsent(ctx context.Context, p Principal, key string, in ConsentInput) (Consent, error) {
	var out Consent
	if !validOwner(p.Owner) {
		return out, ErrUnauthenticated
	}
	var e error
	in.Scopes, e = validateScopes(in.Scopes, false)
	if e != nil || in.Method != "S256" || len(in.Challenge) != 43 || len(in.State) < 16 || len(in.State) > 512 || !validText(in.State, 512, false) {
		return out, ErrInput
	}
	b, e := base64.RawURLEncoding.DecodeString(in.Challenge)
	if e != nil || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != in.Challenge {
		return out, ErrInput
	}
	e = s.transaction(ctx, p.Owner, in.ClientID, func(t Transaction) error {
		if e := s.activeOwner(t, p.Owner); e != nil {
			return e
		}
		var e error
		out, e = replay(t, p.Owner, key, "prepare-consent", in, func() (Consent, error) {
			pending, e := t.PendingConsents(p.Owner, s.now())
			if e != nil {
				return out, e
			}
			if pending >= 100 {
				return out, ErrConflict
			}
			a, e := s.validApp(t, in.ClientID)
			if e != nil {
				return out, e
			}
			if !slices.Contains(a.View.RedirectURIs, in.RedirectURI) || !subset(in.Scopes, a.View.ApprovedScopes) {
				return out, ErrForbidden
			}
			id, e := s.random()
			if e != nil {
				return out, e
			}
			activeScopes, activeExpiresAt, e := s.activeGrantSnapshot(t, p.Owner, a)
			if e != nil {
				return out, e
			}
			out = Consent{
				QQTiers:              qqTiers(in.Scopes),
				ID:                   id,
				Application:          ConsentApplication{ID: a.View.ID, Name: a.View.Name, Purpose: a.View.Purpose, ClientType: a.View.ClientType, GrantSeconds: a.View.Policy.GrantSeconds},
				Scopes:               in.Scopes,
				ActiveGrantedScopes:  activeScopes,
				ActiveGrantExpiresAt: activeExpiresAt,
				RedirectURI:          in.RedirectURI,
				ExpiresAt:            s.now().Add(5 * time.Minute),
			}
			e = t.SaveConsent(ConsentRecord{View: out, Owner: p.Owner, AppRevision: a.View.Revision, Input: in})
			return out, e
		})
		return e
	})
	return out, e
}
func (s *Service) activeGrantSnapshot(t Transaction, owner string, a AppRecord) ([]string, *time.Time, error) {
	g, e := t.OwnerGrant(owner, a.View.ID)
	if errors.Is(e, ErrNotFound) {
		return []string{}, nil, nil
	}
	if e != nil {
		return nil, nil, e
	}
	reason, e := s.grantReason(t, g, a)
	if e != nil {
		return nil, nil, e
	}
	if g.View.State != "active" || reason != "" {
		return []string{}, nil, nil
	}
	scopes := intersection(g.View.Scopes, a.View.ApprovedScopes)
	if len(scopes) == 0 {
		return []string{}, nil, nil
	}
	expiresAt := g.View.ExpiresAt
	return scopes, &expiresAt, nil
}
func (s *Service) Consent(ctx context.Context, p Principal, id string) (Consent, error) {
	var out Consent
	e := s.transaction(ctx, p.Owner, "", func(t Transaction) error {
		if e := s.activeOwner(t, p.Owner); e != nil {
			return e
		}
		c, e := t.Consent(id)
		if e != nil {
			return e
		}
		if c.Owner != p.Owner {
			return ErrNotFound
		}
		if !s.now().Before(c.View.ExpiresAt) {
			return ErrConflict
		}
		out = c.View
		if out.ActiveGrantedScopes == nil {
			out.ActiveGrantedScopes = []string{}
		}
		a, e := t.App(c.Input.ClientID)
		if e != nil {
			return e
		}
		if a.View.State != "active" || (c.AppRevision != 0 && a.View.Revision != c.AppRevision) {
			out.ActiveGrantedScopes = []string{}
			out.ActiveGrantExpiresAt = nil
			return nil
		}
		activeScopes, activeExpiresAt, e := s.activeGrantSnapshot(t, p.Owner, a)
		if e != nil {
			return e
		}
		out.ActiveGrantedScopes = activeScopes
		out.ActiveGrantExpiresAt = activeExpiresAt
		return nil
	})
	return out, e
}
func (s *Service) Decide(ctx context.Context, p Principal, id, key string, in ConsentDecision) (AuthorizationResult, error) {
	var out AuthorizationResult
	if e := s.ready(); e != nil {
		return out, e
	}
	if !validOwner(p.Owner) {
		return out, ErrUnauthenticated
	}
	mode := in.Mode
	if mode == "" {
		mode = "merge"
	}
	if mode != "merge" && mode != "replace" {
		return out, ErrInput
	}
	in.Mode = mode
	var e error
	in.Scopes, e = validateScopes(in.Scopes, in.Decision == "deny")
	if e != nil || (in.Decision != "approve" && in.Decision != "deny") || (in.Decision == "deny" && len(in.Scopes) != 0) {
		return out, ErrInput
	}
	located, e := s.Repo.LocateConsent(ctx, id)
	if e != nil {
		return out, e
	}
	if located.Owner != p.Owner {
		return out, ErrNotFound
	}
	e = s.transaction(ctx, p.Owner, located.Input.ClientID, func(t Transaction) error {
		if e := s.activeOwner(t, p.Owner); e != nil {
			return e
		}
		var e error
		out, e = replay(t, p.Owner, key, "decide-consent:"+id, in, func() (AuthorizationResult, error) {
			c, e := t.Consent(id)
			if e != nil {
				return out, e
			}
			if c.Decision != "" || !s.now().Before(c.View.ExpiresAt) {
				return out, ErrConflict
			}
			a, e := s.validApp(t, c.Input.ClientID)
			if e != nil {
				return out, e
			}
			if c.AppRevision != 0 && a.View.Revision != c.AppRevision {
				return out, ErrConflict
			}
			u, _ := url.Parse(c.Input.RedirectURI)
			q := u.Query()
			q.Set("state", c.Input.State)
			q.Set("iss", s.Issuer)
			c.Decision = in.Decision
			c.Selected = in.Scopes
			if in.Decision == "deny" {
				if !subset(in.Scopes, c.Input.Scopes) || !subset(in.Scopes, a.View.ApprovedScopes) {
					return out, ErrForbidden
				}
				q.Set("error", "access_denied")
			} else {
				now := s.now().Truncate(time.Microsecond)
				g, gErr := t.OwnerGrant(p.Owner, a.View.ID)
				if gErr != nil && !errors.Is(gErr, ErrNotFound) {
					return out, gErr
				}
				existingActive := []string{}
				priorReason := ""
				if gErr == nil && g.View.State == "active" {
					priorReason, e = s.grantReason(t, g, a)
					if e != nil {
						return out, e
					}
					if priorReason == "" {
						existingActive = intersection(g.View.Scopes, a.View.ApprovedScopes)
					}
				}
				allowedScopes := c.Input.Scopes
				if mode == "replace" {
					allowedScopes = union(c.Input.Scopes, existingActive)
				}
				if !subset(in.Scopes, allowedScopes) || !subset(in.Scopes, a.View.ApprovedScopes) {
					return out, ErrForbidden
				}
				nextScopes := in.Scopes
				if mode == "merge" && len(existingActive) > 0 {
					nextScopes = union(existingActive, in.Scopes)
				}
				if errors.Is(gErr, ErrNotFound) {
					gid, e := s.random()
					if e != nil {
						return out, e
					}
					subject, e := s.random()
					if e != nil {
						return out, e
					}
					g = GrantRecord{Owner: p.Owner, View: Grant{ID: gid, AppID: a.View.ID, Subject: subject, GrantedAt: now}}
				} else if g.View.State == "active" {
					removed := difference(g.View.Scopes, nextScopes)
					noticeReason := "consent_changed"
					if priorReason != "" {
						removed = g.View.Scopes
						noticeReason = priorReason
					}
					if len(removed) > 0 {
						if e = s.notice(t, g, removed, noticeReason); e != nil {
							return out, e
						}
					}
				}
				if g.View.GrantedAt.IsZero() {
					g.View.GrantedAt = now
				}
				g.View.AppName = a.View.Name
				g.View.Scopes = nextScopes
				g.View.State = "active"
				g.View.TerminationReason = ""
				g.View.UpdatedAt = now
				g.View.Revision++
				g.AppRevision = a.View.Revision
				g.View.ExpiresAt = now.Add(time.Duration(a.View.Policy.GrantSeconds) * time.Second)
				if e = t.SaveGrant(g); e != nil {
					return out, e
				}
				c.GrantID = g.View.ID
				c.GrantRevision = g.View.Revision
				c.CodeHash = hash(s.code(id))
				c.CodeExpiresAt = now.Add(time.Minute)
			}
			if e = t.SaveConsent(c); e != nil {
				return out, e
			}
			u.RawQuery = q.Encode()
			return AuthorizationResult{RedirectURI: u.String()}, nil
		})
		if e != nil {
			return e
		}
		saved, e := t.Consent(id)
		if e != nil {
			return e
		}
		if saved.Decision == "approve" {
			u, e := url.Parse(out.RedirectURI)
			if e != nil {
				return ErrUnavailable
			}
			q := u.Query()
			q.Set("code", s.code(id))
			u.RawQuery = q.Encode()
			out.RedirectURI = u.String()
		}
		return nil
	})
	return out, e
}
func validVerifier(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for _, c := range v {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~", c)) {
			return false
		}
	}
	return true
}
func (s *Service) Exchange(ctx context.Context, in TokenInput) (Token, error) {
	var out Token
	replayed := false
	if e := s.ready(); e != nil {
		return out, e
	}
	if in.GrantType != "authorization_code" || len(in.Code) > 160 || !validVerifier(in.Verifier) {
		return out, ErrInput
	}
	located, e := s.Repo.LocateCode(ctx, hash(in.Code))
	if e != nil {
		return out, lookupError(e)
	}
	e = s.transaction(ctx, located.Owner, located.Input.ClientID, func(t Transaction) error {
		if e := s.activeOwner(t, located.Owner); e != nil {
			return e
		}
		c, e := t.Consent(located.View.ID)
		if e != nil {
			return lookupError(e)
		}
		a, e := s.validApp(t, c.Input.ClientID)
		if e != nil {
			return e
		}
		if a.View.ClientType == "confidential" && !sameHash(a.SecretHash, hash(in.ClientSecret)) {
			return ErrClient
		}
		if a.View.ClientType == "public" && in.ClientSecret != "" {
			return ErrInput
		}
		challenge := sha256.Sum256([]byte(in.Verifier))
		if c.Decision != "approve" || c.Input.ClientID != in.ClientID || c.Input.RedirectURI != in.RedirectURI || (c.AppRevision != 0 && a.View.Revision != c.AppRevision) || base64.RawURLEncoding.EncodeToString(challenge[:]) != c.Input.Challenge {
			return ErrUnauthenticated
		}
		if c.Consumed {
			if e := t.RevokeCodeTokens(c.View.ID, c.GrantID); e != nil {
				return e
			}
			replayed = true
			return nil
		}
		if !s.now().Before(c.CodeExpiresAt) {
			return ErrUnauthenticated
		}
		g, e := t.Grant(c.GrantID)
		if e != nil {
			return lookupError(e)
		}
		reason, e := s.grantReason(t, g, a)
		if e != nil {
			return e
		}
		if g.View.Revision != c.GrantRevision || reason != "" {
			return ErrUnauthenticated
		}
		raw, e := s.random()
		if e != nil {
			return e
		}
		token := "op_" + raw
		expires := s.now().Add(time.Duration(a.View.Policy.TokenSeconds) * time.Second)
		if g.View.ExpiresAt.Before(expires) {
			expires = g.View.ExpiresAt
		}
		if e = t.SaveToken(TokenRecord{Hash: hash(token), ConsentID: c.View.ID, GrantID: g.View.ID, GrantRevision: g.View.Revision, AppRevision: a.View.Revision, ExpiresAt: expires}); e != nil {
			return e
		}
		c.Consumed = true
		if e = t.SaveConsent(c); e != nil {
			return e
		}
		if e = t.Event(g.Owner, "token_issued", g.View.ID, c.View.ID); e != nil {
			return e
		}
		out = Token{AccessToken: token, TokenType: "Bearer", ExpiresIn: int64(expires.Sub(s.now()).Seconds()), Scope: strings.Join(g.View.Scopes, " "), Subject: g.View.Subject}
		return nil
	})
	if e == nil && replayed {
		return Token{}, ErrUnauthenticated
	}
	return out, e
}

// qqTiers describes the precise disclosure requested on the consent page.
func qqTiers(scopes []string) []string {
	tiers := []string{}
	for _, scope := range scopes {
		switch scope {
		case "qq_binding_status":
			tiers = append(tiers, "binding_status")
		case "qq_binding_details":
			tiers = append(tiers, "binding_status_and_number")
		}
	}
	return tiers
}
