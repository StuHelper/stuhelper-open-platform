package openplatform

import "context"

func (s *Service) Apply(ctx context.Context, p Principal, id, key string, in ApplicationInput) (Application, error) {
	var out Application
	if !validOwner(p.Owner) {
		return out, ErrUnauthenticated
	}
	if e := validateApp(&in); e != nil {
		return out, e
	}
	e := s.transaction(ctx, p.Owner, id, func(t Transaction) error {
		if e := s.activeOwner(t, p.Owner); e != nil {
			return e
		}
		var e error
		out, e = replay(t, p.Owner, key, "application:"+id, in, func() (Application, error) {
			var a AppRecord
			if id == "" {
				n, e := t.CountApps(p.Owner)
				if e != nil {
					return out, e
				}
				if n >= 100 {
					return out, ErrConflict
				}
				id, e = s.random()
				if e != nil {
					return out, e
				}
				a = AppRecord{Owner: p.Owner, View: Application{ID: id, Revision: 1, CreatedAt: s.now(), ApprovedScopes: []string{}}}
			} else {
				var e error
				a, e = t.App(id)
				if e != nil {
					return out, e
				}
				if a.Owner != p.Owner {
					return out, ErrNotFound
				}
				if a.View.State == "active" || a.View.Revision != in.Revision {
					return out, ErrConflict
				}
				a.View.Revision++
				a.View.ApprovedScopes = []string{}
				a.View.Note = ""
				a.View.Policy = Policy{}
			}
			a.View.Name = in.Name
			a.View.Purpose = in.Purpose
			a.View.RedirectURIs = in.RedirectURIs
			a.View.RequestedScopes = in.RequestedScopes
			a.View.ClientType = in.ClientType
			a.View.State = "pending"
			if e := t.SaveApp(a); e != nil {
				return out, e
			}
			return a.View, nil
		})
		return e
	})
	return out, e
}
func (s *Service) Application(ctx context.Context, p Principal, id string) (Application, error) {
	var out Application
	e := s.transaction(ctx, p.Owner, id, func(t Transaction) error {
		if e := s.activeOwner(t, p.Owner); e != nil {
			return e
		}
		a, e := t.App(id)
		if e != nil {
			return e
		}
		if a.Owner != p.Owner && !p.Admin {
			return ErrNotFound
		}
		out = a.View
		return nil
	})
	return out, e
}
func (s *Service) Applications(ctx context.Context, p Principal, admin bool, after string, limit int) (Page[Application], error) {
	var out Page[Application]
	if !validOwner(p.Owner) {
		return out, ErrUnauthenticated
	}
	if admin && !p.Admin {
		return out, ErrForbidden
	}
	limit, e := pagination(after, limit)
	if e != nil {
		return out, e
	}
	e = s.transaction(ctx, p.Owner, "", func(t Transaction) error {
		if e := s.activeOwner(t, p.Owner); e != nil {
			return e
		}
		rows, e := t.Apps(p.Owner, admin, after, limit+1)
		if e != nil {
			return e
		}
		items := []Application{}
		for _, a := range rows {
			items = append(items, a.View)
		}
		out = page(items, limit, func(a Application) string { return a.ID })
		return nil
	})
	return out, e
}
func (s *Service) Review(ctx context.Context, p Principal, id, key string, in ReviewInput) (Application, error) {
	var out Application
	if !validOwner(p.Owner) {
		return out, ErrUnauthenticated
	}
	if !p.Admin {
		return out, ErrForbidden
	}
	if in.Revision < 1 || !validText(in.Note, 1000, true) || (in.Decision != "approve" && in.Decision != "changes_requested" && in.Decision != "suspend") {
		return out, ErrInput
	}
	var e error
	in.ApprovedScopes, e = validateScopes(in.ApprovedScopes, in.Decision != "approve")
	if e != nil {
		return out, e
	}
	if in.Decision == "approve" && !policyValid(in.Policy) {
		return out, ErrInput
	}
	e = s.transaction(ctx, p.Owner, id, func(t Transaction) error {
		if e := s.activeOwner(t, p.Owner); e != nil {
			return e
		}
		var e error
		out, e = replay(t, p.Owner, key, "review:"+id, in, func() (Application, error) {
			a, e := t.App(id)
			if e != nil {
				return out, e
			}
			if e = s.activeOwner(t, a.Owner); e != nil {
				return out, e
			}
			if a.View.Revision != in.Revision {
				return out, ErrConflict
			}
			if !subset(in.ApprovedScopes, a.View.RequestedScopes) {
				return out, ErrInput
			}
			switch in.Decision {
			case "approve":
				a.View.State = "active"
				a.View.ApprovedScopes = in.ApprovedScopes
				a.View.Policy = in.Policy
			case "changes_requested":
				a.View.State = "changes_requested"
			case "suspend":
				a.View.State = "suspended"
			}
			a.View.Revision++
			a.View.Note = in.Note
			if e = t.SaveApp(a); e != nil {
				return out, e
			}
			return a.View, nil
		})
		return e
	})
	return out, e
}
func (s *Service) RotateCredential(ctx context.Context, p Principal, id, key string, revision int64) (Credential, error) {
	var out Credential
	if !validOwner(p.Owner) {
		return out, ErrUnauthenticated
	}
	if revision < 0 {
		return out, ErrInput
	}
	var secret string
	e := s.transaction(ctx, p.Owner, id, func(t Transaction) error {
		if e := s.activeOwner(t, p.Owner); e != nil {
			return e
		}
		a, e := t.App(id)
		if e != nil {
			return e
		}
		if a.Owner != p.Owner {
			return ErrNotFound
		}
		out, e = replay(t, p.Owner, key, "credential:"+id, revision, func() (Credential, error) {
			if a.View.CredentialRevision != revision {
				return out, ErrConflict
			}
			v, e := s.random()
			if e != nil {
				return out, e
			}
			secret = "opsecret_" + v
			a.SecretHash = hash(secret)
			a.View.CredentialRevision++
			if e = t.SaveApp(a); e != nil {
				return out, e
			}
			return Credential{AppID: id, Revision: a.View.CredentialRevision, Retrievable: false}, nil
		})
		return e
	})
	if e == nil && secret != "" {
		out.Secret = secret
		out.Retrievable = true
	}
	return out, e
}
func (s *Service) validApp(t Transaction, id string) (AppRecord, error) {
	a, e := t.App(id)
	if e != nil {
		return a, e
	}
	if e = s.activeOwner(t, a.Owner); e != nil {
		return a, e
	}
	if a.View.State != "active" || !policyValid(a.View.Policy) {
		return a, ErrForbidden
	}
	return a, nil
}
func authenticatedApp(t Transaction, p Principal, id, secret string) (AppRecord, error) {
	a, e := t.App(id)
	if e != nil {
		return a, e
	}
	if secret != "" {
		if !sameHash(a.SecretHash, hash(secret)) {
			return a, ErrUnauthenticated
		}
		return a, nil
	}
	if !validOwner(p.Owner) {
		return a, ErrUnauthenticated
	}
	closed, e := t.Closed(p.Owner)
	if e != nil {
		return a, e
	}
	if closed {
		return a, ErrForbidden
	}
	if a.Owner != p.Owner {
		return a, ErrNotFound
	}
	return a, nil
}
