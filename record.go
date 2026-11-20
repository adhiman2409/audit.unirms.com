package audit

import (
	"encoding/json"
	"sort"
	"strings"
	"time"
	"unicode"
)

type record struct {
	At            time.Time         `bson:"at"`
	Kind          string            `bson:"kind"`
	Service       string            `bson:"service"`
	Route         string            `bson:"route"`
	Method        string            `bson:"method"`
	Path          string            `bson:"path"`
	PathVars      map[string]string `bson:"path_vars,omitempty"`
	Status        int               `bson:"status"`
	Error         string            `bson:"error,omitempty"`
	DurationMS    int64             `bson:"duration_ms"`
	Domain        string            `bson:"domain"`
	ActorID       string            `bson:"actor_id"`
	ActorName     string            `bson:"actor_name"`
	ActorEmail    string            `bson:"actor_email"`
	ActorRole     string            `bson:"actor_role"`
	Department    string            `bson:"department"`
	CorrelationID string            `bson:"correlation_id,omitempty"`
	IP            string            `bson:"ip"`
	Body          any               `bson:"body,omitempty"`
	BodyTruncated bool              `bson:"body_truncated,omitempty"`
	TargetIDs     []string          `bson:"target_ids,omitempty"`
	rawBody       []byte            `bson:"-"`
	rawError      []byte            `bson:"-"`
}

func (r *record) prepare() {
	if r.Status >= 400 {
		var response struct{ Message string }
		if json.Unmarshal(r.rawError, &response) == nil {
			chars := []rune(response.Message)
			if len(chars) > 300 {
				chars = chars[:300]
			}
			r.Error = string(chars)
		}
	}
	var body any
	parsed := len(r.rawBody) != 0 && len(r.rawBody) <= maxScanBytes && json.Unmarshal(r.rawBody, &body) == nil
	r.TargetIDs = targetIDs(r.PathVars, body)
	if r.Kind == "config" && !r.BodyTruncated && parsed {
		redact(body)
		r.Body = body
	}
	r.rawBody, r.rawError = nil, nil
}

// targetKeys are the request fields that name the employee a call acts on,
// compared lower-case without underscores. Role fields such as manager_eid are
// deliberately left out: they name someone involved, not the record changed.
var targetKeys = map[string]bool{
	"eid": true, "eids": true, "employeeid": true, "employeeids": true, "employeeidlist": true,
	"empid": true, "empids": true,
}

const maxTargetIDs = 50

// targetIDs lists the employees a request acts on: the {eid} path variable and
// every targetKeys field anywhere in the JSON body, without duplicates.
func targetIDs(vars map[string]string, body any) []string {
	var ids []string
	seen := map[string]bool{}
	add := func(id string) {
		id = strings.TrimSpace(id)
		if id != "" && !seen[id] && len(ids) < maxTargetIDs {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	add(vars["eid"])
	var walk func(value any)
	walk = func(value any) {
		switch v := value.(type) {
		case map[string]any:
			for key, child := range v {
				if targetKeys[strings.ToLower(strings.ReplaceAll(key, "_", ""))] {
					switch id := child.(type) {
					case string:
						add(id)
					case []any:
						for _, item := range id {
							if s, ok := item.(string); ok {
								add(s)
							}
						}
					}
					continue
				}
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(body)
	sort.Strings(ids)
	return ids
}

func redact(value any) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			if sensitiveKey(key) {
				v[key] = "[redacted]"
			} else {
				redact(child)
			}
		}
	case []any:
		for _, child := range v {
			redact(child)
		}
	}
}

var sensitiveParts = []string{"password", "passwd", "secret", "token", "apikey", "privatekey", "accesskey", "credential"}

// sensitiveKey matches a key after lower-casing it and dropping _ - . and spaces,
// so smtp_password, apiKey and client-secret all match. "otp" only matches at
// either end, so words that merely contain it (footprint) are kept.
func sensitiveKey(key string) bool {
	k := strings.Map(func(r rune) rune {
		switch r {
		case '_', '-', '.', ' ':
			return -1
		}
		return unicode.ToLower(r)
	}, key)
	if strings.HasPrefix(k, "otp") || strings.HasSuffix(k, "otp") {
		return true
	}
	for _, part := range sensitiveParts {
		if strings.Contains(k, part) {
			return true
		}
	}
	return false
}
