package audit

import (
	"encoding/json"
	"strings"
	"time"
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
	if r.Kind == "config" && !r.BodyTruncated && len(r.rawBody) != 0 {
		var body any
		if json.Unmarshal(r.rawBody, &body) == nil {
			redact(body)
			r.Body = body
		}
	}
	r.rawBody, r.rawError = nil, nil
}

func redact(value any) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			switch strings.ToLower(key) {
			case "password", "token", "secret", "otp":
				v[key] = "[redacted]"
			default:
				redact(child)
			}
		}
	case []any:
		for _, child := range v {
			redact(child)
		}
	}
}
