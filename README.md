# audit

Asynchronous audit logging for gorilla/mux services. After authentication has put
the JSON claims string in the request context under `"claims"`, wire the service:

```go
audit.Start(mongoClient, "my-service")
router.Use(audit.Middleware(audit.Options{CaptureBody: []string{"update-config"}}))
defer audit.Close(shutdownContext)
```

Use a bounded shutdown context when closing. Set `AUDIT_DISABLED=true` before
`Start` to disable auditing. Records go to `audit_logs` in each domain's database
(dots in the domain become underscores). Writes are batched in the background;
full queues and failed batches are dropped and logged. Captured JSON configuration
bodies are capped at 8 KB and sensitive keys are redacted.

## Viewer

`cmd/viewer` is a small web page for reading the audit trail: pick an
organisation, filter by service, person, date or failures, open a row for the
full record. It only reads. Sign-in is one username and password from
`AUDIT_UI_USER` and `AUDIT_UI_PASSWORD` (12 characters or more); MongoDB comes
from the same `DB_ADDR`, `DB_PORT`, `DB_USER` and `DB_PASSWORD` the services use.
The session cookie is `Secure`, so serve it over HTTPS (localhost also works).

```bash
docker buildx build --platform linux/amd64 --provenance=false --sbom=false -t hs14/audit-viewer:0.1.1 --push .
microk8s kubectl apply -f deploy/viewer.yaml   # see the secret note at the top
```
