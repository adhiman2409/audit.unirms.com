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
