# audit.unirms.com

Two things live here:

- The `audit` package (repo root): a library the services import to record
  requests into each tenant's `audit_logs` collection. Released by git tag
  (`v0.1.3`, ...); services pick it up by bumping the module version.
- `cmd/viewer`: the web page at https://audit.unirms.com that reads those logs.

## Deploying the viewer

CI builds the viewer image, same as the other UNIRMS services:

- Push to `dev`: `cicd-dev.yaml` builds `pineswift/demo-audit-viewer:<DEV version>`
  and deploys it to the demo cluster (file
  `~/depl.jobs.pineswift.com/unirms.com/audit-viewer-depl.yaml` on the demo
  server, source `deploy/viewer-demo.yaml`).
- Push to `main`: `cicd-prod.yaml` builds `pineswift/audit-viewer:<PROD version>`
  and posts it to Google Chat. It does not deploy.

Versions come from the `DEV-*` / `PROD-*` git tags CI creates. The library's
`v*` tags are separate.

Rolling a prod build out to https://audit.unirms.com (unp cluster) is manual:
set `image: pineswift/audit-viewer:<version>` in `deploy/viewer.yaml`, commit
it, and on the server run `microk8s kubectl apply -f deploy/viewer.yaml`.

Build with `--provenance=false --sbom=false` (CI does): containerd on the
clusters needs a plain image manifest. pineswift images are private and pulled
with the clusters' `regcred`.

## Tenant-facing API

The audit log API for the UNIRMS frontend is not in this repo. It lives in
`organization.unirms.com` (`POST /organization/auditlogs`) and reads the same
`audit_logs` collections.
