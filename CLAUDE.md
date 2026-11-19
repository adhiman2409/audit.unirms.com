# audit.unirms.com

Two things live here:

- The `audit` package (repo root): a library the services import to record
  requests into each tenant's `audit_logs` collection. Released by git tag
  (`v0.1.3`, ...); services pick it up by bumping the module version.
- `cmd/viewer`: the web page at https://audit.unirms.com that reads those logs.

## Deploying the viewer

There is no CI for the viewer, and the server does not build it. The image is
built locally, pushed to Docker Hub, and the cluster pulls it.

1. Commit and push the change to `main`.
2. Build and push a new tag. Never reuse a tag: the cluster will not re-pull it.
   ```bash
   docker buildx build --platform linux/amd64 --provenance=false --sbom=false \
     -t hs14/audit-viewer:<next version> --push .
   ```
   Keep `--provenance=false --sbom=false`: containerd on the unp cluster needs
   a plain image manifest.
3. Set `image: hs14/audit-viewer:<next version>` in `deploy/viewer.yaml` and
   commit it.
4. On the server: `microk8s kubectl apply -f deploy/viewer.yaml`.
5. Check that https://audit.unirms.com serves the new page.

Docker Hub tags show what has been published:
`https://hub.docker.com/v2/repositories/hs14/audit-viewer/tags`.

The `hs14/audit-viewer` image is public, so the manifest has no
`imagePullSecrets`. The cluster's `regcred` cannot pull from the hs14 account.

## Tenant-facing API

The audit log API for the UNIRMS frontend is not in this repo. It lives in
`organization.unirms.com` (`POST /organization/auditlogs`) and reads the same
`audit_logs` collections.
