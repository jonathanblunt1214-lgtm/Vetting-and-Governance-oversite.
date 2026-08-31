# Independent oversight policy

This repository has two purposes only: independently vet bounded candidate-data manifests and independently oversee The Crucible's governance and operation.

The Crucible may not write here, choose this repository's verifier identity, change an oversight result, close a failed review, or treat oversight approval as automatic scientific proof. Oversight never imports Crucible runtime modules. It inspects a disposable read-only checkout and evaluates data with its own code.

Candidate data is untrusted and never executable. Manifests contain hashes and provenance, not secrets, credentials, private source contents, raw telemetry, binaries, or instructions. Passing vetting means only that a manifest is structurally reviewable; claims still require Crucible's controlled testing and distinct scientific verifier.

Oversight results bind the exact Crucible commit and input hashes. Failures are retained in the workflow record and report artifact. The workflow has read-only repository access and cannot modify Crucible.
