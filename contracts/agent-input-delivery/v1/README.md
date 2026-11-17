# Generic agent input delivery v1

This is a public source-level transport contract, not an enabled runtime capability. Runtime preparation and image/Agent integration are not wired. No production image is certified by these fixtures.

`sourceRevision` is the Git HEAD immediately before authoring this export (a reproducible lineage anchor), **not** the commit containing exported bytes. Manifest hashes identify exact checked-in bytes. Re-export only after an intentional source/contract revision; a future change should update this provenance anchor.

Policy admission checks the trusted execution enterprise before reading values; each load uses one projected generation. Secrets are byte-preserved; collisions reject even identical/empty existing values. Only named error codes are public. Unsupported targets include Windows, external-host and lab. Unrelated legacy inputs remain unchanged. Delivery and runtime scrubbing/tool boundaries require later integration and exact-image verification before activation.
