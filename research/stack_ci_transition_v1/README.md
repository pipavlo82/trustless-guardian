# Stack CI transition v1 (local candidate)

Historical manifests, guards, reports and research sources are unchanged.
The unchanged full-tree checker runs at exact PR1, while the new pinned checker
verifies current files plus explicit README/workflow transitions and research additions.
The Windows launcher helpers are byte-identical backports from PR4 e772eebd3ae3fee91237fa62b2caa3be0517684f.
Full historical Windows v04 validation still runs, including surviving/failed mutations;
there is no new PASS mapping. Elevated startup and ordinary local startup are separate paths.
External review and production remain HOLD. New CI has not run on GitHub (no push).
Pass the independently recorded INVENTORY.json SHA256 to every entry point.
The workflow contains that pin once; its recorded hash normalizes that single self-reference
to __POLICY_SHA256__. All other bytes must match. Changing policy and workflow together
requires a new external source/policy review; this is not protection against a trusted author.
