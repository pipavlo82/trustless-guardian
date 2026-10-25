# Architecture foundation

An action gateway receives structured requests. A deterministic policy engine
checks an independently selected policy. An enforcement broker owns the ability
to change a protected resource. A recorder preserves observations and an independent
verifier recomputes policy results and checks evidence.

The experimental Windows boundary is a distinct low-privilege agent security
principal and OS-enforced resource access. A policy decision alone is insufficient.
