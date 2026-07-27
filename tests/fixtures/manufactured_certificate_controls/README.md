# Manufactured deterministic certificate controls

This zero-network cohort continuously checks known-positive and known-negative structural
certificate shapes. The human-authored answer key is in `manifest.json`, outside `snapshot/`,
so retrieval never sees expected outcomes.

These cases qualify only the bounded deterministic producer/checker contracts. They do not
estimate real-world precision, recall, exploitability, or control effectiveness, and they
are not training data. Live-provider qualification remains in the separate four-case
`manufactured_sentinels` cohort so this offline expansion does not silently increase paid
weekly usage.
