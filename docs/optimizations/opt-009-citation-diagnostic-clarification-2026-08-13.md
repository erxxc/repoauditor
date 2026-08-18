# OPT-009 citation-format diagnostic clarification

This suffix is diagnostic-only and is not a production prompt revision.

For `citation_snippet`, copy only contiguous source-code text. Remove the displayed
`NUMBER<TAB>` prefix from every cited line; that prefix is presentation metadata and is
not part of the source file. For injection, cite the sink line that receives the tainted
value. Return an empty list when the supplied source does not establish the mechanism.
