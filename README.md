# IPA

This branch contains a full implementation of IPA v2 protocol that is no longer evolved and has been deprecated in 
favour of IPA v3 (OPRF-based attribution). The dependency versions have been pinned to avoid regressions.

IPA v2 uses sort to group the match keys together and does not support sharding, while IPA v3 does. 

It was tested on Rust compiler version 1.76. It may or may not work on versions that are above that. 

For more information, see the README file in the main branch.
