# IPA

A collaborative effort to create prototype of the helper (or server) components
of the [Interoperable Private Attribution (IPA)
proposal](https://github.com/patcg-individual-drafts/ipa/).

IPA enables
[attribution](https://en.wikipedia.org/wiki/Attribution_(marketing)), providing
information about how advertising campaigns are delivering value to advertisers,
while giving users strong privacy assurances.  IPA uses multi-party computation
(MPC) to achieve this goal.  IPA relies on three helper nodes (servers) that are
trusted to faithfully execute the protocol without conspiring with other helper
nodes to violate user privacy.

## This Project

This project is intended to be a functional, performant, and comprehensible
implementation of the core IPA protocol.  This should allow for validation of
the implementation and should enable performance measurement.

The eventual goal is to provide the core of an implementation that could be
deployed and used.  This will require additional infrastructure in order to meet
the privacy and security goals of the project.

This is very much a work in progress; input is welcome.  However, see our
[contribution guidelines](./CONTRIBUTING.md) for some important notices
regarding how to participate in the project.
