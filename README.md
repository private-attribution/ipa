# Raw IPA

A collaborative effort to generate a raw, but broadly functional, prototype of
the [Interoperable Private Attribution (IPA)
proposal](https://docs.google.com/document/d/1KpdSKD8-Rn0bWPTu4UtK54ks0yv2j22pA5SrAD9av4s/edit#heading=h.f4x9f0nqv28x).

The goal of this project is to explore a stricter threat model than the original
proposal assumes, with the potential for malicious but non-colluding servers.
That is, servers (or helpers) that do no collude with each other, though they
may collude with user agents (browsers or mobile operating systems), websites,
or mobile apps.

The tools here will not include fully functional servers and clients, but
instead command-line utilities that operate on files.

The focus is on readable code that is easy to understand and modify.  This code
might be useful for evaluating performance claims, but only in general terms; a
full and performant implementation is likely to be much faster.

A token effort will be made to meet privacy and security goals. However, this is
only for the purposes of learning.  No serious effort will be made to ensure
that these goals are met and therefore this code is **not fit for production
use**.


## Getting started

1. Install [cargo-make](https://github.com/sagiegurari/cargo-make):

```bash
cargo install cargo-make
```

2. Building code

The following command runs the same checks as Github CI approval workflow, so it is useful 
to validate code before submitting a PR

```bash
cargo make touch
```

to produce binaries, run `cargo build`

