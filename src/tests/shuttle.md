# Testing concurrent code with Shuttle

This note explains how to write concurrent tests for IPA using the Shuttle crate. IPA has been onboarded to Shuttle and
there were already a couple of issues uncovered by using concurrency testing. Having more code tested by Shuttle reduces
the chance of having intermittent failures in the future and makes software release more smooth.

## Why does IPA need it?

Testing concurrent code is hard because there is often an unbounded number of possible executions. There are multiple
approaches to it: [exhaustive space exploration](https://docs.rs/loom/latest/loom/) and [stochastic simulation](https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/asplos277-pct.pdf). Shuttle takes the latter approach and uses randomized
scheduling techniques to detect concurrency issues with high probability. Certain IPA layers benefit more from having
those tests

### Infrastructure
Infrastructure uses tasks and schedulers to keep up with the load, so it benefits greatly from having good coverage
of concurrency tests. In fact, [this issue](https://github.com/private-attribution/ipa/issues/256) was revealed only
after onboarding infrastructure to Shuttle.

### Protocols
Protocols are inherently asynchronous and vulnerable to the same class of concurrency issues as the infrastructure.

```rust
/// computes (a*b)/(c*d)
async fn mul_and_divide(a: Share, b: Share, c: Share, d: Share) -> Share {
    let mut futures = FuturesUnordered::new();
    futures.push(secure_mul(a, b));
    futures.push(secure_mul(c, d));
    
    // bug: c*d may be computed first, so this function may compute an inverse of the intended result
    let results = futures.collect().await;
    
    results[0] / results[1]
}
```


## How does it work?

There are multiple strategies to run a Shuttle test, most common one used in IPA involves randomized concurrency testing.
Shuttle picks a possible execution based on random choice. There is more in Shuttle than just a randomized scheduler, more information can be found
[here](https://docs.rs/shuttle/latest/shuttle/scheduler/index.html).

## Getting started

Shuttle tests live inside the `src/tests/` folder. The first line of each test module should be the following

```rust
#![cfg(all(feature = "shuttle", test))]
```

Shuttle test is a regular Rust test that uses Shuttle scheduler to run it. It cannot be made async, so `block_on` is used
to block the main thread awaiting future completion.

```rust
#[test]
fn my_first_concurrency_test() {
    // how many times Shuttle needs to schedule this test for execution.
    // Each execution will have a unique schedule, so keep it as high as possible.
    let iterations = 1000; 
    shuttle::check_random(|| { shuttle::future::block_on(async {
        // run semi-honest multiplication
        let world = TestWorld::default();

        let a = Fp31::from(2);
        let b = Fp31::from(5);

        let res = world.semi_honest((a, b), |ctx, (a, b)| async move { 
            ctx.multiply(RecordId::from(0), &a, &b).await.unwrap() 
        }).await;

        // assertions are important because some corruptions lead
        // to incorrect results rather than panic or deadlock
        assert_eq!(a * b, res.reconstruct());
    }) }, iterations);
}
```

## Running Shuttle tests

Execute the cargo `test` command with shuttle feature enabled:
```bash
cargo test --features shuttle
```

Running Shuttle tests and unit tests is not possible at the same time because they use different runtimes. 
The command above disables unit tests and only run concurrency tests. 

Running just one test is also possible

```bash
 cargo test --lib tests::protocol::semi_honest_ipa --features shuttle --exact
```

Omitting `--exact` flag will run all tests that match the `--lib` argument.

## Failures

Concurrency bugs manifest themselves as assertion violations, panics and deadlock errors.

#### Assertion violations 
Concurrency tests provide the most value when they can validate the results produced by a randomized execution. If results
are not correct, test will fail

```
test panicked in task 'main-thread'
failing schedule: "91038e14b4c9b..."
pass that string to `shuttle::replay` to replay the failure


Left:  5_mod31
Right: 13_mod31
```

In case of random input (PRSS, secret shares), left and right values will be different for each test execution.

### Panics
If an internal assertion does not hold under randomized test, it will panic:

```
test panicked in task 'main-thread'
index out of bounds: the len is 50 but the index is 1942298774
thread 'tests::randomized::sort' panicked at 'index out of bounds: the len is 50 but the index is 1942298774', src/protocol/sort/apply.rs:23:24
```

Typically running the same test as regular Rust test does not result in the same panic. 


### Deadlocks
This failure mode occurs when Shuttle cannot pick next execution because every task/thread is blocked. It must be taken seriously because it means
that some execution leads to the whole system getting stalled under some circumstances.

Running the following test produces a deadlock error

```rust
#[test]
fn deadlock() {
    shuttle::check_random(
        || {
            shuttle::future::block_on(async {
                let world = TestWorld::default();
                let input = Fp31::from(1u128);
                let results: [Replicated<Fp31>; 3] = world.semi_honest(input, |ctx, share| async move {
                    // this will lead to a deadlock. All three helpers blocked awaiting data from peers.
                    let left = ctx.mesh().receive::<Fp31>(ctx.role().peer(Direction::Left), RecordId::from(0)).await.unwrap();
                    let right = ctx.mesh().receive::<Fp31>(ctx.role().peer(Direction::Right), RecordId::from(0)).await.unwrap();

                    ctx.multiply(RecordId::from(1), &Replicated::new(left, right), &share).await.unwrap()
                }).await;
            }) }, 1);
}
```


```
deadlock! blocked tasks: [main-thread (task 0, pending future), <unknown> (task 1, pending future), <unknown> (task 2, pending future), <unknown> (task 3, pending future), <unknown> (task 4, pending future), <unknown> (task 5, pending future), <unknown> (task 6, pending future)]
failing schedule: "91033..."
pass that string to `shuttle::replay` to replay the failure
```

The error does not have enough information to say exactly what happened, but nevertheless must be investigated because
it reliably shows an execution that leads to a stall.


## Replaying errors
This is a hit-or-miss feature, as of Jan 2023 not working very reliably. Shuttle generates a unique string to make
any random execution deterministically reproducible. In some simple cases it works fine but any sort of non-determinism
inside the test or code being tested leads to Shuttle failing to replay failures.


## FAQ

### What class of issues is intended to be covered by concurrency testing?
As a rule of thumb, if there is an `await` point or `thread::spawn`, it is strongly preferred to have a concurrency test 
for it. 

**There is no added value** running the following code under Shuttle schedulers

### Can Shuttle tests serve as unit tests?
No. Concurrency testing complements unit testing, but it is not a replacement for it. 

```rust
async fn foo(a: u32, b: u32) -> u32 {
    // result is always 0, but there are no concurrency issues here. 
    secure_mul(a, 0*b).await?;
}
```

### How fast Shuttle tests are compared to unit tests?
In general, expect them to be much slower than unit tests. While not performing exhaustive search, randomized schedulers
tend to explore much bigger space compared to unit tests, so they need more time to work. 

**It should not, however, be an issue** because you only need to run them as part of CI workflow approval.


