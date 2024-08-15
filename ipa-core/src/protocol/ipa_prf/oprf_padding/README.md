# Padding Dummy Records for OPRF IPA
For the OPRF IPA, if we are assuming a matchkey can occur at most $M$ times in a query, then using the replacement DP neighboring definition
we should use $\Delta = 2 * M$ as the sensitivity for the noise.  Then to each of the cardinalities we will add Truncated Double Geometric
noise for a decided $\epsilon, \delta$ and sensitivity $\Delta$.  The OPRFPaddingDp struct can be instantiated with these parameters and then
used to sample how many dummy records to generate for each cardinality of matchkey (e.g. a random number of users with 1 matchkey, a random number of users with 2 matchkeys, ..., a random number of users with $M$ matchkeys).

# Truncated Double Geometric (Discrete Laplace)
To determine how many dummy elements to add we implement some of the non-negative DP distributions from this [paper](https://arxiv.org/abs/2110.08177) focusing initially on the Truncated Double Geometric.


## Definition of Truncated Double Geometric
From Section 3.2 of the [paper](https://arxiv.org/abs/2110.08177) we recall the definition of the Truncated Double Geometric mechanism and distribuiton. Consider a mechanism using this distribution:

$$M(X) = f(X) + z; \quad z \sim p_{DoubleGeometric}(n)$$
$$\textrm{Pr}_{DoubleGeometric}(x|n) = Ae^{-\epsilon|n-x|}; \qquad x\in \{0,\ldots,2n\}$$

For some normalizing constant $0 \lt A \lt 1$ and some $n \in \mathbb{N}$.
As a probability this must sum to 1, which lets us solve for $A$.  Let $r=e^{-\epsilon}$.  Then we can rewrite as a classic geometric sequence as:
$$1=\Big(2 A\sum_{k=0}^n e^{-k\epsilon}\Big) -A = A\Big( -1 + 2\sum_{k=0}^n r^k \Big)
= A\Big( -1 + 2 \frac{1 - r^{n+1} }{1-r} \Big)
= A\Big( \frac{1 + r - 2r^{n+1} }{1-r} \Big) \nonumber$$
$$\Rightarrow \quad A = \frac{1-r}{1 + r - 2r^{n+1} } = \frac{1-e^{-\epsilon}}{1 + e^{-\epsilon} - 2e^{-\epsilon(n+1)}}$$


If we have sensitivity $\Delta \in \mathbb{Z}^+$, then we need $\delta$ to cover the tail as:
$$\delta \geq A \sum_{k=n-\Delta+1}^n  e^{-k \epsilon}$$


For the common case of $\Delta=1$, such as in counting queries of users, at equality this simplifies (see appendix A of the cited paper) to:
$$\delta = Ae^{-n \epsilon} = Ar^n = \frac{r^n(1-r)}{1 + r -2r^{n+1}}$$
$$\Rightarrow  \quad n = \Big\lceil -\frac{1}{\epsilon}\ ln \Big(\frac{\delta (1 + r)}{1-r + 2r\delta}\Big) \Big\rceil$$


The geometric distribution is unwieldy analytically beyond $\Delta=1$ so we instead compute $n$ numerically.  We do this by letting
$$RHS = A \sum_{k=n-\Delta+1}^n  e^{-k \epsilon}$$
and then for a fixed set of DP parameters $\varepsilon$, $\delta$, $\Delta$ we find the smallest $n$ that makes this RHS larger than $\delta$. This gives the narrowest Truncated Double Geometric that provides this level of DP for the given parameters.


## Sampling from a Truncated Double Geometric
The process of drawing a sample from a Truncated Double Geometric will be done by sampling from a series of distributions
1. We will assume access to samples from a Bernoulli distribution as provided by the `rand` crate
2. We will use this to implement sampling from a geometric distribution
3. We will use the geometric distribution to implement sampling from a double geometric distribution
4. We will use rejection sampleing from a double geometric to sample from a truncated double geometric.

### Sampling from the Geometric Distribuiton
We take the Geometric Distribution to be the probability distribution of the number of failures of Bernoulli trials before the first success, supported on the set $\{0,1,2,...\}$, with $0 < p \leq 1$ the success probability of the Bernoulli trials.

The mean of the geometric is $\mu = \frac{1-p}{p}$ and variance is $\sigma^2 = \frac{1-p}{p^2}$.

### Sampling from the Double Geometric Distribution
We use the following from this [book](https://www.researchgate.net/publication/258697410_The_Laplace_Distribution_and_Generalizations) page 159.

A double geometric distribution has probability function
$$f(k)=c(s)e^{|k-\theta|/s},k=0,\pm 1, \pm 2,...$$
where $\theta$ is an integer, $s$ is a positive real number, and $c(s)$ is a normalizing constant.  It is a property that a double geometric random variable, $Y$, with the above probability function can be represented as
$Y=\theta + X_1 - X_2$
where $X_1$ and $X_2$ are iid geometric variables with success probability $p = 1 - e^{-1/s}$.  We use this relation to sample from the double geometric by first drawing two independent samples from $X_1$ and $X_2$ and then computing their difference plus the shift by $\theta$.


The variance of a double geometric is the sum of the variances of the two independent geometrics, $X_1$ and $X_2$, so is $2 * (\frac{1-p}{p^2})$

### Samples from the Truncated Double Geometric Distribution
Once we can draw samples from a double geometric, we can sample from our desired truncated double geometric by sampling the double geometric with rejection if the sample lies outside the support set $\{0,...,2n\}$.

The variance of a truncated double geometric distribution is (TODO), but the variance is always less than the variance of the underlying (non-truncated) double geometric distribution.

# Padding Breakdowns Keys for New Aggregation
A new aggregation protocol reveals the breakdown keys in the clear before aggregating the associated secret
shared values.   This leaks the number of records for each breakdown key.  We can assume that there is a cap
enforced on the number of records for any one matchkey in IPA. Using this sensitivity we can then (with a desired epsilon,
delta) generate a random padding number of dummy rows with each breakdown key.

# Generating Padding for Matchkeys and Breakdown keys together
We need to add fake rows for matchkeys and fake rows for breakdown keys.  It makes sense to try and add the fake breakdown
keys to the fake rows already being generated for fake matchkeys. But this approach has a couple challenges:
1. We shouldn't add any fake breakdown keys to fake matchkey rows when the matchkey is being added with cardinality equal to one.
Because these rows can be dropped after matching and never have the fake breakdowns revealed.
2. There may need to be some adjustment made to the DP parameters achieved. TODO
3. We should not be adding fake breakdown keys to matchkeys that have a cardinality larger than the cap we have established for
the number of breakdowns per user. Otherwise, those breakdown keys would never be revealed as they will be dropped.

Instead of this approach we will the fake rows for matchkey padding first and then the fake rows for breakdown key padding. When
we generate the fake rows for breakdown key padding, the fake matchkeys generated will all have cardinality two or three (and with small probability one).
