# Documentation for DP in MPC

## Binomial Noise
To use binomial noise for DP, we refer to these two papers:
1. [Dwork et. al. 2006](https://www.iacr.org/archive/eurocrypt2006/40040493/40040493.pdf) which 
introduces Binomials for DP.
2. [Canonne et. al. 2018](https://arxiv.org/pdf/1805.10559.pdf) which gives a crucial tighter analysis of binomials and 
considers their use for d-dimension queries (such as we will need for WALR).


To achieve a desired $(\varepsilon, \delta)$-DP guarantee, we generate $num\\_bernoulli$ secret shared samples of a 
Bernoulli having probability $0.5$ using PRSS.  Next we aggregate them to get a Binomial sample. The result of the 2018 
paper above is that for small epsilon (TODO, how small required?), we require the following number of samples:

$$ num\\_bernoulli \geq \frac{8 \log \left( \frac{2}{\delta}\right)}{\varepsilon^2}$$

This [spreadsheet](https://docs.google.com/spreadsheets/d/1sMgqkMw3-yNBp6f8ctyv4Hdfx9Ei7muj0ZhP9i1DHrw/edit#gid=0) 
looks at the calculation for different parameter choices and confirms that this approach does lead to a better final 
variance of the noise than if each helper independently sampled Gaussian noise to add to the result (Note: the 2006 
paper's analysis isn't tight enough to show that the Binomial in MPC approach is better than the three independent 
Gaussians but the 2018 paper's analysis shows this).


## Binomial Noise for d-dimensional queries
For WALR we will be adding noise to a d-dimensional query, to add binomial noise we have to look 
simulatenously at the sensitivity under three different norms, $\ell_1, \ell_2, \ell_\infty$.  TODO. 
