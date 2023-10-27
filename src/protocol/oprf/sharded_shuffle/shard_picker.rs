use rand::{
    distributions::{WeightedError, WeightedIndex},
    prelude::Distribution,
    Rng,
};

#[derive(Debug, Clone, Copy)]
struct ShardInfo {
    empty_slots: usize,
}

struct ShardPicker {
    total_available_slots: usize,
    shards: Box<[ShardInfo]>,
    dist: WeightedIndex<usize>,
}

impl ShardPicker {
    pub fn new(num_shards: usize, shard_size: usize) -> Result<Self, WeightedError> {
        let shards = vec![
            ShardInfo {
                empty_slots: shard_size,
            };
            num_shards
        ]
        .into_boxed_slice();

        let weights = shards
            .iter()
            .map(|s| s.empty_slots)
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let dist = WeightedIndex::new(weights.iter())?;

        Ok(Self {
            total_available_slots: num_shards * shard_size,
            shards,
            dist,
        })
    }

    pub fn pick_shard_and_update_dist<R: Rng>(
        &mut self,
        rng: &mut R,
    ) -> Result<usize, WeightedError> {
        if self.total_available_slots == 0 {
            return Err(WeightedError::AllWeightsZero);
        }

        let shard_idx = self.pick_shard_idx(rng);
        self.shards[shard_idx].empty_slots -= 1;
        self.total_available_slots -= 1;

        if self.total_available_slots > 0 {
            let new_weight = self.shards[shard_idx].empty_slots;
            self.update_weights(&[(shard_idx, &new_weight)])?;
        }

        Ok(shard_idx)
    }

    fn pick_shard_idx<R: Rng>(&mut self, rng: &mut R) -> usize {
        self.dist.sample(rng)
    }

    fn update_weights(&mut self, new_weights: &[(usize, &usize)]) -> Result<(), WeightedError> {
        self.dist.update_weights(new_weights)
    }
}

mod tests {
    use super::*;
    use rand::{distributions::WeightedError, thread_rng};

    #[test]
    fn picks_from_all_shards() {
        let mut rng = thread_rng();
        let mut sampler = ShardPicker::new(3, 1).unwrap();
        let mut picks =
            std::iter::repeat_with(|| sampler.pick_shard_and_update_dist(&mut rng).unwrap())
                .take(3)
                .collect::<Vec<_>>();

        picks.sort_unstable();
        assert_eq!(picks, [0, 1, 2], "Expected to pick all available shards");

        let err = sampler.pick_shard_and_update_dist(&mut rng);
        assert_eq!(err, Err(WeightedError::AllWeightsZero));
    }

    #[test]
    fn considers_weights() {
        let mut rng = thread_rng();

        for _ in 0..10 {
            let mut sampler = ShardPicker::new(3, 100).unwrap();

            sampler
                .update_weights(&[(0, &0), (1, &0), (2, &100)])
                .unwrap();

            let picked_idx = sampler.pick_shard_and_update_dist(&mut rng).unwrap();
            assert_eq!(
                picked_idx, 2,
                "Expecting it to always pick shard 2 as all other shards have 0 weights"
            );
        }
    }
}
