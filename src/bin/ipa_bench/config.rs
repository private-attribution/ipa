use log::error;
use rand_distr::num_traits::ToPrimitive;
use serde_json::Value;
use std::io::{BufReader, Read};
use std::ops::Range;
use std::process;

pub fn parse<R: Read>(input: &mut R) -> Config {
    let f = BufReader::new(input);

    let config: Value = serde_json::from_reader(f).unwrap();

    Config { config }
}

#[derive(Clone)]
pub struct Config {
    config: Value,
}

impl Config {
    fn weighted_index_u8_f64(&self, name: &str) -> Vec<(u8, f64)> {
        let config: &Vec<Value> = self.config[name]["weighted_index"]
            .as_array()
            .unwrap_or_else(|| {
                error!("Failed to read '{}' config.", name);
                process::exit(1);
            });

        let mut distr: Vec<(u8, f64)> = Vec::with_capacity(config.len());

        for i in config {
            let index = i["index"]
                .as_u64()
                .unwrap_or_else(|| {
                    error!("WeightedIndex key must be a number.");
                    process::exit(1);
                })
                .to_u8()
                .unwrap_or_else(|| {
                    error!("'{}' index value must be u8.", name);
                    process::exit(1);
                });

            let weight = i["weight"].as_f64().unwrap_or_else(|| {
                error!("'{}' weight value must be f64.", name);
                process::exit(1);
            });

            distr.push((index, weight));
        }

        distr
    }

    fn weighted_index_range_f64_f64(&self, name: &str) -> Vec<(Range<f64>, f64)> {
        let config: &Vec<Value> = self.config[name]["weighted_index"]
            .as_array()
            .unwrap_or_else(|| {
                error!("Failed to read '{}' config.", name);
                process::exit(1);
            });

        let mut distr: Vec<(Range<f64>, f64)> = Vec::with_capacity(config.len());

        for i in config {
            let start = i["index"]["start"].as_f64().unwrap_or_else(|| {
                error!("Range 'start' must be f64.");
                process::exit(1);
            });
            let end = i["index"]["end"].as_f64().unwrap_or_else(|| {
                error!("Range 'end' must be f64.");
                process::exit(1);
            });
            let weight = i["weight"].as_f64().unwrap_or_else(|| {
                error!("'{}' weight value must be Range<f64>.", name);
                process::exit(1);
            });

            distr.push((Range { start, end }, weight));
        }

        distr
    }

    fn weighted_index_range_u32_f64(&self, name: &str) -> Vec<(Range<u32>, f64)> {
        // Reuse range_f64_f64 and cast to u32
        let config = self.weighted_index_range_f64_f64(name);
        config
            .iter()
            .map(|i| {
                (
                    Range {
                        start: i.0.start.to_u32().unwrap(),
                        end: i.0.end.to_u32().unwrap(),
                    },
                    i.1,
                )
            })
            .collect()
    }

    pub fn devices_per_user(&self) -> Vec<(u8, f64)> {
        self.weighted_index_u8_f64("devices_per_user")
    }

    pub fn cvr_per_ad(&self) -> Vec<(Range<f64>, f64)> {
        self.weighted_index_range_f64_f64("cvr_per_ad")
    }

    pub fn conversion_value_per_user(&self) -> Vec<(Range<u32>, f64)> {
        self.weighted_index_range_u32_f64("conversion_value_per_user")
    }

    pub fn reach_per_ad(&self) -> Vec<(Range<u32>, f64)> {
        self.weighted_index_range_u32_f64("reach_per_ad")
    }

    pub fn impression_per_user(&self) -> Vec<(u8, f64)> {
        self.weighted_index_u8_f64("impression_per_user")
    }

    pub fn conversion_per_user(&self) -> Vec<(u8, f64)> {
        self.weighted_index_u8_f64("conversion_per_user")
    }

    pub fn impression_impression_duration(&self) -> Vec<(Range<f64>, f64)> {
        self.weighted_index_range_f64_f64("impression_impression_duration")
    }

    pub fn impression_conversion_duration(&self) -> Vec<(Range<u32>, f64)> {
        self.weighted_index_range_u32_f64("impression_conversion_duration")
    }
}
