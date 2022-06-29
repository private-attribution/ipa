use log::error;
use rand_distr::num_traits::ToPrimitive;
use serde_json::Value;
use std::io::{BufReader, Read};
use std::ops::Range;
use std::process;

#[derive(Clone)]
pub struct Config {
    pub devices_per_user: Vec<(u8, f64)>,
    pub cvr_per_ad: Vec<(Range<f64>, f64)>,
    pub conversion_value_per_user: Vec<(Range<u32>, f64)>,
    pub reach_per_ad: Vec<(Range<u32>, f64)>,
    pub impression_per_user: Vec<(u8, f64)>,
    pub conversion_per_user: Vec<(u8, f64)>,
    pub impression_impression_duration: Vec<(Range<f64>, f64)>,
    pub impression_conversion_duration: Vec<(Range<u32>, f64)>,
}

impl Config {
    pub fn parse<R: Read>(input: &mut R) -> Self {
        let f = BufReader::new(input);

        let config: Value = serde_json::from_reader(f).unwrap();

        Config {
            devices_per_user: Config::weighted_index_u8_f64(&config, "devices_per_user"),
            cvr_per_ad: Config::weighted_index_range_f64_f64(&config, "cvr_per_ad"),
            conversion_value_per_user: Config::weighted_index_range_u32_f64(
                &config,
                "conversion_value_per_user",
            ),
            reach_per_ad: Config::weighted_index_range_u32_f64(&config, "reach_per_ad"),
            impression_per_user: Config::weighted_index_u8_f64(&config, "impression_per_user"),
            conversion_per_user: Config::weighted_index_u8_f64(&config, "conversion_per_user"),
            impression_impression_duration: Config::weighted_index_range_f64_f64(
                &config,
                "impression_impression_duration",
            ),
            impression_conversion_duration: Config::weighted_index_range_u32_f64(
                &config,
                "impression_conversion_duration",
            ),
        }
    }

    fn weighted_index_u8_f64(config: &Value, name: &str) -> Vec<(u8, f64)> {
        let config: &Vec<Value> = config[name]["weighted_index"]
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

    fn weighted_index_range_f64_f64(config: &Value, name: &str) -> Vec<(Range<f64>, f64)> {
        let config: &Vec<Value> = config[name]["weighted_index"]
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

    fn weighted_index_range_u32_f64(config: &Value, name: &str) -> Vec<(Range<u32>, f64)> {
        // Reuse range_f64_f64 and cast to u32
        let config = Config::weighted_index_range_f64_f64(config, name);
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
}
