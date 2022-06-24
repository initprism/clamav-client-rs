use chrono::{DateTime, TimeZone, Utc};
use std::str::FromStr;

use crate::client::Result;
use crate::error::ClamError;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct Signature {
    // Start names with targeted platform or file format
    pub platform: Option<String>,
    // Follow with the category
    pub category: Option<String>,
    // Follow with a representative name
    pub virus: Option<String>,
    // signature num
    pub signum: Option<String>,
    // signature sub version
    pub sigversion: Option<String>,
    // raw string
    pub raw: String,
}

impl Signature {
    pub fn from(str: &str) -> Self {
        let xs: Vec<&str> = str.splitn(2, "-").collect();
        let sig0_xs = xs.get(0).map(|x| x.splitn(3, ".").collect::<Vec<&str>>());

        let platform = sig0_xs
            .as_ref()
            .map(|x| x.get(0).map(|x| x.to_string()))
            .flatten();
        let category = sig0_xs
            .as_ref()
            .map(|x| x.get(1).map(|x| x.to_string()))
            .flatten();
        let virus = sig0_xs
            .as_ref()
            .map(|x| x.get(2).map(|x| x.to_string()))
            .flatten();

        let sig1_xs = xs.get(1).map(|x| x.splitn(2, "-").collect::<Vec<&str>>());
        let signum = sig1_xs
            .as_ref()
            .map(|x| x.get(0).map(|x| x.to_string()))
            .flatten();
        let sigversion = sig1_xs
            .as_ref()
            .map(|x| x.get(1).map(|x| x.to_string()))
            .flatten();

        Self {
            platform,
            category,
            virus,
            signum,
            sigversion,
            raw: str.to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub enum ScanResult {
    Ok,
    Found(String, Signature),
    Error(String),
}

impl ScanResult {
    pub fn parse<T: AsRef<str>>(s: T) -> Vec<ScanResult> {
        s.as_ref()
            .split('\0')
            .filter(|s| s != &"")
            .map(|s| {
                if s.ends_with("OK") {
                    return ScanResult::Ok;
                }

                if s.contains("FOUND") {
                    let mut split = s.split_whitespace();
                    let path: String = split.next().unwrap().trim_end_matches(':').to_owned();
                    let virus = split
                        .take_while(|s| !s.starts_with("FOUND"))
                        .collect::<String>();

                    return ScanResult::Found(path, Signature::from(&virus));
                }

                ScanResult::Error(s.to_owned())
            })
            .collect::<Vec<ScanResult>>()
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, PartialOrd)]
pub struct Version {
    pub version_tag: String,
    pub build_number: u64,
    pub release_date: DateTime<Utc>,
}

impl Version {
    pub fn parse(s: &str) -> Result<Self> {
        let parts = s
            .trim_end_matches('\0')
            .split('/')
            .map(|s| s.to_owned())
            .collect::<Vec<String>>();

        if parts.len() != 3 {
            return Err(ClamError::InvalidData(s.to_string()));
        }

        let build_number = match parts[1].parse() {
            Ok(v) => v,
            Err(e) => return Err(ClamError::IntParseError(e)),
        };

        let release_date = match Utc.datetime_from_str(&parts[2], "%a %b %e %T %Y") {
            Ok(v) => v,
            Err(e) => return Err(ClamError::DateParseError(e)),
        };

        Ok(Version {
            version_tag: parts[0].to_owned(),
            build_number,
            release_date,
        })
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, PartialOrd)]
pub struct Stats {
    pub pools: u64,
    pub state: String,
    pub threads_live: u64,
    pub threads_idle: u64,
    pub threads_max: u64,
    pub threads_idle_timeout_secs: u64,
    pub queue: u64,
    pub mem_heap: String,
    pub mem_mmap: String,
    pub mem_used: String,
    pub mem_free: String,
    pub mem_releasable: String,
    pub pools_used: String,
    pub pools_total: String,
}

impl Stats {
    pub fn parse(s: &str) -> Result<Self> {
        match parse_stats(s) {
            Ok(x) => Ok(x.1),
            Err(_) => Err(ClamError::InvalidData(s.to_string())),
        }
    }
}

named!(parse_stats<&str, Stats>,
    do_parse!(
        tag!("POOLS: ") >>
        pools: map_res!(take_until_and_consume!("\n\nSTATE: "), u64::from_str) >>
        state: map_res!(take_until_and_consume!("\nTHREADS: live "), FromStr::from_str) >>
        threads_live: map_res!(take_until_and_consume!("  idle "), u64::from_str) >>
        threads_idle: map_res!(take_until_and_consume!(" max "), u64::from_str) >>
        threads_max: map_res!(take_until_and_consume!(" idle-timeout "), u64::from_str) >>
        threads_idle_timeout_secs: map_res!(take_until_and_consume!("\nQUEUE: "), u64::from_str) >>
        queue: map_res!(take_until_and_consume!(" items\n"), u64::from_str) >>
        take_until_and_consume!("heap ") >>
        mem_heap: map_res!(take_until_and_consume!(" mmap "), FromStr::from_str) >>
        mem_mmap: map_res!(take_until_and_consume!(" used "), FromStr::from_str) >>
        mem_used: map_res!(take_until_and_consume!(" free "), FromStr::from_str) >>
        mem_free: map_res!(take_until_and_consume!(" releasable "), FromStr::from_str) >>
        mem_releasable: map_res!(take_until_and_consume!(" pools "), FromStr::from_str) >>
        take_until_and_consume!("pools_used ") >>
        pools_used: map_res!(take_until_and_consume!(" pools_total "), FromStr::from_str) >>
        pools_total: map_res!(take_until!("\n"), FromStr::from_str) >>
        (
            Stats {
                pools,
                state,
                threads_live,
                threads_idle,
                threads_max,
                threads_idle_timeout_secs,
                queue,
                mem_heap,
                mem_mmap,
                mem_used,
                mem_free,
                mem_releasable,
                pools_used,
                pools_total
            }
        )
    )
);

#[cfg(test)]
mod tests {
    use super::*;

    static VERSION_STRING: &'static str = "ClamAV 0.100.0/24802/Wed Aug  1 08:43:37 2018\0";
    static STATS_STRING: &'static str = "POOLS: 1\n\nSTATE: VALID PRIMARY\nTHREADS: live 1  idle 0 max 12 idle-timeout 30\nQUEUE: 0 items\n\tSTATS 0.000394\n\nMEMSTATS: heap 9.082M mmap 0.000M used 6.902M free 2.184M releasable 0.129M pools 1 pools_used 565.979M pools_total 565.999M\nEND\0";

    #[test]
    fn test_version_parse_version_tag() {
        let raw = VERSION_STRING.to_owned();
        let parsed = Version::parse(&raw).unwrap();
        assert_eq!(parsed.version_tag, "ClamAV 0.100.0".to_string());
    }

    #[test]
    fn test_version_parse_build_number() {
        let raw = VERSION_STRING.to_owned();
        let parsed = Version::parse(&raw).unwrap();
        assert_eq!(parsed.build_number, 24802);
    }

    #[test]
    fn test_version_parse_publish_dt() {
        let raw = VERSION_STRING.to_owned();
        let parsed = Version::parse(&raw).unwrap();
        assert_eq!(
            parsed.release_date,
            Utc.datetime_from_str("Wed Aug  1 08:43:37 2018", "%a %b %e %T %Y")
                .unwrap()
        );
    }

    #[test]
    fn test_result_parse_ok() {
        let raw = "/some/file: OK\0";
        let parsed = ScanResult::parse(raw);
        assert_eq!(parsed[0], ScanResult::Ok);
    }

    #[test]
    fn test_result_parse_error() {
        let raw = "/some/file: lstat() failed or some other random error\0";
        let parsed = ScanResult::parse(raw);
        assert_eq!(
            parsed[0],
            ScanResult::Error("/some/file: lstat() failed or some other random error".to_string())
        );
    }

    #[test]
    fn test_stats_parse_pools() {
        let parsed = Stats::parse(STATS_STRING).unwrap();
        assert_eq!(parsed.pools, 1);
    }

    #[test]
    fn test_stats_parse_state() {
        let parsed = Stats::parse(STATS_STRING).unwrap();
        assert_eq!(parsed.state, "VALID PRIMARY".to_string());
    }

    #[test]
    fn test_stats_parse_live_threads() {
        let parsed = Stats::parse(STATS_STRING).unwrap();
        assert_eq!(parsed.threads_live, 1);
    }

    #[test]
    fn test_stats_parse_idle_threads() {
        let parsed = Stats::parse(STATS_STRING).unwrap();
        assert_eq!(parsed.threads_idle, 0);
    }

    #[test]
    fn test_stats_parse_max_threads() {
        let parsed = Stats::parse(STATS_STRING).unwrap();
        assert_eq!(parsed.threads_max, 12);
    }

    #[test]
    fn test_stats_parse_threads_timeout() {
        let parsed = Stats::parse(STATS_STRING).unwrap();
        assert_eq!(parsed.threads_idle_timeout_secs, 30);
    }

    #[test]
    fn test_stats_parse_queue() {
        let parsed = Stats::parse(STATS_STRING).unwrap();
        assert_eq!(parsed.queue, 0);
    }

    #[test]
    fn test_stats_parse_mem_heap() {
        let parsed = Stats::parse(STATS_STRING).unwrap();
        assert_eq!(parsed.mem_heap, "9.082M".to_string());
    }

    #[test]
    fn test_stats_parse_mem_mmap() {
        let parsed = Stats::parse(STATS_STRING).unwrap();
        assert_eq!(parsed.mem_mmap, "0.000M".to_string());
    }

    #[test]
    fn test_stats_parse_mem_used() {
        let parsed = Stats::parse(STATS_STRING).unwrap();
        assert_eq!(parsed.mem_used, "6.902M".to_string());
    }

    #[test]
    fn test_stats_parse_mem_free() {
        let parsed = Stats::parse(STATS_STRING).unwrap();
        assert_eq!(parsed.mem_free, "2.184M".to_string());
    }

    #[test]
    fn test_stats_parse_mem_releaseable() {
        let parsed = Stats::parse(STATS_STRING).unwrap();
        assert_eq!(parsed.mem_releasable, "0.129M".to_string());
    }

    #[test]
    fn test_stats_parse_pools_used() {
        let parsed = Stats::parse(STATS_STRING).unwrap();
        assert_eq!(parsed.pools_used, "565.979M".to_string());
    }

    #[test]
    fn test_stats_parse_pools_total() {
        let parsed = Stats::parse(STATS_STRING).unwrap();
        assert_eq!(parsed.pools_total, "565.999M".to_string());
    }
}
