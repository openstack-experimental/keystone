// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

//! Minimal parser for the Prometheus text exposition format.

use std::collections::HashMap;

/// Metrics scraped from one node. Series with labels are folded to the
/// maximum value seen per metric name (the only labelled series the soak test
/// looks at is `keystone_raft_replication_lag{peer_id}`, where the worst peer
/// is what matters).
#[derive(Clone, Debug, Default)]
pub struct Scrape {
    pub values: HashMap<String, f64>,
}

impl Scrape {
    pub fn get(&self, name: &str) -> Option<f64> {
        self.values.get(name).copied()
    }
}

/// Parse `text` in the Prometheus exposition format.
pub fn parse(text: &str) -> Scrape {
    let mut values: HashMap<String, f64> = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let name_end = line.find(['{', ' ']).unwrap_or(line.len());
        let name = &line[..name_end];
        // The value is the first token after the (optional) label set.
        let rest = match line[name_end..].strip_prefix('{') {
            Some(labels) => labels.split_once('}').map(|(_, r)| r).unwrap_or(""),
            None => &line[name_end..],
        };
        let Some(value) = rest
            .split_whitespace()
            .next()
            .and_then(|v| v.parse::<f64>().ok())
        else {
            continue;
        };
        values
            .entry(name.to_string())
            .and_modify(|v| *v = v.max(value))
            .or_insert(value);
    }
    Scrape { values }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_and_labelled_series() {
        let s = parse(
            "# HELP x y\n# TYPE keystone_raft_term gauge\nkeystone_raft_term 7\n\
             keystone_raft_replication_lag{peer_id=\"2\"} 20\n\
             keystone_raft_replication_lag{peer_id=\"3\"} 100 1700000000\n\
             broken line\n",
        );
        assert_eq!(s.get("keystone_raft_term"), Some(7.0));
        assert_eq!(s.get("keystone_raft_replication_lag"), Some(100.0));
        assert_eq!(s.get("missing"), None);
    }
}
