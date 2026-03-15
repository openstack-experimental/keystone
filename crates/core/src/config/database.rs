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
// SPDX-License-Identifier: Apache-2.0
use regex::Regex;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

/// Database configuration.
#[derive(Debug, Default, Deserialize, Clone)]
pub struct DatabaseSection {
    /// Database URL.
    pub connection: SecretString,
}

impl DatabaseSection {
    pub fn get_connection(&self) -> SecretString {
        let val = self.connection.expose_secret();
        if val.contains("+") {
            return Regex::new(r"(?<type>\w+)\+(\w+)://")
                .map(|re| SecretString::from(re.replace(val, "${type}://").to_string()))
                .unwrap_or(self.connection.clone());
        }
        self.connection.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn test_db_connection() {
        let sot = DatabaseSection {
            connection: "mysql://u:p@h".into(),
        };
        assert_eq!("mysql://u:p@h", sot.get_connection().expose_secret());
        let sot = DatabaseSection {
            connection: "mysql+driver://u:p@h".into(),
        };
        assert_eq!("mysql://u:p@h", sot.get_connection().expose_secret());
    }
}
