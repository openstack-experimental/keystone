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
        if let Some(slash_pos) = val.find("://") {
            let scheme = &val[..slash_pos];
            if let Some(plus_pos) = scheme.find('+') {
                let base = &scheme[..plus_pos];
                return SecretString::from(format!("{}://{}", base, &val[slash_pos + 3..]));
            }
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
        // No driver suffix – no change
        let sot = DatabaseSection {
            connection: "mysql://u:p@h".into(),
        };
        assert_eq!("mysql://u:p@h", sot.get_connection().expose_secret());

        // Driver suffix stripped
        let sot = DatabaseSection {
            connection: "mysql+driver://u:p@h".into(),
        };
        assert_eq!("mysql://u:p@h", sot.get_connection().expose_secret());
    }

    #[test]
    fn test_db_connection_multiple_scheme_delimiters() {
        // :// in password, driver stripped
        let sot = DatabaseSection {
            connection: "mysql+driver://u:p://x@h".into(),
        };
        assert_eq!("mysql://u:p://x@h", sot.get_connection().expose_secret());

        // Multiple :// in password, driver stripped
        let sot = DatabaseSection {
            connection: "mysql+driver://u://x:p://y@h".into(),
        };
        assert_eq!(
            "mysql://u://x:p://y@h",
            sot.get_connection().expose_secret()
        );
    }

    #[test]
    fn test_db_connection_plus_in_password() {
        // Single + in password, no driver – unchanged
        let sot = DatabaseSection {
            connection: "mysql://u:p+q@h".into(),
        };
        assert_eq!("mysql://u:p+q@h", sot.get_connection().expose_secret());

        // Multiple + in password, no driver – unchanged
        let sot = DatabaseSection {
            connection: "mysql://u:a+b+c@h".into(),
        };
        assert_eq!("mysql://u:a+b+c@h", sot.get_connection().expose_secret());

        // Only + as password, no driver – unchanged
        let sot = DatabaseSection {
            connection: "mysql://u:+@h".into(),
        };
        assert_eq!("mysql://u:+@h", sot.get_connection().expose_secret());

        // + at end of password, no driver – unchanged
        let sot = DatabaseSection {
            connection: "mysql://u:pass+@h".into(),
        };
        assert_eq!("mysql://u:pass+@h", sot.get_connection().expose_secret());

        // Driver suffix + single + in password
        let sot = DatabaseSection {
            connection: "mysql+driver://u:p+q@h".into(),
        };
        assert_eq!("mysql://u:p+q@h", sot.get_connection().expose_secret());

        // Driver suffix + multiple + in password
        let sot = DatabaseSection {
            connection: "mysql+driver://u:a+b+c@h".into(),
        };
        assert_eq!("mysql://u:a+b+c@h", sot.get_connection().expose_secret());

        // Driver suffix + only + as password
        let sot = DatabaseSection {
            connection: "mysql+driver://u:+@h".into(),
        };
        assert_eq!("mysql://u:+@h", sot.get_connection().expose_secret());

        // Driver suffix + :// and + in password
        let sot = DatabaseSection {
            connection: "mysql+driver://u:p+q://r@h".into(),
        };
        assert_eq!("mysql://u:p+q://r@h", sot.get_connection().expose_secret());

        // + in username and password, no driver
        let sot = DatabaseSection {
            connection: "mysql://u+v:p+w@h".into(),
        };
        assert_eq!("mysql://u+v:p+w@h", sot.get_connection().expose_secret());

        // Driver suffix + + in username and password
        let sot = DatabaseSection {
            connection: "mysql+driver://u+v:p+w@h".into(),
        };
        assert_eq!("mysql://u+v:p+w@h", sot.get_connection().expose_secret());

        // Empty password, no driver
        let sot = DatabaseSection {
            connection: "mysql://u:@h".into(),
        };
        assert_eq!("mysql://u:@h", sot.get_connection().expose_secret());

        // Empty password, driver stripped
        let sot = DatabaseSection {
            connection: "mysql+driver://u:@h".into(),
        };
        assert_eq!("mysql://u:@h", sot.get_connection().expose_secret());

        // No password, no driver
        let sot = DatabaseSection {
            connection: "mysql://u@h".into(),
        };
        assert_eq!("mysql://u@h", sot.get_connection().expose_secret());

        // No password, driver stripped
        let sot = DatabaseSection {
            connection: "mysql+driver://u@h".into(),
        };
        assert_eq!("mysql://u@h", sot.get_connection().expose_secret());

        // Special chars in password: @, /, ?, #
        let sot = DatabaseSection {
            connection: "mysql+driver://u:p@ss/w?_r#k@h".into(),
        };
        assert_eq!(
            "mysql://u:p@ss/w?_r#k@h",
            sot.get_connection().expose_secret()
        );

        // % encoded + in password (literal %2B)
        let sot = DatabaseSection {
            connection: "mysql+driver://u:%2B@h".into(),
        };
        assert_eq!("mysql://u:%2B@h", sot.get_connection().expose_secret());
    }

    #[test]
    fn test_db_connection_edge_cases() {
        // Multiple consecutive +
        let sot = DatabaseSection {
            connection: "mysql+driver+extra://u:p@h".into(),
        };
        assert_eq!("mysql://u:p@h", sot.get_connection().expose_secret());

        // No scheme separator – passthrough
        let sot = DatabaseSection {
            connection: "mysql+driver/u:p@h".into(),
        };
        assert_eq!("mysql+driver/u:p@h", sot.get_connection().expose_secret());

        // Empty connection
        let sot = DatabaseSection {
            connection: "".into(),
        };
        assert_eq!("", sot.get_connection().expose_secret());
    }
}
