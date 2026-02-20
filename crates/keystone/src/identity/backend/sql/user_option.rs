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

use crate::db::entity::user_option;
use crate::identity::{IdentityProviderError, types::UserOptions};

mod create;
mod list;

pub use create::create;
pub use list::list_by_user_id;

impl FromIterator<user_option::Model> for UserOptions {
    fn from_iter<I: IntoIterator<Item = user_option::Model>>(iter: I) -> Self {
        let mut user_opts: UserOptions = UserOptions::default();
        for opt in iter.into_iter() {
            match (opt.option_id.as_str(), opt.option_value) {
                ("1000", Some(val)) => {
                    user_opts.ignore_change_password_upon_first_use = val.parse().ok();
                }
                ("1001", Some(val)) => {
                    user_opts.ignore_password_expiry = val.parse().ok();
                }
                ("1002", Some(val)) => {
                    user_opts.ignore_lockout_failure_attempts = val.parse().ok();
                }
                ("1003", Some(val)) => {
                    user_opts.lock_password = val.parse().ok();
                }
                ("1004", Some(val)) => {
                    user_opts.ignore_user_inactivity = val.parse().ok();
                }
                ("MFAR", Some(val)) => {
                    user_opts.multi_factor_auth_rules = serde_json::from_str(val.as_ref()).ok();
                }
                ("MFAE", Some(val)) => {
                    user_opts.multi_factor_auth_enabled = val.parse().ok();
                }
                ("ISSA", Some(val)) => {
                    user_opts.is_service_account = val.parse().ok();
                }
                _ => {}
            }
        }
        user_opts
    }
}

impl UserOptions {
    pub(super) fn to_model_iter<U: Into<String>>(
        &self,
        user_id: U,
    ) -> Result<impl IntoIterator<Item = user_option::Model>, IdentityProviderError> {
        let mut res: Vec<user_option::Model> = Vec::new();
        let uid = user_id.into();
        if let Some(val) = &self.ignore_change_password_upon_first_use {
            res.push(user_option::Model {
                user_id: uid.clone(),
                option_id: "1000".into(),
                option_value: Some(val.to_string()),
            });
        }
        if let Some(val) = &self.ignore_password_expiry {
            res.push(user_option::Model {
                user_id: uid.clone(),
                option_id: "1001".into(),
                option_value: Some(val.to_string()),
            });
        }
        if let Some(val) = &self.ignore_lockout_failure_attempts {
            res.push(user_option::Model {
                user_id: uid.clone(),
                option_id: "1002".into(),
                option_value: Some(val.to_string()),
            });
        }
        if let Some(val) = &self.lock_password {
            res.push(user_option::Model {
                user_id: uid.clone(),
                option_id: "1003".into(),
                option_value: Some(val.to_string()),
            });
        }
        if let Some(val) = &self.ignore_user_inactivity {
            res.push(user_option::Model {
                user_id: uid.clone(),
                option_id: "1004".into(),
                option_value: Some(val.to_string()),
            });
        }
        if let Some(val) = &self.multi_factor_auth_rules {
            res.push(user_option::Model {
                user_id: uid.clone(),
                option_id: "MFAR".into(),
                option_value: Some(serde_json::to_string(val)?),
            });
        }
        if let Some(val) = &self.multi_factor_auth_enabled {
            res.push(user_option::Model {
                user_id: uid.clone(),
                option_id: "MFAE".into(),
                option_value: Some(val.to_string()),
            });
        }
        if let Some(val) = &self.is_service_account {
            res.push(user_option::Model {
                user_id: uid.clone(),
                option_id: "ISSA".into(),
                option_value: Some(val.to_string()),
            });
        }
        Ok(res)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::db::entity::user_option;
    use crate::identity::types::UserOptions;

    impl Default for user_option::Model {
        fn default() -> Self {
            Self {
                user_id: "1".into(),
                option_id: "1000".into(),
                option_value: None,
            }
        }
    }

    pub fn get_user_options_mock<U: Into<String>>(
        user_id: U,
        options: &UserOptions,
    ) -> Vec<user_option::Model> {
        options
            .to_model_iter(user_id)
            .unwrap()
            .into_iter()
            .collect()
    }

    #[test]
    fn test_from_rows_empty() {
        assert_eq!(
            UserOptions::from_iter(Vec::<user_option::Model>::new()),
            UserOptions::default()
        );
    }

    #[test]
    fn test_to_model_iter() {
        // Test conversion of multiple options to ensure we do not stop on first match.
        // It is not necessary to cover all options in this test
        let rows: Vec<user_option::Model> = UserOptions {
            ignore_change_password_upon_first_use: Some(true),
            ignore_password_expiry: Some(true),
            ignore_lockout_failure_attempts: Some(true),
            lock_password: Some(true),
            ignore_user_inactivity: Some(true),
            multi_factor_auth_rules: Some(vec![vec!["a".into(), "b".into()]]),
            multi_factor_auth_enabled: Some(true),
            is_service_account: Some(true),
        }
        .to_model_iter("uid")
        .unwrap()
        .into_iter()
        .collect();
        assert!(rows.contains(&user_option::Model {
            user_id: "uid".into(),
            option_id: "1000".into(),
            option_value: Some("true".into())
        }));
        assert!(rows.contains(&user_option::Model {
            user_id: "uid".into(),
            option_id: "1001".into(),
            option_value: Some("true".into())
        }));
        assert!(rows.contains(&user_option::Model {
            user_id: "uid".into(),
            option_id: "1002".into(),
            option_value: Some("true".into())
        }));
        assert!(rows.contains(&user_option::Model {
            user_id: "uid".into(),
            option_id: "1003".into(),
            option_value: Some("true".into())
        }));
        assert!(rows.contains(&user_option::Model {
            user_id: "uid".into(),
            option_id: "1004".into(),
            option_value: Some("true".into())
        }));
        assert!(rows.contains(&user_option::Model {
            user_id: "uid".into(),
            option_id: "MFAR".into(),
            option_value: Some("[[\"a\",\"b\"]]".into())
        }),);
        assert!(rows.contains(&user_option::Model {
            user_id: "uid".into(),
            option_id: "MFAE".into(),
            option_value: Some("true".into())
        }),);
        assert!(rows.contains(&user_option::Model {
            user_id: "uid".into(),
            option_id: "ISSA".into(),
            option_value: Some("true".into())
        }));
    }

    #[test]
    fn test_to_model_iter_1000() {
        let sot = UserOptions {
            ignore_change_password_upon_first_use: Some(true),
            ..Default::default()
        };
        let rows = vec![user_option::Model {
            user_id: "uid".into(),
            option_id: "1000".into(),
            option_value: Some("true".into()),
        }];
        assert_eq!(
            sot.to_model_iter("uid")
                .unwrap()
                .into_iter()
                .collect::<Vec<user_option::Model>>(),
            rows
        );
        assert_eq!(sot, UserOptions::from_iter(rows.into_iter()));
    }

    #[test]
    fn test_to_model_iter_1001() {
        let sot = UserOptions {
            ignore_password_expiry: Some(true),
            ..Default::default()
        };
        let rows = vec![user_option::Model {
            user_id: "uid".into(),
            option_id: "1001".into(),
            option_value: Some("true".into()),
        }];
        assert_eq!(
            sot.to_model_iter("uid")
                .unwrap()
                .into_iter()
                .collect::<Vec<user_option::Model>>(),
            rows
        );
        assert_eq!(sot, UserOptions::from_iter(rows.into_iter()));
    }

    #[test]
    fn test_to_model_iter_1002() {
        let sot = UserOptions {
            ignore_lockout_failure_attempts: Some(true),
            ..Default::default()
        };
        let rows = vec![user_option::Model {
            user_id: "uid".into(),
            option_id: "1002".into(),
            option_value: Some("true".into()),
        }];
        assert_eq!(
            sot.to_model_iter("uid")
                .unwrap()
                .into_iter()
                .collect::<Vec<user_option::Model>>(),
            rows
        );
        assert_eq!(sot, UserOptions::from_iter(rows.into_iter()));
    }

    #[test]
    fn test_to_model_iter_1003() {
        let sot = UserOptions {
            lock_password: Some(true),
            ..Default::default()
        };
        let rows = vec![user_option::Model {
            user_id: "uid".into(),
            option_id: "1003".into(),
            option_value: Some("true".into()),
        }];
        assert_eq!(
            sot.to_model_iter("uid")
                .unwrap()
                .into_iter()
                .collect::<Vec<user_option::Model>>(),
            rows
        );
        assert_eq!(sot, UserOptions::from_iter(rows.into_iter()));
    }

    #[test]
    fn test_1004() {
        let sot = UserOptions {
            ignore_user_inactivity: Some(true),
            ..Default::default()
        };
        let rows = vec![user_option::Model {
            user_id: "uid".into(),
            option_id: "1004".into(),
            option_value: Some("true".into()),
        }];
        assert_eq!(
            sot.to_model_iter("uid")
                .unwrap()
                .into_iter()
                .collect::<Vec<user_option::Model>>(),
            rows
        );
        assert_eq!(sot, UserOptions::from_iter(rows.into_iter()));
    }

    #[test]
    fn test_mfar() {
        let sot = UserOptions {
            multi_factor_auth_rules: Some(vec![vec!["a".into(), "b".into()]]),
            ..Default::default()
        };
        let rows = vec![user_option::Model {
            user_id: "uid".into(),
            option_id: "MFAR".into(),
            option_value: Some("[[\"a\",\"b\"]]".into()),
        }];
        assert_eq!(
            sot.to_model_iter("uid")
                .unwrap()
                .into_iter()
                .collect::<Vec<user_option::Model>>(),
            rows
        );
        assert_eq!(sot, UserOptions::from_iter(rows.into_iter()));
    }

    #[test]
    fn test_mfae() {
        let sot = UserOptions {
            multi_factor_auth_enabled: Some(true),
            ..Default::default()
        };
        let rows = vec![user_option::Model {
            user_id: "uid".into(),
            option_id: "MFAE".into(),
            option_value: Some("true".into()),
        }];
        assert_eq!(
            sot.to_model_iter("uid")
                .unwrap()
                .into_iter()
                .collect::<Vec<user_option::Model>>(),
            rows
        );
        assert_eq!(sot, UserOptions::from_iter(rows.into_iter()));
    }

    #[test]
    fn test_issa() {
        let sot = UserOptions {
            is_service_account: Some(true),
            ..Default::default()
        };
        let rows = vec![user_option::Model {
            user_id: "uid".into(),
            option_id: "ISSA".into(),
            option_value: Some("true".into()),
        }];
        assert_eq!(
            sot.to_model_iter("uid")
                .unwrap()
                .into_iter()
                .collect::<Vec<user_option::Model>>(),
            rows
        );
        assert_eq!(sot, UserOptions::from_iter(rows.into_iter()));
    }
}
