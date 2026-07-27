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

use openstack_keystone_core_types::resource::ProjectOptions;

use crate::entity::project_option;

mod list;
mod upsert;

pub use list::list_by_project_id;
pub use upsert::upsert;

impl FromIterator<project_option::Model> for ProjectOptions {
    fn from_iter<I: IntoIterator<Item = project_option::Model>>(iter: I) -> Self {
        let mut project_opts: ProjectOptions = ProjectOptions::default();
        for opt in iter.into_iter() {
            if let ("IMMU", Some(val)) = (opt.option_id.as_str(), opt.option_value) {
                project_opts.immutable = val.parse().ok();
            }
        }
        project_opts
    }
}

pub trait ProjectOptionIntoModelIterator {
    fn to_model_iter<P: Into<String>>(
        &self,
        project_id: P,
    ) -> impl IntoIterator<Item = project_option::Model>;
}

impl ProjectOptionIntoModelIterator for ProjectOptions {
    /// Convert project options to a model iterator.
    ///
    /// # Parameters
    /// - `project_id`: The project (or domain) ID.
    ///
    /// # Returns
    /// An iterator of project option models.
    fn to_model_iter<P: Into<String>>(
        &self,
        project_id: P,
    ) -> impl IntoIterator<Item = project_option::Model> {
        let mut res: Vec<project_option::Model> = Vec::new();
        let pid = project_id.into();
        if let Some(val) = &self.immutable {
            res.push(project_option::Model {
                project_id: pid.clone(),
                option_id: "IMMU".into(),
                option_value: Some(val.to_string()),
            });
        }
        res
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::entity::project_option;

    impl Default for project_option::Model {
        fn default() -> Self {
            Self {
                project_id: "1".into(),
                option_id: "IMMU".into(),
                option_value: None,
            }
        }
    }

    #[test]
    fn test_from_rows_empty() {
        assert_eq!(
            ProjectOptions::from_iter(Vec::<project_option::Model>::new()),
            ProjectOptions::default()
        );
    }

    #[test]
    fn test_to_model_iter_immutable() {
        let sot = ProjectOptions {
            immutable: Some(true),
        };
        let rows = vec![project_option::Model {
            project_id: "pid".into(),
            option_id: "IMMU".into(),
            option_value: Some("true".into()),
        }];
        assert_eq!(
            sot.to_model_iter("pid").into_iter().collect::<Vec<_>>(),
            rows
        );
        assert_eq!(sot, ProjectOptions::from_iter(rows));
    }

    #[test]
    fn test_to_model_iter_unset() {
        let sot = ProjectOptions::default();
        assert!(sot.to_model_iter("pid").into_iter().next().is_none());
    }
}
