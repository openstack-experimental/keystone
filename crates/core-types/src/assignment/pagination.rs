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

//! # In-memory pagination for assignment listings

use crate::ListPagination;
use crate::assignment::Assignment;

/// Apply cursor pagination to a fully materialized assignment list in memory.
///
/// Assignment listings have no SQL cursor: a driver's result is already a union
/// of several queries plus in-memory implied-role expansion, and the assignment
/// provider's untargeted fan-out (ADR 0034 §5) unions several drivers' results
/// on top of that. Both sort on [`Assignment::pagination_marker`], drop every
/// row on the wrong side of `marker`, then keep `limit + 1` rows — the extra
/// row is the caller's "has a next page" probe.
///
/// # Parameters
/// - `assignments`: The fully fetched, deduplicated result set, mutated in place.
/// - `pagination`: The requested `limit` / `marker` / `page_reverse`.
pub fn paginate_in_memory(assignments: &mut Vec<Assignment>, pagination: &ListPagination) {
    assignments.sort_by_key(Assignment::pagination_marker);
    if let Some(marker) = &pagination.marker {
        if pagination.page_reverse {
            assignments.retain(|x| x.pagination_marker().as_str() < marker.as_str());
        } else {
            assignments.retain(|x| x.pagination_marker().as_str() > marker.as_str());
        }
    }
    if let Some(limit) = pagination.limit {
        let limit = (limit + 1) as usize;
        if pagination.page_reverse {
            if assignments.len() > limit {
                *assignments = assignments.split_off(assignments.len() - limit);
            }
        } else {
            assignments.truncate(limit);
        }
    }
}
