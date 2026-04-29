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
//! # Common functionality
use std::fmt;

use axum::http::{Request, Response, StatusCode};
use tower_http::classify::{
    ClassifiedResponse, ClassifyResponse, MakeClassifier, NeverClassifyEos,
};

pub use openstack_keystone_core::common::*;

/// Custom Response classifier to silent the 503 errors which are "normal"
/// logic.
#[derive(Clone)]
pub struct KeystoneResponseClassifier;

impl ClassifyResponse for KeystoneResponseClassifier {
    type FailureClass = String;
    type ClassifyEos = NeverClassifyEos<Self::FailureClass>;

    /// Classifies the response to determine if it is a failure.
    ///
    /// # Parameters
    /// - `self`: The classifier instance.
    /// - `res`: The response to classify.
    fn classify_response<B>(
        self,
        res: &Response<B>,
    ) -> ClassifiedResponse<Self::FailureClass, Self::ClassifyEos> {
        let status = res.status();

        // Logic: If it's a 503, we check if we should "ignore" it.
        // For a global layer, you can simply decide that 503s are NEVER hard errors
        // because in a Raft/Distributed system, 503 is an expected state (Catching up).
        if status == StatusCode::SERVICE_UNAVAILABLE {
            return ClassifiedResponse::Ready(Ok(()));
        }

        if status.is_server_error() {
            ClassifiedResponse::Ready(Err(format!("Server Error: {}", status)))
        } else if status.is_client_error() {
            ClassifiedResponse::Ready(Err(format!("Client Error: {}", status)))
        } else {
            ClassifiedResponse::Ready(Ok(()))
        }
    }

    /// Classifies the error into a failure class.
    ///
    /// # Parameters
    /// - `self`: The classifier instance.
    /// - `error`: The error to classify.
    fn classify_error<E>(self, error: &E) -> Self::FailureClass
    where
        E: fmt::Display,
    {
        error.to_string()
    }
}

// Factory to provide the classifier to the middleware.
impl MakeClassifier for KeystoneResponseClassifier {
    type Classifier = Self;
    type FailureClass = String;
    type ClassifyEos = NeverClassifyEos<Self::FailureClass>;

    /// Creates a new classifier instance.
    ///
    /// # Parameters
    /// - `self`: The factory instance.
    /// - `_request`: The request being processed.
    fn make_classifier<B>(&self, _request: &Request<B>) -> Self::Classifier {
        self.clone()
    }
}
