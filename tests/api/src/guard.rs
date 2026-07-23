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
//! RAII-style guards for API-created test resources.
//!
//! # Cleanup contract
//!
//! Rust has no async `Drop`, so the **only reliable cleanup is an explicit
//! `guard.delete().await?` at the end of the test**. The [`Drop`]
//! implementation is *leak detection*, not cleanup: when a guard is dropped
//! without `.delete()` having run — including drops during a panic/failed
//! assertion or an early `?` return — it prints a diagnostic naming the
//! leaked resource type so the leak can be traced and removed from the
//! shared server state (relevant for the long-lived K8s deployments).
//!
//! For negative tests, create fixtures with an *admin* session and delete
//! them with that same admin session, so cleanup does not depend on an
//! underprivileged session succeeding.

use std::io::Write;
use std::ops::Deref;
use std::sync::Arc;

use eyre::Result;
use openstack_sdk::AsyncOpenStack;

/// Trait to allow State to delete various resource types T
#[async_trait::async_trait]
pub trait DeletableResource: Send + Sync {
    async fn delete(&self, state: &Arc<AsyncOpenStack>) -> Result<()>;
}

/// Trait for the Guard itself to allow for polymorphism in tests
#[async_trait::async_trait]
pub trait ResourceGuard: Send + Sync {
    async fn delete(self) -> Result<()>;
}

pub struct AsyncResourceGuard<T>
where
    T: DeletableResource,
{
    resource: Option<T>,
    state: Arc<AsyncOpenStack>,
    was_deleted: bool,
}

impl<T> AsyncResourceGuard<T>
where
    T: DeletableResource,
{
    pub fn new(resource: T, state: Arc<AsyncOpenStack>) -> Self {
        Self {
            resource: Some(resource),
            state,
            was_deleted: false,
        }
    }

    /// The guarded resource, or `None` when it has already been taken by
    /// the consuming [`ResourceGuard::delete`].
    pub fn resource(&self) -> Option<&T> {
        self.resource.as_ref()
    }
}

impl<T> std::fmt::Debug for AsyncResourceGuard<T>
where
    T: DeletableResource + std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsyncResourceGuard")
            .field("resource", &self.resource)
            .field("was_deleted", &self.was_deleted)
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl<R> ResourceGuard for AsyncResourceGuard<R>
where
    R: DeletableResource,
{
    async fn delete(mut self) -> Result<()> {
        if let Some(resource) = self.resource.take() {
            let result = resource.delete(&self.state).await;
            self.was_deleted = true;
            result?;
        }
        Ok(())
    }
}

impl<T> Drop for AsyncResourceGuard<T>
where
    T: DeletableResource,
{
    fn drop(&mut self) {
        if !self.was_deleted && self.resource.is_some() {
            // Leak *detection* only — async cleanup cannot run reliably in
            // `Drop` (current-thread `#[tokio::test]` runtimes, runtime
            // shutdown, panic unwinding). Emit on the panic path too: a
            // failed assertion is exactly when explicit cleanup is most
            // likely to have been skipped. Never panics (a second panic
            // while unwinding would abort the test process).
            let during_panic = if std::thread::panicking() {
                " while unwinding a panic"
            } else {
                ""
            };
            let _ = writeln!(
                std::io::stderr(),
                "\n[ERROR] AsyncResourceGuard<{}> leaked{}: .delete() was not \
                 called; the resource is left behind on the server.",
                std::any::type_name::<T>(),
                during_panic,
            );
        }
    }
}

impl<R> Deref for AsyncResourceGuard<R>
where
    R: DeletableResource,
{
    type Target = R;
    fn deref(&self) -> &Self::Target {
        match self.resource.as_ref() {
            Some(resource) => resource,
            // `ResourceGuard::delete` consumes the guard, so no borrow can
            // observe the taken state.
            None => unreachable!(
                "AsyncResourceGuard<{}> dereferenced after delete()",
                std::any::type_name::<R>()
            ),
        }
    }
}
