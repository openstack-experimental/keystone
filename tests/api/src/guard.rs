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
use std::ops::Deref;
/// Trait to allow State to delete various resource types T
use std::sync::Arc;

use eyre::Result;
use openstack_sdk_core::AsyncOpenStack;

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

    pub fn resource(&self) -> &T {
        self.resource.as_ref().expect("Resource already deleted")
    }
}

#[async_trait::async_trait]
impl<R> ResourceGuard for AsyncResourceGuard<R>
where
    R: DeletableResource,
{
    async fn delete(mut self) -> Result<()> {
        if let Some(resource) = self.resource.take() {
            let _result = resource.delete(&self.state).await;
            // Mark as deleted regardless of success to prevent Drop panic
            self.was_deleted = true;
        }
        Ok(())
    }
}

impl<T> Drop for AsyncResourceGuard<T>
where
    T: DeletableResource,
{
    fn drop(&mut self) {
        if !self.was_deleted && !std::thread::panicking() {
            eprintln!(
                "\n[ERROR] AsyncResourceGuard leaked! .delete() was not called for resource."
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
        self.resource()
    }
}
