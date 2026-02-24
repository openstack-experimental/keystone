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
//! Test the k8s auth functionality

use eyre::Result;
use tokio::fs;

#[tokio::test]
async fn test_k8s_auth() -> Result<()> {
    let k8s_token =
        fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/token").await?;
    let k8s_ca = fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt").await?;
    println!("token is {}", k8s_token);
    println!("ca is {}", k8s_ca);
    Ok(())
}
