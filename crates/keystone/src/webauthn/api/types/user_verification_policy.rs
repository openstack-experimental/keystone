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
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Defines the User Authenticator Verification policy. This is documented
/// <https://w3c.github.io/webauthn/#enumdef-userverificationrequirement>, and each variant lists
/// it's effects.
///
/// To be clear, Verification means that the Authenticator perform extra or
/// supplementary interaction with the user to verify who they are. An example
/// of this is Apple Touch Id required a fingerprint to be verified, or a yubico
/// device requiring a pin in addition to a touch event.
///
/// An example of a non-verified interaction is a yubico device with no pin
/// where touch is the only interaction - we only verify a user is present, but
/// we don't have extra details to the legitimacy of that user.
///
/// As UserVerificationPolicy is only used in credential registration, this
/// stores the verification state of the credential in the persisted credential.
/// These persisted credentials define which UserVerificationPolicy is issued
/// during authentications.
///
/// IMPORTANT - Due to limitations of the webauthn specification, CTAP devices,
/// and browser implementations, the only secure choice as an RP is required.
///
///   ⚠️ WARNING - discouraged is marked with a warning, as some authenticators
/// will FORCE   verification during registration but NOT during authentication.
/// This makes it impossible   for a relying party to consistently enforce user
/// verification, which can confuse users and   lead them to distrust user
/// verification is being enforced.
///
///   ⚠️ WARNING - preferred can lead to authentication errors in some cases due
/// to browser   peripheral exchange allowing authentication verification
/// bypass. Webauthn RS is not   vulnerable to these bypasses due to our
/// tracking of UV during registration through   authentication, however
/// preferred can cause legitimate credentials to not prompt for UV   correctly
/// due to browser perhipheral exchange leading Webauthn RS to deny them in what
///   should otherwise be legitimate operations.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub enum UserVerificationPolicy {
    /// Require user verification bit to be set, and fail the registration or
    /// authentication if false. If the authenticator is not able to perform
    /// verification, it will not be usable with this policy.
    ///
    /// This policy is the default as it is the only secure and consistent user
    /// verification option.
    Required,
    /// Prefer UV if possible, but ignore if not present. In other webauthn
    /// deployments this is bypassable as it implies the library will not
    /// check UV is set correctly for this credential. Webauthn-RS is not
    /// vulnerable to this as we check the UV state always based on
    /// it's presence at registration.
    ///
    /// However, in some cases use of this policy can lead to some credentials
    /// failing to verify correctly due to browser peripheral exchange
    /// bypasses.
    Preferred,
    /// Discourage - but do not prevent - user verification from being supplied.
    /// Many CTAP devices will attempt UV during registration but not
    /// authentication leading to user confusion.
    DiscouragedDoNotUse,
}

impl From<UserVerificationPolicy> for webauthn_rs_proto::options::UserVerificationPolicy {
    fn from(val: UserVerificationPolicy) -> Self {
        match val {
            UserVerificationPolicy::DiscouragedDoNotUse => {
                webauthn_rs_proto::options::UserVerificationPolicy::Discouraged_DO_NOT_USE
            }
            UserVerificationPolicy::Preferred => {
                webauthn_rs_proto::options::UserVerificationPolicy::Preferred
            }
            UserVerificationPolicy::Required => {
                webauthn_rs_proto::options::UserVerificationPolicy::Required
            }
        }
    }
}

impl From<webauthn_rs_proto::options::UserVerificationPolicy> for UserVerificationPolicy {
    fn from(val: webauthn_rs_proto::options::UserVerificationPolicy) -> Self {
        match val {
            webauthn_rs_proto::options::UserVerificationPolicy::Discouraged_DO_NOT_USE => {
                UserVerificationPolicy::DiscouragedDoNotUse
            }
            webauthn_rs_proto::options::UserVerificationPolicy::Preferred => {
                UserVerificationPolicy::Preferred
            }
            webauthn_rs_proto::options::UserVerificationPolicy::Required => {
                UserVerificationPolicy::Required
            }
        }
    }
}
