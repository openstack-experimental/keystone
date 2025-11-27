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

//! Embedded type webauthn_rs::prelude::CreationChallengeResponse

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Passkey registration request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct UserPasskeyRegistrationStartRequest {
    /// The description for the passkey (name).
    pub passkey: PasskeyCreate,
}

/// Passkey information.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct PasskeyCreate {
    /// Passkey description
    #[schema(nullable = false, max_length = 64)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Passkey.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct PasskeyResponse {
    /// The description for the passkey (name).
    pub passkey: Passkey,
}

/// Passkey information.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct Passkey {
    /// Credential ID.
    pub credential_id: String,
    /// Credential description.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Passkey challenge.
///
/// This is the WebauthN challenge that need to be signed by the
/// passkey/security device.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct UserPasskeyRegistrationStartResponse {
    /// The options.
    pub public_key: PublicKeyCredentialCreationOptions,
}

/// The requested options for the authentication.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct PublicKeyCredentialCreationOptions {
    /// The requested attestation level from the device.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<AttestationConveyancePreference>,
    /// The list of attestation formats that the RP will accept.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_formats: Option<Vec<AttestationFormat>>,
    /// Criteria defining which authenticators may be used in this operation.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    /// The challenge that should be signed by the authenticator.
    #[schema(value_type = String, format = Binary, content_encoding = "base64")]
    pub challenge: String,
    /// Credential ID’s that are excluded from being able to be registered.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
    /// extensions.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<RequestRegistrationExtensions>,
    /// Hints defining which types credentials may be used in this operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hints: Option<Vec<PublicKeyCredentialHints>>,
    /// The set of cryptographic types allowed by this server.
    pub pub_key_cred_params: Vec<PubKeyCredParams>,
    /// The relying party
    pub rp: RelyingParty,
    /// The timeout for the authenticator in case of no interaction.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    /// The user.
    pub user: User,
}

/// Relying Party Entity.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct RelyingParty {
    /// The id of the relying party.
    pub id: String,
    /// The name of the relying party.
    pub name: String,
}

/// User Entity.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
#[schema(as = PasskeyUser)]
pub struct User {
    /// The user’s id in base64 form. This MUST be a unique id, and must NOT
    /// contain personally identifying information, as this value can NEVER
    /// be changed. If in doubt, use a UUID.
    #[schema(value_type = String, format = Binary, content_encoding = "base64")]
    pub id: String,
    /// A detailed name for the account, such as an email address. This value
    /// can change, so must not be used as a primary key.
    pub name: String,
    /// The user’s preferred name for display. This value can change, so must
    /// not be used as a primary key.
    pub display_name: String,
}

/// Public key cryptographic parameters
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct PubKeyCredParams {
    /// The algorithm in use defined by CASE.
    pub alg: i64,
    /// The type of public-key credential.
    pub type_: String,
}

/// <https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialdescriptor>
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct PublicKeyCredentialDescriptor {
    /// The type of credential.
    pub type_: String,
    /// The credential id.
    #[schema(value_type = String, format = Binary, content_encoding = "base64")]
    pub id: String,
    /// The allowed transports for this credential. Note this is a hint, and is
    /// NOT enforced.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<AuthenticatorTransport>>,
}

///
/// Request in residentkey workflows that conditional mediation should be used
/// in the UI, or not.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub enum Mediation {
    /// Discovered credentials are presented to the user in a dialog.
    /// Conditional UI is used. See <https://github.com/w3c/webauthn/wiki/Explainer:-WebAuthn-Conditional-UI>
    /// <https://w3c.github.io/webappsec-credential-management/#enumdef-credentialmediationrequirement>
    Conditional,
}

/// A descriptor of a credential that can be used.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct AllowCredentials {
    /// The type of credential.
    pub type_: String,
    /// The id of the credential.
    #[schema(value_type = String, format = Binary, content_encoding = "base64")]
    pub id: String,
    /// <https://www.w3.org/TR/webauthn/#transport> may be usb, nfc, ble, internal
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<AuthenticatorTransport>>,
}

/// <https://www.w3.org/TR/webauthn/#enumdef-authenticatortransport>
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub enum AuthenticatorTransport {
    /// <https://www.w3.org/TR/webauthn/#dom-authenticatortransport-ble>
    Ble,
    /// Hybrid transport, formerly caBLE. Part of the level 3 draft
    /// specification. <https://w3c.github.io/webauthn/#dom-authenticatortransport-hybrid>
    Hybrid,
    /// <https://www.w3.org/TR/webauthn/#dom-authenticatortransport-internal>
    Internal,
    /// <https://www.w3.org/TR/webauthn/#dom-authenticatortransport-nfc>
    Nfc,
    /// Test transport; used for Windows 10.
    Test,
    /// An unknown transport was provided - it will be ignored.
    Unknown,
    /// <https://www.w3.org/TR/webauthn/#dom-authenticatortransport-usb>
    Usb,
}

/// <https://www.w3.org/TR/webauthn/#dictdef-authenticatorselectioncriteria>
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct AuthenticatorSelectionCriteria {
    /// How the authenticator should be attached to the client machine. Note
    /// this is only a hint. It is not enforced in anyway shape or form. <https://www.w3.org/TR/webauthn/#attachment>.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
    /// Hint to the credential to create a resident key. Note this value should
    /// be a member of ResidentKeyRequirement, but client must ignore
    /// unknown values, treating an unknown value as if the member does not
    /// exist. <https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-residentkey>.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resident_key: Option<ResidentKeyRequirement>,
    /// Hint to the credential to create a resident key. Note this can not be
    /// enforced or validated, so the authenticator may choose to ignore
    /// this parameter. <https://www.w3.org/TR/webauthn/#resident-credential>.
    pub require_resident_key: bool,
    /// The user verification level to request during registration. Depending on
    /// if this authenticator provides verification may affect future
    /// interactions as this is associated to the credential during
    /// registration.
    pub user_verification: UserVerificationPolicy,
}

/// The authenticator attachment hint. This is NOT enforced, and is only used to
/// help a user select a relevant authenticator type.
///
/// <https://www.w3.org/TR/webauthn/#attachment>
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub enum AuthenticatorAttachment {
    /// Request a device that is part of the machine aka inseparable.
    /// <https://www.w3.org/TR/webauthn/#attachment>.
    Platform,
    /// Request a device that can be separated from the machine aka an external
    /// token. <https://www.w3.org/TR/webauthn/#attachment>.
    CrossPlatform,
}

/// The Relying Party’s requirements for client-side discoverable credentials.
///
/// <https://www.w3.org/TR/webauthn-2/#enumdef-residentkeyrequirement>
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub enum ResidentKeyRequirement {
    /// <https://www.w3.org/TR/webauthn-2/#dom-residentkeyrequirement-discouraged>.
    Discouraged,
    /// ⚠️ In all major browsers preferred is identical in behaviour to
    /// required. You should use required instead. <https://www.w3.org/TR/webauthn-2/#dom-residentkeyrequirement-preferred>.
    Preferred,
    /// <https://www.w3.org/TR/webauthn-2/#dom-residentkeyrequirement-required>.
    Required,
}

/// A hint as to the class of device that is expected to fufil this operation.
///
/// <https://www.w3.org/TR/webauthn-3/#enumdef-publickeycredentialhints>
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub enum PublicKeyCredentialHints {
    /// The credential is a platform authenticator.
    ClientDevice,
    /// The credential will come from an external device.
    Hybrid,
    /// The credential is a removable security key.
    SecurityKey,
}

/// <https://www.w3.org/TR/webauthn/#enumdef-attestationconveyancepreference>
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub enum AttestationConveyancePreference {
    /// Do not request attestation.
    /// <https://www.w3.org/TR/webauthn/#dom-attestationconveyancepreference-none>.
    None,
    /// Request attestation in a semi-anonymized form.
    /// <https://www.w3.org/TR/webauthn/#dom-attestationconveyancepreference-indirect>.
    Indirect,
    /// Request attestation in a direct form.
    /// <https://www.w3.org/TR/webauthn/#dom-attestationconveyancepreference-direct>.
    Direct,
}

/// The type of attestation on the credential.
///
/// <https://www.iana.org/assignments/webauthn/webauthn.xhtml>
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub enum AttestationFormat {
    /// Packed attestation.
    Packed,
    /// TPM attestation (like Microsoft).
    Tpm,
    /// Android hardware attestation.
    AndroidKey,
    /// Older Android Safety Net.
    AndroidSafetyNet,
    /// Old U2F attestation type.
    FIDOU2F,
    /// Apple touchID/faceID.
    AppleAnonymous,
    /// No attestation.
    None,
}

/// Extension option inputs for PublicKeyCredentialCreationOptions.
///
/// Implements `AuthenticatorExtensionsClientInputs` from the spec.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct RequestRegistrationExtensions {
    /// ⚠️ - This extension result is always unsigned, and only indicates if the
    /// browser requests a residentKey to be created. It has no bearing on
    /// the true rk state of the credential.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_props: Option<bool>,
    /// The credProtect extension options.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_protect: Option<CredProtect>,
    /// ⚠️ - Browsers support the creation of the secret, but not the retrieval
    /// of it. CTAP2.1 create hmac secret.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac_create_secret: Option<bool>,
    /// CTAP2.1 Minimum pin length.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_pin_length: Option<bool>,
    /// ⚠️ - Browsers do not support this! Uvm
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uvm: Option<bool>,
}

/// The desired options for the client’s use of the credProtect extension
///
/// <https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#sctn-credProtect-extension>
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct CredProtect {
    /// The credential policy to enact.
    pub credential_protection_policy: CredentialProtectionPolicy,
    /// Whether it is better for the authenticator to fail to create a
    /// credential rather than ignore the protection policy If no value is
    /// provided, the client treats it as false.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforce_credential_protection_policy: Option<bool>,
}

/// Valid credential protection policies
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
#[repr(u8)]
pub enum CredentialProtectionPolicy {
    /// This reflects “FIDO_2_0” semantics. In this configuration, performing
    /// some form of user verification is optional with or without
    /// credentialID list. This is the default state of the credential if
    /// the extension is not specified.
    UserVerificationOptional = 1,
    /// In this configuration, credential is discovered only when its
    /// credentialID is provided by the platform or when some form of user
    /// verification is performed.
    UserVerificationOptionalWithCredentialIDList = 2,
    /// This reflects that discovery and usage of the credential MUST be
    /// preceded by some form of user verification.
    UserVerificationRequired = 3,
}

/// Defines the User Authenticator Verification policy. This is documented
/// <https://w3c.github.io/webauthn/#enumdef-userverificationrequirement>, and each variant lists
/// it’s effects.
///
/// To be clear, Verification means that the Authenticator perform extra or
/// supplementary interaction with the user to verify who they are. An example
/// of this is Apple Touch Id required a fingerprint to be verified, or a yubico
/// device requiring a pin in addition to a touch event.
///
/// An example of a non-verified interaction is a yubico device with no pin
/// where touch is the only interaction - we only verify a user is present, but
/// we don’t have extra details to the legitimacy of that user.
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
    /// it’s presence at registration.
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

/// A client response to a registration challenge. This contains all required
/// information to assess and assert trust in a credential’s legitimacy,
/// followed by registration to a user.
///
/// You should not need to handle the inner content of this structure - you
/// should provide this to the correctly handling function of Webauthn only.
/// <https://w3c.github.io/webauthn/#iface-pkcredential>
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct UserPasskeyRegistrationFinishRequest {
    /// Optional credential description.
    #[schema(nullable = false, max_length = 64)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The id of the PublicKey credential, likely in base64.
    ///
    /// This is NEVER actually used in a real registration, because the true
    /// credential ID is taken from the attestation data.
    pub id: String,
    /// The id of the credential, as binary.
    ///
    /// This is NEVER actually used in a real registration, because the true
    /// credential ID is taken from the attestation data.
    #[schema(value_type = String, format = Binary, content_encoding = "base64")]
    pub raw_id: String,
    /// <https://w3c.github.io/webauthn/#dom-publickeycredential-response>.
    pub response: AuthenticatorAttestationResponseRaw,
    /// The type of credential.
    pub type_: String,
    /// Unsigned Client processed extensions.
    pub extensions: RegistrationExtensionsClientOutputs,
}

/// <https://w3c.github.io/webauthn/#authenticatorattestationresponse>
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct AuthenticatorAttestationResponseRaw {
    /// <https://w3c.github.io/webauthn/#dom-authenticatorattestationresponse-attestationobject>.
    #[schema(value_type = String, format = Binary, content_encoding = "base64")]
    pub attestation_object: String,
    /// <https://w3c.github.io/webauthn/#dom-authenticatorresponse-clientdatajson>.
    #[schema(value_type = String, format = Binary, content_encoding = "base64")]
    pub client_data_json: String,
    /// <https://w3c.github.io/webauthn/#dom-authenticatorattestationresponse-gettransports>.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<AuthenticatorTransport>>,
}

/// <https://w3c.github.io/webauthn/#dictdef-authenticationextensionsclientoutputs> The default
/// option here for Options are None, so it can be derived
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct RegistrationExtensionsClientOutputs {
    /// Indicates whether the client used the provided appid extension.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub appid: Option<bool>,
    /// Indicates if the client believes it created a resident key. This
    /// property is managed by the webbrowser, and is NOT SIGNED and CAN NOT
    /// be trusted!
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_props: Option<CredProps>,
    /// Indicates if the client successfully applied a HMAC Secret.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac_secret: Option<bool>,
    /// Indicates if the client successfully applied a credential protection
    /// policy.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_protect: Option<CredentialProtectionPolicy>,
    /// Indicates the current minimum PIN length.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_pin_length: Option<u32>,
}

/// <https://www.w3.org/TR/webauthn-3/#sctn-authenticator-credential-properties-extension>
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct CredProps {
    /// A user agent supplied hint that this credential may have created a
    /// resident key. It is returned from the user agent, not the
    /// authenticator meaning that this is an unreliable signal.
    ///
    /// Note that this extension is UNSIGNED and may have been altered by page
    /// javascript.
    pub rk: bool,
}

impl From<crate::identity::types::WebauthnCredential> for PasskeyResponse {
    fn from(value: crate::identity::types::WebauthnCredential) -> Self {
        Self {
            passkey: value.into(),
        }
    }
}

impl From<crate::identity::types::WebauthnCredential> for Passkey {
    fn from(value: crate::identity::types::WebauthnCredential) -> Self {
        Self {
            credential_id: value.credential_id,
            description: value.description,
        }
    }
}
