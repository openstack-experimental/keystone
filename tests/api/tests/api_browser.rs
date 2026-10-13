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
//! Real-browser tests of the OAuth2 sign-in pages. Need a WebDriver
//! (`chromedriver --port=4444`, Chromium) or `BROWSER=firefox` with geckodriver; see `test_api::browser`.

mod api_browser {
    mod oauth2_device;
    mod oauth2_login;
    mod oauth2_passkey;
}
