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
//! Typed configuration sections and the registry that lets crates other than
//! the schema crate own their section.
//!
//! The INI section name is bound to the Rust type
//! ([`ConfigSection::NAME`]) so a lookup by type can never mismatch the name.
//! A crate registers its section with `register_section!`; registration is
//! link-time (the same mechanism as the backend registrations), while the
//! values are (re-)parsed on every load, so registered sections follow
//! the live reload of the configuration exactly like the core ones.
use std::any::{Any, TypeId};
use std::collections::{HashMap, HashSet};
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::sync::Arc;

use eyre::{Report, WrapErr, eyre};
use serde::de::DeserializeOwned;

/// Error type of the section hooks.
pub type ConfigError = Report;

/// Context handed to [`ConfigSection::finish`].
#[derive(Clone, Debug)]
pub struct LoadCtx {
    /// Path of the main configuration file.
    pub config_path: PathBuf,
}

/// A typed section of the configuration file.
///
/// A section type that implements [`Default`] is optional: when the INI
/// section is missing the value is materialized from `Default` (the
/// `#[serde(default)]` behaviour). A section type without a `Default` is
/// required and must be present when somebody asks for it
/// ([`ConfigView::require`]).
pub trait ConfigSection: DeserializeOwned + Send + Sync + 'static {
    /// Name of the INI section (e.g. `openfga`).
    const NAME: &'static str;

    /// Post-process the freshly parsed section: read the files it refers to.
    fn finish(&mut self, _ctx: &LoadCtx) -> Result<(), ConfigError> {
        Ok(())
    }

    /// Second validation pass, run when all registered sections are
    /// materialized. Sibling registered sections can be read from `sections`.
    fn validate_with(&self, _sections: &SectionBag) -> Result<(), ConfigError> {
        Ok(())
    }

    /// Files (or directories) whose change must trigger a reload.
    fn watch_files(&self) -> Vec<PathBuf> {
        Vec::new()
    }
}

/// Object safe facade over [`ConfigSection`].
trait ErasedSection: Any + Send + Sync {
    /// The section as [`Any`], for downcasting to its concrete type.
    fn as_any(&self) -> &dyn Any;
    /// See [`ConfigSection::finish`].
    fn finish(&mut self, ctx: &LoadCtx) -> Result<(), ConfigError>;
    /// See [`ConfigSection::validate_with`].
    fn validate_with(&self, sections: &SectionBag) -> Result<(), ConfigError>;
    /// See [`ConfigSection::watch_files`].
    fn watch_files(&self) -> Vec<PathBuf>;
}

impl<S: ConfigSection> ErasedSection for S {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn finish(&mut self, ctx: &LoadCtx) -> Result<(), ConfigError> {
        ConfigSection::finish(self, ctx)
    }
    fn validate_with(&self, sections: &SectionBag) -> Result<(), ConfigError> {
        ConfigSection::validate_with(self, sections)
    }
    fn watch_files(&self) -> Vec<PathBuf> {
        ConfigSection::watch_files(self)
    }
}

/// Function parsing one registered section out of the raw configuration.
type ParseFn = fn(&config::Config) -> Result<Option<Box<dyn ErasedSection>>, Report>;

/// Type erased description of a registered section.
pub struct SectionDescriptor {
    /// INI section name.
    pub name: &'static str,
    /// Parser of the section out of the raw configuration.
    parse: ParseFn,
    /// [`TypeId`] of the section type.
    type_id: fn() -> TypeId,
}

impl SectionDescriptor {
    /// Describe a section that is optional: absent in the file means
    /// `S::default()`.
    pub const fn optional<S: ConfigSection + Default>() -> Self {
        Self {
            name: S::NAME,
            parse: parse_optional::<S>,
            type_id: TypeId::of::<S>,
        }
    }

    /// Describe a section that is required: absent in the file means absent
    /// in the [`SectionBag`].
    pub const fn required<S: ConfigSection>() -> Self {
        Self {
            name: S::NAME,
            parse: parse_required::<S>,
            type_id: TypeId::of::<S>,
        }
    }
}

inventory::collect!(SectionDescriptor);

/// Read the section `S` out of the raw configuration; `None` when it is not
/// present.
fn read_section<S: ConfigSection>(raw: &config::Config) -> Result<Option<S>, Report> {
    match raw.get::<S>(S::NAME) {
        Ok(section) => Ok(Some(section)),
        Err(config::ConfigError::NotFound(_)) => Ok(None),
        Err(err) => Err(Report::new(err).wrap_err(format!("parsing [{}] section", S::NAME))),
    }
}

/// [`ParseFn`] of a required section: `None` when absent.
fn parse_required<S: ConfigSection>(
    raw: &config::Config,
) -> Result<Option<Box<dyn ErasedSection>>, Report> {
    Ok(read_section::<S>(raw)?.map(|s| Box::new(s) as Box<dyn ErasedSection>))
}

/// [`ParseFn`] of an optional section: `S::default()` when absent.
fn parse_optional<S: ConfigSection + Default>(
    raw: &config::Config,
) -> Result<Option<Box<dyn ErasedSection>>, Report> {
    Ok(Some(
        Box::new(read_section::<S>(raw)?.unwrap_or_default()) as Box<dyn ErasedSection>
    ))
}

/// Register a [`ConfigSection`] type with the engine.
///
/// `register_section!(S)` registers a required section; use
/// `register_section!(S, default)` for a section implementing `Default` that
/// is materialized when the file does not contain it.
#[macro_export]
macro_rules! register_section {
    ($section:ty) => {
        $crate::inventory::submit! { $crate::SectionDescriptor::required::<$section>() }
    };
    ($section:ty, default) => {
        $crate::inventory::submit! { $crate::SectionDescriptor::optional::<$section>() }
    };
}

/// The materialized registered sections, keyed by their Rust type.
#[derive(Default)]
pub struct SectionBag {
    /// The sections by the [`TypeId`] of their type.
    sections: HashMap<TypeId, Box<dyn ErasedSection>>,
}

impl SectionBag {
    /// Get the section by type.
    pub fn get<S: ConfigSection>(&self) -> Option<&S> {
        self.sections
            .get(&TypeId::of::<S>())
            .and_then(|s| s.as_any().downcast_ref::<S>())
    }

    /// Insert (or replace) a section value. Mainly useful for tests.
    pub fn insert<S: ConfigSection>(&mut self, section: S) {
        self.sections.insert(TypeId::of::<S>(), Box::new(section));
    }

    /// Files watched by all sections.
    fn watch_files(&self) -> HashSet<PathBuf> {
        self.sections
            .values()
            .flat_map(|s| s.watch_files())
            .collect()
    }
}

/// Fail on duplicate section names across registrations and on names that
/// collide with `reserved` (the sections of the core schema).
pub fn check_registry(reserved: &[&str]) -> Result<(), Report> {
    let mut seen: HashMap<&'static str, TypeId> = HashMap::new();
    for descriptor in inventory::iter::<SectionDescriptor> {
        if reserved.contains(&descriptor.name) {
            return Err(eyre!(
                "section [{}] is reserved by the core schema",
                descriptor.name
            ));
        }
        let type_id = (descriptor.type_id)();
        if let Some(previous) = seen.insert(descriptor.name, type_id)
            && previous != type_id
        {
            return Err(eyre!(
                "section [{}] is registered by more than one type",
                descriptor.name
            ));
        }
    }
    Ok(())
}

/// Names of the top-level sections of `raw` that neither the core schema
/// (`reserved`) nor any registered section claims, e.g. a misspelled
/// `[openfga_typo]`. Only tables count: scalar top-level keys come from
/// environment variables such as `OS_CLOUD` and are not sections.
pub fn unclaimed_sections(raw: &config::Config, reserved: &[&str]) -> Vec<String> {
    let claimed: HashSet<String> = reserved
        .iter()
        .copied()
        .chain(
            inventory::iter::<SectionDescriptor>
                .into_iter()
                .map(|d| d.name),
        )
        .map(str::to_lowercase)
        .collect();
    let mut unclaimed: Vec<String> = raw
        .cache
        .clone()
        .into_table()
        .map(|table| {
            table
                .into_iter()
                .filter(|(_, value)| matches!(value.kind, config::ValueKind::Table(_)))
                .map(|(name, _)| name)
                .filter(|name| !claimed.contains(&name.to_lowercase()))
                .collect()
        })
        .unwrap_or_default();
    unclaimed.sort();
    unclaimed
}

/// Assert that every name in `expected` is registered. Catches a driver whose
/// registration was dropped by the linker.
pub fn assert_registered(expected: &[&str]) -> Result<(), Report> {
    let registered: HashSet<&str> = inventory::iter::<SectionDescriptor>
        .into_iter()
        .map(|d| d.name)
        .collect();
    for name in expected {
        if !registered.contains(name) {
            return Err(eyre!("section [{name}] is not registered"));
        }
    }
    Ok(())
}

/// Parse all registered sections out of the raw configuration, run the
/// `finish` hooks and the validation pass.
pub(crate) fn load_sections(raw: &config::Config, ctx: &LoadCtx) -> Result<SectionBag, Report> {
    let mut bag = SectionBag::default();
    for descriptor in inventory::iter::<SectionDescriptor> {
        if let Some(mut section) = (descriptor.parse)(raw)? {
            section
                .finish(ctx)
                .wrap_err_with(|| format!("reading [{}] section", descriptor.name))?;
            bag.sections.insert((descriptor.type_id)(), section);
        }
    }
    for section in bag.sections.values() {
        section
            .validate_with(&bag)
            .wrap_err("Configuration validation failed")?;
    }
    Ok(bag)
}

/// One consistent snapshot of the configuration: the core schema value and
/// the registered sections. Reload swaps both together.
pub struct Loaded<C> {
    /// The core schema.
    pub core: C,
    /// The registered sections, shared between clones of the snapshot.
    pub sections: Arc<SectionBag>,
}

impl<C: Clone> Clone for Loaded<C> {
    /// Clone the core schema; the sections are shared.
    fn clone(&self) -> Self {
        Self {
            core: self.core.clone(),
            sections: Arc::clone(&self.sections),
        }
    }
}

impl<C> Loaded<C> {
    /// Create a snapshot without registered sections.
    pub fn new(core: C) -> Self {
        Self {
            core,
            sections: Arc::new(SectionBag::default()),
        }
    }

    /// Files watched by the registered sections.
    pub(crate) fn section_watch_files(&self) -> HashSet<PathBuf> {
        self.sections.watch_files()
    }

    /// Borrow the snapshot as a [`ConfigView`].
    pub fn view(&self) -> ConfigView<'_, C> {
        ConfigView {
            core: &self.core,
            sections: &self.sections,
        }
    }

    /// Create a snapshot from a core value and a ready made section bag.
    pub fn with_sections(core: C, sections: SectionBag) -> Self {
        Self {
            core,
            sections: Arc::new(sections),
        }
    }
}

impl<C> Deref for Loaded<C> {
    type Target = C;
    /// The core schema.
    fn deref(&self) -> &C {
        &self.core
    }
}

impl<C> DerefMut for Loaded<C> {
    /// The core schema.
    fn deref_mut(&mut self) -> &mut C {
        &mut self.core
    }
}

/// Typed read access to the configuration: the core schema (through `Deref`)
/// plus the registered sections.
pub struct ConfigView<'a, C> {
    /// The core schema.
    pub core: &'a C,
    /// The registered sections.
    sections: &'a SectionBag,
}

impl<C> Clone for ConfigView<'_, C> {
    /// A view is a pair of references, so cloning copies it.
    fn clone(&self) -> Self {
        *self
    }
}
impl<C> Copy for ConfigView<'_, C> {}

impl<'a, C> ConfigView<'a, C> {
    /// Create a view from its parts.
    pub fn new(core: &'a C, sections: &'a SectionBag) -> Self {
        Self { core, sections }
    }

    /// The registered section `S`, or an error naming the missing section.
    pub fn require<S: ConfigSection>(&self) -> Result<&'a S, ConfigError> {
        self.section::<S>()
            .ok_or_else(|| eyre!("required section [{}] is missing", S::NAME))
    }

    /// The registered section `S`, if materialized.
    pub fn section<S: ConfigSection>(&self) -> Option<&'a S> {
        self.sections.get::<S>()
    }
}

impl<C> Deref for ConfigView<'_, C> {
    type Target = C;
    /// The core schema.
    fn deref(&self) -> &C {
        self.core
    }
}

/// A parsed, type erased section value, for blocks whose type is chosen by a
/// discriminator in the file (e.g. `driver = openfga`) rather than by the
/// section name. Cheap to clone, comparable and printable, so a reload can
/// detect changed blocks without knowing their type.
///
/// Unlike a registered section, a block is not in the [`SectionBag`] and is
/// not reachable through [`ConfigView::section`]: the schema stores it in its
/// own field (e.g. the `Named` variant of a per-domain backend config) and
/// the driver that owns the type recovers it with [`Self::downcast_ref`].
/// The same type may be registered both as a section (`register_section!`)
/// and as a block (`register_block!`).
#[derive(Clone)]
pub struct ParsedSection {
    /// The type erased value.
    inner: Arc<dyn ErasedBlock>,
}

/// Object safe facade over the value of a [`ParsedSection`].
trait ErasedBlock: Any + Send + Sync + std::fmt::Debug {
    /// The value as [`Any`], for downcasting to its concrete type.
    fn as_any(&self) -> &dyn Any;
    /// Compare with another type erased value.
    fn eq_dyn(&self, other: &dyn Any) -> bool;
}

impl<S> ErasedBlock for S
where
    S: Any + Send + Sync + std::fmt::Debug + PartialEq,
{
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn eq_dyn(&self, other: &dyn Any) -> bool {
        other.downcast_ref::<S>().is_some_and(|o| self == o)
    }
}

impl ParsedSection {
    /// Borrow the value as its concrete type.
    ///
    /// Returns `None` when the block was parsed into a different type, which
    /// means it belongs to another driver. The owning driver should report
    /// that as a misconfiguration.
    pub fn downcast_ref<S: Any>(&self) -> Option<&S> {
        self.inner.as_any().downcast_ref::<S>()
    }

    /// Wrap a parsed value.
    pub fn new<S>(section: S) -> Self
    where
        S: Any + Send + Sync + std::fmt::Debug + PartialEq,
    {
        Self {
            inner: Arc::new(section),
        }
    }
}

impl PartialEq for ParsedSection {
    /// Equal when both hold the same type and the values are equal.
    fn eq(&self, other: &Self) -> bool {
        self.inner.eq_dyn(other.inner.as_any())
    }
}

impl std::fmt::Debug for ParsedSection {
    /// Format the wrapped value.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}

/// Description of a driver specific configuration block selected by a
/// discriminator, e.g. `[assignment.backends.<name>] driver = openfga`.
pub struct BlockDescriptor {
    /// Value of the discriminator (e.g. `openfga`).
    pub driver: &'static str,
    /// Namespace of the blocks, owned by the schema (e.g.
    /// `assignment.backends`).
    pub namespace: &'static str,
    /// Parser of the block value into the registered type.
    parse: fn(config::Value) -> Result<ParsedSection, Report>,
}

impl BlockDescriptor {
    /// Describe a block parsed into `S`.
    pub const fn new<S>(namespace: &'static str, driver: &'static str) -> Self
    where
        S: DeserializeOwned + Any + Send + Sync + std::fmt::Debug + PartialEq,
    {
        Self {
            driver,
            namespace,
            parse: parse_block_as::<S>,
        }
    }
}

/// Parse a block value into `S` and wrap it as a [`ParsedSection`].
fn parse_block_as<S>(value: config::Value) -> Result<ParsedSection, Report>
where
    S: DeserializeOwned + Any + Send + Sync + std::fmt::Debug + PartialEq,
{
    Ok(ParsedSection::new(value.try_deserialize::<S>()?))
}

inventory::collect!(BlockDescriptor);

/// Register the type a `driver` block of `namespace` is parsed into.
#[macro_export]
macro_rules! register_block {
    ($namespace:expr, $driver:expr, $section:ty) => {
        $crate::inventory::submit! { $crate::BlockDescriptor::new::<$section>($namespace, $driver) }
    };
}

/// Parse the block `value` of `namespace` with the type registered for
/// `driver`.
///
/// # Errors
/// Fails when no type is registered for `driver` (the driver crate is not
/// linked) or when the block does not fit the registered type.
pub fn parse_block(
    namespace: &str,
    driver: &str,
    value: config::Value,
) -> Result<ParsedSection, Report> {
    let descriptor = inventory::iter::<BlockDescriptor>
        .into_iter()
        .find(|d| d.namespace == namespace && d.driver == driver)
        .ok_or_else(|| eyre!("unknown driver `{driver}` for [{namespace}.*] (is it linked?)"))?;
    (descriptor.parse)(value)
        .wrap_err_with(|| format!("parsing a `{driver}` block of [{namespace}.*]"))
}
