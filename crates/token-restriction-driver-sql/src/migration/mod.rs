pub use sea_orm_migration::prelude::*;

mod m20251005_131042_token_restriction;

pub fn migrations() -> Vec<Box<dyn MigrationTrait>> {
    vec![Box::new(m20251005_131042_token_restriction::Migration)]
}
