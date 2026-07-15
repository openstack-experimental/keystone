use eyre::Result;
use openstack_keystone_api_types::v3::application_credential::application_credential::*;
use openstack_sdk::{AsyncOpenStack, config::CloudConfig};
use std::sync::Arc;
use test_api::guard::ResourceGuard;
use test_api::identity::application_credential::{
    create_application_credential, list_application_credentials,
};
use tracing_test::traced_test;

pub async fn get_project_scoped_client() -> Result<Arc<AsyncOpenStack>> {
    let mut tc = AsyncOpenStack::new(&CloudConfig::from_env()?).await?;

    tc.authorize(
        Some(openstack_sdk::auth::authtoken::AuthTokenScope::Project(
            openstack_sdk::types::identity::v3::Project {
                id: None,
                name: Some("admin".to_string()),
                domain: Some(openstack_sdk::types::identity::v3::Domain {
                    id: Some("default".to_string()),
                    name: None,
                }),
            },
        )),
        false,
        false,
    )
    .await?;

    Ok(Arc::new(tc))
}

#[tokio::test]
#[traced_test]
async fn test_list() -> Result<()> {
    let tc = get_project_scoped_client().await?;
    let user_id = tc
        .get_auth_info()
        .ok_or_else(|| eyre::eyre!("no auth info available"))?
        .token
        .user
        .id;

    let cred1 = create_application_credential(
        &tc,
        &user_id,
        ApplicationCredentialCreateBuilder::default()
            .name(format!("cred-1"))
            .roles(vec![])
            .build()?,
    )
    .await?;

    let cred2 = create_application_credential(
        &tc,
        &user_id,
        ApplicationCredentialCreateBuilder::default()
            .name(format!("cred-2"))
            .roles(vec![])
            .build()?,
    )
    .await?;

    let list = list_application_credentials(&tc, &user_id).await?;
    assert!(list.iter().any(|c| c.id == cred1.id));
    assert!(list.iter().any(|c| c.id == cred2.id));

    cred1.delete().await?;
    cred2.delete().await?;
    Ok(())
}
