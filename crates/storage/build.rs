fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_files = [
        "proto/raft.proto",
        "proto/storage_types.proto",
        "proto/storage.proto",
    ];

    // Use PROTOC_INCLUDE env var if set; otherwise auto-detect common system paths.
    let sys_include = std::env::var("PROTOC_INCLUDE").ok().or_else(|| {
        ["/usr/include", "/usr/local/include"]
            .iter()
            .find(|p| std::path::Path::new(p).exists())
            .map(|p| p.to_string())
    });
    let mut includes = vec!["proto"];
    if let Some(ref extra) = sys_include {
        includes.push(extra.as_str());
    }

    tonic_prost_build::configure()
        .btree_map(".")
        .type_attribute("keystone.raft.Entry", "#[derive(Deserialize, Serialize)]")
        .type_attribute(
            "keystone.raft.LeaderId",
            "#[derive(Deserialize, Serialize)]",
        )
        .type_attribute("keystone.raft.LogId", "#[derive(Deserialize, Serialize)]")
        .type_attribute(
            "keystone.raft.Membership",
            "#[derive(Deserialize, Serialize)]",
        )
        .type_attribute("keystone.raft.Node", "#[derive(Deserialize, Serialize)]")
        .type_attribute(
            "keystone.raft.NodeIdSet",
            "#[derive(Deserialize, Serialize)]",
        )
        .type_attribute("keystone.raft.Vote", "#[derive(Deserialize, Serialize)]")
        .type_attribute("keystone.api.Response", "#[derive(Deserialize, Serialize)]")
        .type_attribute(
            "keystone.api.Response.Violation",
            "#[derive(serde::Deserialize, serde::Serialize)]",
        )
        .type_attribute(
            "keystone.api.CommandRequest",
            "#[derive(Deserialize, Serialize)]",
        )
        //        .type_attribute(
        //            "keystone.api.DeleteRequest",
        //            "#[derive(Deserialize, Serialize)]",
        //        )
        //        .type_attribute(
        //            "keystone.api.StoreRequest",
        //            "#[derive(Deserialize, Serialize)]",
        //        )
        //        .type_attribute(
        //            "keystone.api.StoreRequest.request",
        //            "#[derive(serde::Deserialize, serde::Serialize)]",
        //        )
        //.type_attribute("keystone.api.Response", "#[derive(Deserialize, Serialize)]")
        .compile_protos(&proto_files, &includes)?;
    Ok(())
}
