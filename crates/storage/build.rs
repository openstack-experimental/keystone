fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_files = [
        "proto/raft.proto",
        "proto/identity_types.proto",
        "proto/identity.proto",
    ];

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
        .type_attribute(
            "keystone.api.SetRequest",
            "#[derive(Deserialize, Serialize)]",
        )
        .type_attribute("keystone.api.Response", "#[derive(Deserialize, Serialize)]")
        .compile_protos(&proto_files, &["proto"])?;
    Ok(())
}
