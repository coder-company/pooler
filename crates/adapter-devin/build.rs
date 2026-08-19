use std::{env, path::PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest path"));
    let proto_root = manifest_dir.join("proto");
    let files = [
        "buf/validate/validate.proto",
        "exa/analytics_pb/analytics.proto",
        "exa/api_server_pb/api_server.proto",
        "exa/auth_pb/auth.proto",
        "exa/auto_cascade_common_pb/auto_cascade_common.proto",
        "exa/bug_checker_pb/bug_checker.proto",
        "exa/cascade_plugins_pb/cascade_plugins.proto",
        "exa/chat_pb/chat.proto",
        "exa/code_edit/code_edit_pb/code_edit.proto",
        "exa/codeium_common_pb/codeium_common.proto",
        "exa/context_module_pb/context_module.proto",
        "exa/cortex_pb/cortex.proto",
        "exa/diff_action_pb/diff_action.proto",
        "exa/index_pb/index.proto",
        "exa/knowledge_base_pb/knowledge_base.proto",
        "exa/language_server_pb/language_server.proto",
        "exa/opensearch_clients_pb/opensearch_clients.proto",
        "exa/prompt_pb/prompt.proto",
        "exa/reactive_component_pb/reactive_component.proto",
        "exa/trust_pb/trust.proto",
    ];
    for file in files {
        println!("cargo:rerun-if-changed={}", proto_root.join(file).display());
    }

    let protoc = protoc_bin_vendored::protoc_bin_path().expect("bundled protoc path");
    env::set_var("PROTOC", protoc);

    let mut config = prost_build::Config::new();
    config.include_file("mod.rs");
    config.type_attribute(".", "#[allow(clippy::all)]");
    let paths = files
        .iter()
        .map(|file| proto_root.join(file))
        .collect::<Vec<_>>();
    config
        .compile_protos(&paths, &[proto_root])
        .expect("compile vendored Devin protobuf sources");
}
