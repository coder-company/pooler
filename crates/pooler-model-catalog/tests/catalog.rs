use pooler_core::{Capability, CapabilitySet, FactSupport, ModelDialect, ModelId, ModelProfile};
use pooler_model_catalog::{
    merge_discoveries, AliasConfig, CatalogConfig, CatalogError, CatalogInput, CatalogSourceConfig,
    DiscoveredModel, DiscoveryResponse, ModelOverrideConfig, ModelOverrides, RefreshConfig,
};

fn model(id: &str, capabilities: &[Capability]) -> DiscoveredModel {
    DiscoveredModel::new(
        ModelId::new(id).expect("valid test model"),
        capabilities.iter().copied().collect::<CapabilitySet>(),
    )
}

fn source(config: CatalogSourceConfig) -> pooler_model_catalog::CatalogSource {
    config.compile().expect("valid test source")
}

fn limits() -> pooler_model_catalog::RefreshLimits {
    RefreshConfig::default()
        .compile()
        .expect("default limits compile")
}

fn no_overrides() -> ModelOverrides {
    ModelOverrides::default()
}

fn overrides(declarations: Vec<ModelOverrideConfig>) -> ModelOverrides {
    ModelOverrides::compile(declarations).expect("valid test overrides")
}

#[test]
fn merge_applies_exclusions_aliases_forks_prefixes_and_provenance() {
    let openai = source(CatalogSourceConfig {
        id: "openai.primary".to_owned(),
        provider: "openai".to_owned(),
        priority: 20,
        aliases: vec![AliasConfig {
            name: "gpt-5.2".to_owned(),
            alias: "flagship".to_owned(),
            fork: true,
            display_name: Some("Pooler Flagship".to_owned()),
            force_mapping: true,
        }],
        excluded_models: vec!["*-deprecated".to_owned(), "internal-*".to_owned()],
        ..CatalogSourceConfig::default()
    });
    let xai = source(CatalogSourceConfig {
        id: "xai.primary".to_owned(),
        provider: "xai".to_owned(),
        priority: 10,
        aliases: vec![AliasConfig {
            name: "grok-4.5".to_owned(),
            alias: "flagship".to_owned(),
            fork: false,
            display_name: Some("Grok".to_owned()),
            force_mapping: true,
        }],
        ..CatalogSourceConfig::default()
    });
    let anthropic = source(CatalogSourceConfig {
        id: "anthropic.primary".to_owned(),
        provider: "anthropic".to_owned(),
        prefix: Some("anthropic".to_owned()),
        aliases: vec![AliasConfig {
            name: "claude-sonnet-4-5".to_owned(),
            alias: "latest".to_owned(),
            display_name: Some("Claude Latest".to_owned()),
            ..AliasConfig::default()
        }],
        ..CatalogSourceConfig::default()
    });

    let openai_input = CatalogInput::new(
        openai,
        pooler_model_catalog::DiscoveryResponse::new(vec![
            model("internal-eval", &[Capability::Text]),
            model("gpt-5.2-deprecated", &[Capability::Text]),
            model(
                "gpt-5.2",
                &[Capability::Text, Capability::Tools, Capability::Streaming],
            ),
        ])
        .with_revision("openai-etag-7"),
    );
    let xai_input = CatalogInput::new(
        xai,
        pooler_model_catalog::DiscoveryResponse::new(vec![model(
            "grok-4.5",
            &[Capability::Text, Capability::Tools],
        )])
        .with_revision("xai-r3"),
    );
    let anthropic_input = CatalogInput::new(
        anthropic,
        pooler_model_catalog::DiscoveryResponse::new(vec![model(
            "claude-sonnet-4-5",
            &[Capability::Text, Capability::Tools],
        )]),
    );

    let forward = merge_discoveries(
        9,
        1_700_000_000_123,
        vec![
            xai_input.clone(),
            anthropic_input.clone(),
            openai_input.clone(),
        ],
        limits(),
        &no_overrides(),
    )
    .expect("catalog merges");
    let reverse = merge_discoveries(
        9,
        1_700_000_000_123,
        vec![openai_input, anthropic_input, xai_input],
        limits(),
        &no_overrides(),
    )
    .expect("catalog merge is input-order independent");
    assert_eq!(forward, reverse);

    let model_ids = forward
        .models()
        .keys()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    assert_eq!(model_ids, vec!["anthropic/latest", "flagship", "gpt-5.2"]);
    let flagship = forward.get("flagship").expect("merged alias");
    assert_eq!(flagship.display_name(), Some("Pooler Flagship"));
    assert_eq!(flagship.targets().len(), 2);
    assert_eq!(flagship.targets()[0].provider().as_str(), "openai");
    assert_eq!(flagship.targets()[0].upstream_model().as_str(), "gpt-5.2");
    assert!(flagship.targets()[0].force_mapping());
    let origin = &flagship.targets()[0].provenance()[0];
    assert_eq!(origin.source().as_str(), "openai.primary");
    assert_eq!(origin.revision(), Some("openai-etag-7"));
    assert_eq!(origin.observed_at_unix_ms(), 1_700_000_000_123);
    assert_eq!(
        origin.exposure(),
        pooler_model_catalog::ExposureKind::ForkedAlias
    );
    assert!(forward.get("gpt-5.2").is_some(), "fork retains native ID");
    assert!(forward.get("grok-4.5").is_none(), "rename hides native ID");
    assert!(forward.get("anthropic/latest").is_some());

    let openai_state = forward
        .sources()
        .iter()
        .find(|(source, _)| source.as_str() == "openai.primary")
        .map(|(_, state)| state)
        .expect("source state");
    assert_eq!(openai_state.discovered_models(), 3);
    assert_eq!(openai_state.excluded_models(), 2);
    assert_eq!(openai_state.published_exposures(), 2);
}

#[test]
fn an_operator_override_outranks_every_discovered_fact() {
    let discovered = source(CatalogSourceConfig {
        id: "openai.primary".to_owned(),
        provider: "openai".to_owned(),
        ..CatalogSourceConfig::default()
    });
    let input = CatalogInput::new(
        discovered,
        DiscoveryResponse::new(vec![
            model("keep-me", &[Capability::Text]),
            model("hide-me", &[Capability::Text]),
            model("reshape-me", &[Capability::Text]),
        ]),
    );

    let snapshot = merge_discoveries(
        1,
        1,
        vec![input],
        limits(),
        &overrides(vec![
            ModelOverrideConfig {
                model: "hide-me".to_owned(),
                disabled: true,
                ..ModelOverrideConfig::default()
            },
            ModelOverrideConfig {
                model: "reshape-me".to_owned(),
                display_name: Some("Reshaped".to_owned()),
                capabilities: Some(
                    [Capability::Text, Capability::Reasoning]
                        .into_iter()
                        .collect(),
                ),
                profile: Some(ModelProfile {
                    reasoning: FactSupport::Supported,
                    output_limit: Some(8_192),
                    ..ModelProfile::DEFAULT
                }),
                dialect: Some(ModelDialect::new().rejecting_temperature()),
                ..ModelOverrideConfig::default()
            },
            ModelOverrideConfig {
                model: "never-served".to_owned(),
                disabled: true,
                ..ModelOverrideConfig::default()
            },
        ]),
    )
    .expect("merge succeeds");

    // A disabled model remains visible to management so it can be enabled again.
    assert!(snapshot.get("hide-me").is_some());
    assert_eq!(
        snapshot.overrides().disabled_models(),
        &[ModelId::new("hide-me").expect("model id")]
    );

    // An untouched model is unaffected by its neighbours being overridden.
    let kept = snapshot
        .get("keep-me")
        .expect("unoverridden model survives");
    assert_eq!(
        kept.targets()[0].capabilities(),
        [Capability::Text].into_iter().collect::<CapabilitySet>()
    );

    // The operator adds a capability no provider reported, which the merge's
    // intersection rule could never have produced on its own.
    let reshaped = snapshot.get("reshape-me").expect("overridden model");
    assert_eq!(reshaped.display_name(), Some("Reshaped"));
    assert_eq!(
        reshaped.targets()[0].capabilities(),
        [Capability::Text, Capability::Reasoning]
            .into_iter()
            .collect::<CapabilitySet>()
    );
    assert_eq!(
        reshaped.targets()[0].dialect(),
        ModelDialect::new().rejecting_temperature()
    );
    assert_eq!(reshaped.targets()[0].profile().output_limit, Some(8_192));
    assert_eq!(
        reshaped.targets()[0].profile().reasoning,
        FactSupport::Supported
    );
    assert_eq!(
        reshaped.targets()[0].profile().dialect,
        ModelDialect::new().rejecting_temperature(),
        "the narrow dialect override wins over the profile dialect"
    );

    // An override for a model no provider serves is reported rather than
    // failing the refresh, since a model can vanish upstream at any time.
    assert_eq!(
        snapshot.overrides().unmatched_models(),
        &[ModelId::new("never-served").expect("model id")]
    );
}

#[test]
fn merged_target_intersects_capabilities_but_adopts_one_source_dialect() {
    let strict = source(CatalogSourceConfig {
        id: "openai.strict".to_owned(),
        provider: "openai".to_owned(),
        priority: 20,
        ..CatalogSourceConfig::default()
    });
    let permissive = source(CatalogSourceConfig {
        id: "openai.permissive".to_owned(),
        provider: "openai".to_owned(),
        priority: 10,
        ..CatalogSourceConfig::default()
    });
    let strict = CatalogInput::new(
        strict,
        DiscoveryResponse::new(vec![model("gpt-x", &[Capability::Text, Capability::Tools])
            .with_dialect(ModelDialect::new().rejecting_temperature())]),
    );
    let permissive = CatalogInput::new(
        permissive,
        DiscoveryResponse::new(vec![model("gpt-x", &[Capability::Text])]),
    );

    for inputs in [
        vec![strict.clone(), permissive.clone()],
        vec![permissive, strict],
    ] {
        let snapshot =
            merge_discoveries(1, 1, inputs, limits(), &no_overrides()).expect("merge succeeds");
        let merged = snapshot.get("gpt-x").expect("merged model");
        let target = &merged.targets()[0];

        // Capabilities intersect: only the higher-priority source reported tools.
        assert_eq!(
            target.capabilities(),
            [Capability::Text].into_iter().collect::<CapabilitySet>()
        );
        // The dialect is adopted whole from the highest-priority source rather
        // than combined field by field, so it still describes a request shape
        // that some provider actually implements.
        assert_eq!(
            target.dialect(),
            ModelDialect::new().rejecting_temperature()
        );
    }
}

#[test]
fn same_provider_public_mapping_conflict_is_deterministic() {
    let higher = source(CatalogSourceConfig {
        id: "openai.higher".to_owned(),
        provider: "openai".to_owned(),
        priority: 20,
        aliases: vec![AliasConfig {
            name: "gpt-new".to_owned(),
            alias: "latest".to_owned(),
            ..AliasConfig::default()
        }],
        ..CatalogSourceConfig::default()
    });
    let lower = source(CatalogSourceConfig {
        id: "openai.lower".to_owned(),
        provider: "openai".to_owned(),
        priority: 10,
        aliases: vec![AliasConfig {
            name: "gpt-old".to_owned(),
            alias: "latest".to_owned(),
            ..AliasConfig::default()
        }],
        ..CatalogSourceConfig::default()
    });
    let higher = CatalogInput::new(
        higher,
        pooler_model_catalog::DiscoveryResponse::new(vec![model("gpt-new", &[Capability::Text])]),
    );
    let lower = CatalogInput::new(
        lower,
        pooler_model_catalog::DiscoveryResponse::new(vec![model("gpt-old", &[Capability::Text])]),
    );

    let first = merge_discoveries(
        1,
        1,
        vec![lower.clone(), higher.clone()],
        limits(),
        &no_overrides(),
    )
    .expect_err("ambiguous provider mapping is rejected");
    let second = merge_discoveries(1, 1, vec![higher, lower], limits(), &no_overrides())
        .expect_err("input order cannot change the conflict");
    assert_eq!(first, second);
    match first {
        CatalogError::ConflictingPublicMapping { conflict } => {
            assert_eq!(conflict.first_source().as_str(), "openai.higher");
            assert_eq!(conflict.first_upstream().as_str(), "gpt-new");
            assert_eq!(conflict.second_source().as_str(), "openai.lower");
            assert_eq!(conflict.second_upstream().as_str(), "gpt-old");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn configuration_is_strict_and_refresh_limits_cannot_be_disabled() {
    let unknown = r#"
sources:
  - id: openai.primary
    provider: openai
    aliases: []
    excluded_models: []
    surprise: true
"#;
    let error = serde_yml::from_str::<CatalogConfig>(unknown)
        .expect_err("unknown source field must fail")
        .to_string();
    assert!(error.contains("unknown field `surprise`"));

    let invalid = CatalogConfig {
        refresh: RefreshConfig {
            max_concurrency: 0,
            ..RefreshConfig::default()
        },
        ..CatalogConfig::default()
    }
    .compile()
    .expect_err("zero concurrency must fail");
    assert!(matches!(
        invalid,
        CatalogError::InvalidRefreshLimit {
            field: "max_concurrency",
            actual: 0,
            ..
        }
    ));
}

#[test]
fn duplicate_source_ids_are_rejected_even_when_priorities_differ() {
    let error = CatalogConfig {
        sources: vec![
            CatalogSourceConfig {
                id: "provider.same".to_owned(),
                provider: "provider".to_owned(),
                priority: 100,
                ..CatalogSourceConfig::default()
            },
            CatalogSourceConfig {
                id: "other.middle".to_owned(),
                provider: "other".to_owned(),
                priority: 50,
                ..CatalogSourceConfig::default()
            },
            CatalogSourceConfig {
                id: "provider.same".to_owned(),
                provider: "provider".to_owned(),
                priority: 0,
                ..CatalogSourceConfig::default()
            },
        ],
        ..CatalogConfig::default()
    }
    .compile()
    .expect_err("source identity must be unique independent of priority sorting");
    assert!(matches!(error, CatalogError::DuplicateSource { .. }));
}

#[test]
fn response_model_count_is_bounded_before_publication() {
    let source = source(CatalogSourceConfig {
        id: "provider.primary".to_owned(),
        provider: "provider".to_owned(),
        ..CatalogSourceConfig::default()
    });
    let limits = RefreshConfig {
        max_models_per_source: 1,
        max_total_models: 1,
        ..RefreshConfig::default()
    }
    .compile()
    .expect("small positive bounds compile");
    let error = merge_discoveries(
        1,
        1,
        vec![CatalogInput::new(
            source,
            pooler_model_catalog::DiscoveryResponse::new(vec![
                model("one", &[Capability::Text]),
                model("two", &[Capability::Text]),
            ]),
        )],
        limits,
        &no_overrides(),
    )
    .expect_err("oversized response must fail");
    assert!(matches!(
        error,
        CatalogError::SourceModelLimitExceeded {
            actual: 2,
            maximum: 1,
            ..
        }
    ));
}

#[test]
fn inclusion_policy_runs_before_exclusions_and_is_auditable() {
    let source = source(CatalogSourceConfig {
        id: "provider.primary".to_owned(),
        provider: "provider".to_owned(),
        included_models: vec!["public-*".to_owned()],
        excluded_models: vec!["*-preview".to_owned()],
        ..CatalogSourceConfig::default()
    });
    let snapshot = merge_discoveries(
        1,
        10,
        vec![CatalogInput::new(
            source,
            pooler_model_catalog::DiscoveryResponse::new(vec![
                model("internal-one", &[Capability::Text]),
                model("public-preview", &[Capability::Text]),
                model("public-stable", &[Capability::Text]),
            ]),
        )],
        limits(),
        &no_overrides(),
    )
    .expect("catalog merges");

    assert_eq!(
        snapshot
            .models()
            .keys()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        vec!["public-stable"]
    );
    let state = snapshot.sources().values().next().expect("source state");
    assert_eq!(state.discovered_models(), 3);
    assert_eq!(state.not_included_models(), 1);
    assert_eq!(state.excluded_models(), 1);
}

#[test]
fn merge_work_is_rejected_before_rule_evaluation() {
    let source = source(CatalogSourceConfig {
        id: "provider.primary".to_owned(),
        provider: "provider".to_owned(),
        included_models: vec!["*".to_owned(), "model-*".to_owned()],
        ..CatalogSourceConfig::default()
    });
    let limits = RefreshConfig {
        max_merge_operations: 2,
        ..RefreshConfig::default()
    }
    .compile()
    .expect("small positive work budget compiles");
    let error = merge_discoveries(
        1,
        1,
        vec![CatalogInput::new(
            source,
            pooler_model_catalog::DiscoveryResponse::new(vec![model(
                "model-one",
                &[Capability::Text],
            )]),
        )],
        limits,
        &no_overrides(),
    )
    .expect_err("rule work over budget must fail before publication");
    assert!(matches!(
        error,
        CatalogError::MergeWorkLimitExceeded {
            actual: 3,
            maximum: 2
        }
    ));
}
