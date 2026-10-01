# Plan Semantic Tuples — 15 Operators (Issue #46 Cycle A v3)

Source: `logs/full-teardown-completion/phase-d-evidence/cycle-a-v3/plans/` (non-final files only)

## Summary

- **Operators**: 15
- **Total resources**: 343
- **Total explicit_deletes**: 10
- **Action breakdown**: DELETE=112, EXPECT=77, KEEP=136, REVIEW=18

**Limitation**: ExecutionPlan v2 does not store `version` (apiVersion group version). The `version` field is `null` in all tuples.

## Per-Operator Breakdown

| # | Operator | Resources | Explicit | DELETE | EXPECT | KEEP | REVIEW | Phases |
|---|----------|-----------|----------|--------|--------|------|--------|--------|
| 1 | rhods-operator | 134 | 5 | 42 | 73 | 18 | 1 | 1..8 |
| 2 | rhbk-operator | 10 | 1 | 6 | 0 | 4 | 0 | 1..8 |
| 3 | leader-worker-set | 7 | 0 | 3 | 0 | 3 | 1 | 1..7 |
| 4 | job-set | 8 | 0 | 4 | 0 | 3 | 1 | 1..7 |
| 5 | kueue-operator | 7 | 0 | 3 | 0 | 3 | 1 | 1..7 |
| 6 | servicemeshoperator3 | 26 | 0 | 3 | 0 | 22 | 1 | 1..7 |
| 7 | nfd | 16 | 0 | 5 | 0 | 8 | 3 | 1..7 |
| 8 | gpu-operator-certified | 12 | 0 | 4 | 0 | 7 | 1 | 1..7 |
| 9 | cert-manager-operator | 21 | 0 | 7 | 0 | 12 | 2 | 1..7 |
| 10 | rhcl-operator | 25 | 4 | 8 | 0 | 16 | 1 | 1..8 |
| 11 | authorino-operator | 13 | 0 | 7 | 0 | 5 | 1 | 1..7 |
| 12 | dns-operator | 9 | 0 | 2 | 0 | 5 | 2 | 1..7 |
| 13 | limitador-operator | 9 | 0 | 3 | 0 | 4 | 2 | 1..7 |
| 14 | cluster-observability-operator | 36 | 0 | 12 | 4 | 20 | 0 | 1..7 |
| 15 | opentelemetry-product | 10 | 0 | 3 | 0 | 6 | 1 | 1..7 |

## Explicit Deletes (10 targets)

| Operator | Kind | Namespace | Name | UID | Reason |
|----------|------|-----------|------|-----|--------|
| rhods-operator | ConfigMap | openshift-ingress | maas-gateway-options | 0a4f5c32-948... | config explicit |
| rhods-operator | Deployment | redhat-ods-applications | maas-postgres | c71dcc06-4e7... | config explicit |
| rhods-operator | Deployment | rhoai-model-registries | model-catalog | 6b1da06e-1b9... | config explicit |
| rhods-operator | Gateway | openshift-ingress | maas-default-gateway | 9739a44f-e31... | config explicit |
| rhods-operator | StatefulSet | redhat-ods-applications | ogx-postgres | f9060f89-dc0... | config explicit |
| rhbk-operator | StatefulSet | keycloak | postgres | a1556a15-057... | config explicit |
| rhcl-operator | ConfigMap | openshift-rhcl | kuadrant-console-nginx-conf | b3b875ff-7b9... | config explicit |
| rhcl-operator | ConsolePlugin | None | kuadrant-console-plugin | b33501b2-f7b... | config explicit |
| rhcl-operator | Deployment | openshift-rhcl | kuadrant-console-plugin | f48c2899-a52... | config explicit |
| rhcl-operator | Service | openshift-rhcl | kuadrant-console-plugin | 66f7d874-e72... | config explicit |

## Resource Details

### rhods-operator (134 resources)

| Phase | Phase Name | Action | Kind | Namespace | Name | UID | Explicit |
|-------|-----------|--------|------|-----------|------|-----|----------|
| 1 | Freeze OLM | DELETE | Subscription | redhat-ods-operator | rhods-operator | d8175cac-985... |  |
| 1 | Freeze OLM | KEEP | ClusterServiceVersion | redhat-ods-operator | rhods-operator.3.5.1 | f94a3ecb-e27... |  |
| 2 | Trigger operand cleanup | DELETE | DataScienceCluster | — | default-dsc | fa97159f-134... |  |
| 2 | Trigger operand cleanup | DELETE | DSCInitialization | — | default-dsci | 03682b4b-5ea... |  |
| 2 | Trigger operand cleanup | DELETE | Config | — | default | b74610ef-6f9... |  |
| 2 | Trigger operand cleanup | EXPECT | DataSciencePipelines | — | default-datasciencepipelines | 23c16214-6fc... |  |
| 2 | Trigger operand cleanup | EXPECT | ModelRegistry | — | default-modelregistry | 5982aa30-a9b... |  |
| 2 | Trigger operand cleanup | EXPECT | Ray | — | default-ray | c30162ef-c04... |  |
| 2 | Trigger operand cleanup | EXPECT | Trainer | — | default-trainer | a74381d7-9b7... |  |
| 2 | Trigger operand cleanup | EXPECT | TrainingOperator | — | default-trainingoperator | 6497d729-0ff... |  |
| 2 | Trigger operand cleanup | EXPECT | TrustyAI | — | default-trustyai | b1eb2447-b46... |  |
| 2 | Trigger operand cleanup | EXPECT | HardwareProfile | redhat-ods-applications | default-profile | 6e1a5f0f-74c... |  |
| 2 | Trigger operand cleanup | EXPECT | GatewayConfig | — | default-gateway | 1de66233-51a... |  |
| 2 | Trigger operand cleanup | EXPECT | Monitoring | — | default-monitoring | 25a9894a-5a3... |  |
| 2 | Trigger operand cleanup | EXPECT | AIGateway | — | default-aigateway | 31943c1a-38f... |  |
| 2 | Trigger operand cleanup | EXPECT | Dashboard | — | default-dashboard | 17a2f650-70e... |  |
| 2 | Trigger operand cleanup | EXPECT | FeastOperator | — | default-feastoperator | 3dc9efce-4f4... |  |
| 2 | Trigger operand cleanup | EXPECT | Kserve | — | default-kserve | 59addb4c-45a... |  |
| 2 | Trigger operand cleanup | EXPECT | MLflowOperator | — | default-mlflowoperator | d455d7e5-895... |  |
| 2 | Trigger operand cleanup | EXPECT | OGX | — | default-ogx | 01794ead-8bf... |  |
| 2 | Trigger operand cleanup | EXPECT | Workbenches | — | default-workbenches | 6aac395e-4ad... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhQuickStart | redhat-ods-applications | create-aikit-notebook | 15c35155-7b8... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhQuickStart | redhat-ods-applications | create-jupyter-notebook | 55354a2a-38a... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhQuickStart | redhat-ods-applications | deploy-python-model | ae0ac1f0-114... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhQuickStart | redhat-ods-applications | openvino-inference-notebook | 51f29ccb-08e... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhQuickStart | redhat-ods-applications | pachyderm-beginner-tutorial-notebook | 154c9a6d-00d... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhQuickStart | redhat-ods-applications | using-starburst-enterprise | 04f28202-acd... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhApplication | redhat-ods-applications | agentic-starter-kits | 7fe3e207-843... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhApplication | redhat-ods-applications | aikit | ec4103de-854... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhApplication | redhat-ods-applications | elastic | c61e201b-efd... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhApplication | redhat-ods-applications | jupyter | 0d13914e-e7a... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhApplication | redhat-ods-applications | mlflow | e42a26e6-c92... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhApplication | redhat-ods-applications | nvidia-nim | b864eb9d-865... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhApplication | redhat-ods-applications | openvino | 59a13742-c80... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhApplication | redhat-ods-applications | pachyderm | 6cc6d8b9-db9... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhApplication | redhat-ods-applications | pgvector | 734d58b0-2b9... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhApplication | redhat-ods-applications | rhoai | 2b680ab3-730... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhApplication | redhat-ods-applications | starburstenterprise | 242ce688-418... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhApplication | redhat-ods-applications | watson-x-ai | 5b12c52b-15c... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhDocument | redhat-ods-applications | agentic-starter-kits-a2a-tutorial | 420d44e9-f25... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhDocument | redhat-ods-applications | agentic-starter-kits-autogen-tutorial | 51edeedd-ad7... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhDocument | redhat-ods-applications | agentic-starter-kits-crewai-tutorial | 72f475a5-6bf... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhDocument | redhat-ods-applications | agentic-starter-kits-google-adk-tutorial | b393fc7a-7a0... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhDocument | redhat-ods-applications | agentic-starter-kits-hitl-tutorial | 90cf0470-28f... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhDocument | redhat-ods-applications | agentic-starter-kits-langflow-tutorial | de9e4b27-eb5... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhDocument | redhat-ods-applications | agentic-starter-kits-langgraph-tutorial | 87da3ddb-2e3... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhDocument | redhat-ods-applications | agentic-starter-kits-llamaindex-tutorial | e2abf6a6-429... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhDocument | redhat-ods-applications | agentic-starter-kits-memory-tutorial | 4cb6c9ef-417... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhDocument | redhat-ods-applications | agentic-starter-kits-rag-tutorial | 88aef28f-216... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhDocument | redhat-ods-applications | agentic-starter-kits-vanilla-python-tutorial | c12daca6-ea8... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhDocument | redhat-ods-applications | jupyter-install-python-packages | d5a1ba83-b9f... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhDocument | redhat-ods-applications | jupyter-update-server-settings | 99091682-2c2... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhDocument | redhat-ods-applications | jupyter-use-s3-bucket-data | 528c3dd3-657... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhDocument | redhat-ods-applications | jupyter-view-installed-packages | 96ccae1f-5a6... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhDocument | redhat-ods-applications | openvino-ovms-serving | 837f4890-20c... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhDocument | redhat-ods-applications | pachyderm-beginner-tutorial | 08550d4b-ac3... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhDocument | redhat-ods-applications | pachyderm-house-pricing-tutorial | bb74705a-750... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhDocument | redhat-ods-applications | rhoai-documentation | 8bdef5fe-7f6... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhDocument | redhat-ods-applications | rhoai-tutorial-fraud | e8c8d67f-d44... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhDocument | redhat-ods-applications | starburst-enterprise-requirements | 38dc25d0-df1... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhDocument | redhat-ods-applications | starburst-openshift-deployment | e09a9865-a28... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhDocument | redhat-ods-applications | starburst-openshift-overview | 4cd08bbf-18c... |  |
| 2 | Trigger operand cleanup | EXPECT | OdhDocument | redhat-ods-applications | watson-x-use-case | 25b9ca7b-3fc... |  |
| 2 | Trigger operand cleanup | EXPECT | AITenant | ai-tenants | models-as-a-service | 8b1ad576-fe8... |  |
| 2 | Trigger operand cleanup | EXPECT | MaasTenantConfig | models-as-a-service | default-tenant | e0cb6e9b-2bf... |  |
| 2 | Trigger operand cleanup | EXPECT | ClusterStorageContainer | — | default | fa8e1368-cc5... |  |
| 2 | Trigger operand cleanup | EXPECT | ClusterTrainingRuntime | — | torch-distributed | 2a1eac6e-af1... |  |
| 2 | Trigger operand cleanup | EXPECT | ClusterTrainingRuntime | — | torch-distributed-cpu | 47c75876-657... |  |
| 2 | Trigger operand cleanup | EXPECT | ClusterTrainingRuntime | — | torch-distributed-cpu-torch211-py312 | 182f5657-8d5... |  |
| 2 | Trigger operand cleanup | EXPECT | ClusterTrainingRuntime | — | torch-distributed-cuda130-torch211-py312 | 759e1a8e-937... |  |
| 2 | Trigger operand cleanup | EXPECT | ClusterTrainingRuntime | — | torch-distributed-rocm | fcd689ef-aba... |  |
| 2 | Trigger operand cleanup | EXPECT | ClusterTrainingRuntime | — | torch-distributed-rocm714-torch211-py312 | 63b58f56-b0d... |  |
| 2 | Trigger operand cleanup | EXPECT | ClusterTrainingRuntime | — | training-hub | 98fbb91e-d51... |  |
| 2 | Trigger operand cleanup | EXPECT | ClusterTrainingRuntime | — | training-hub-cpu | 2d9c47ad-1f5... |  |
| 2 | Trigger operand cleanup | EXPECT | ClusterTrainingRuntime | — | training-hub-rocm | 8affb17f-882... |  |
| 2 | Trigger operand cleanup | EXPECT | ClusterTrainingRuntime | — | training-hub-th09-cpu-torch211-py312 | 96f36fee-6c4... |  |
| 2 | Trigger operand cleanup | EXPECT | ClusterTrainingRuntime | — | training-hub-th09-cuda130-torch211-py312 | 35a7d6fc-284... |  |
| 2 | Trigger operand cleanup | EXPECT | ClusterTrainingRuntime | — | training-hub-th09-rocm714-torch211-py312 | 43f49a9e-0e6... |  |
| 2 | Trigger operand cleanup | DELETE | HardwareProfile | redhat-ods-applications | nvidia-gpu-1 | 5866ca65-402... |  |
| 2 | Trigger operand cleanup | DELETE | Auth | — | auth | c7edfed8-9a5... |  |
| 2 | Trigger operand cleanup | DELETE | MLflow | — | mlflow | 52805766-f6f... |  |
| 3 | Remaining cleanup | DELETE | MaaSAuthPolicy | models-as-a-service | admin-auth-policy | 44abc60f-40c... |  |
| 3 | Remaining cleanup | DELETE | MaaSAuthPolicy | models-as-a-service | maas-qwen3-06b-users-auth-policy | bdecb970-4a0... |  |
| 3 | Remaining cleanup | DELETE | MaaSSubscription | models-as-a-service | maas-admins-subscription | ba4200a7-62c... |  |
| 3 | Remaining cleanup | DELETE | MaaSSubscription | models-as-a-service | maas-qwen3-06b-users-subscription | ccd4fba5-8cd... |  |
| 3 | Remaining cleanup | DELETE | MaasTenantConfig | redhat-ods-applications | default-tenant | 2debb138-d89... |  |
| 3 | Remaining cleanup | DELETE | OGXServer | redhat-ods-applications | ogx-server | 08b20ec3-427... |  |
| 3 | Remaining cleanup | DELETE | OdhDashboardConfig | redhat-ods-applications | odh-dashboard-config | ba250171-ea9... |  |
| 3 | Remaining cleanup | DELETE | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-decode-template | d042060c-92e... |  |
| 3 | Remaining cleanup | DELETE | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-decode-worker-data-parallel | 5a182f2e-0b5... |  |
| 3 | Remaining cleanup | DELETE | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-multi-node-pd-template-nvidia-cuda | 2ac906a5-0e5... |  |
| 3 | Remaining cleanup | DELETE | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-multi-node-template-nvidia-cuda | 781be3bd-c5e... |  |
| 3 | Remaining cleanup | DELETE | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-prefill-template | 740d97dd-788... |  |
| 3 | Remaining cleanup | DELETE | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-prefill-worker-data-parallel | 0c793f1f-e46... |  |
| 3 | Remaining cleanup | DELETE | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-router-route | e99a4127-c86... |  |
| 3 | Remaining cleanup | DELETE | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-scheduler | 33229ed7-730... |  |
| 3 | Remaining cleanup | DELETE | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-scheduler-latency-predictor | a611b44b-18d... |  |
| 3 | Remaining cleanup | DELETE | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-single-node-pd-template-nvidia-cuda | 9ec1fed0-0dc... |  |
| 3 | Remaining cleanup | DELETE | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-single-node-template-nvidia-cuda | ac811a02-1b0... |  |
| 3 | Remaining cleanup | DELETE | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-template | ca9ddf72-279... |  |
| 3 | Remaining cleanup | DELETE | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-template-amd-rocm | 9f1c86a4-f27... |  |
| 3 | Remaining cleanup | DELETE | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-template-ibm-spyre-ppc64le | ca3afccd-776... |  |
| 3 | Remaining cleanup | DELETE | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-template-ibm-spyre-s390x | b3588e0f-e3d... |  |
| 3 | Remaining cleanup | DELETE | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-template-ibm-spyre-x86 | 416a9fd3-9d5... |  |
| 3 | Remaining cleanup | DELETE | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-template-intel-gaudi | 918cfc5b-102... |  |
| 3 | Remaining cleanup | DELETE | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-tokenizer | 1651f5c0-b94... |  |
| 3 | Remaining cleanup | DELETE | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-tracing | a4928e94-27a... |  |
| 3 | Remaining cleanup | DELETE | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-worker-data-parallel | 76b69d5c-3fa... |  |
| 3 | Remaining cleanup | DELETE | NemoGuardrails | redhat-ods-applications | nemo-guardrails | bfe08c0d-095... |  |
| 4 | Remove Operator controllers | DELETE | ClusterServiceVersion | redhat-ods-operator | rhods-operator.3.5.1 | f94a3ecb-e27... |  |
| 5 | Namespace cleanup | DELETE | OperatorGroup | redhat-ods-operator | rhods-operator | ba0a0318-d71... |  |
| 5 | Namespace cleanup | REVIEW | Lease | redhat-ods-operator | 07ed84f7.opendatahub.io | 3588a54d-d3c... |  |
| 6 | Explicit cleanup | DELETE | Deployment | redhat-ods-applications | maas-postgres | c71dcc06-4e7... | **yes** |
| 6 | Explicit cleanup | DELETE | StatefulSet | redhat-ods-applications | ogx-postgres | f9060f89-dc0... | **yes** |
| 6 | Explicit cleanup | DELETE | Deployment | rhoai-model-registries | model-catalog | 6b1da06e-1b9... | **yes** |
| 6 | Explicit cleanup | DELETE | Gateway | openshift-ingress | maas-default-gateway | 9739a44f-e31... | **yes** |
| 6 | Explicit cleanup | DELETE | ConfigMap | openshift-ingress | maas-gateway-options | 0a4f5c32-948... | **yes** |
| 7 | APIs | KEEP | CustomResourceDefinition | — | auths.services.platform.opendatahub.io | — |  |
| 7 | APIs | KEEP | CustomResourceDefinition | — | datascienceclusters.datasciencecluster.opendatahub.io | — |  |
| 7 | APIs | KEEP | CustomResourceDefinition | — | datasciencepipelines.components.platform.opendatahub.io | — |  |
| 7 | APIs | KEEP | CustomResourceDefinition | — | dscinitializations.dscinitialization.opendatahub.io | — |  |
| 7 | APIs | KEEP | CustomResourceDefinition | — | featuretrackers.features.opendatahub.io | — |  |
| 7 | APIs | KEEP | CustomResourceDefinition | — | gatewayconfigs.services.platform.opendatahub.io | — |  |
| 7 | APIs | KEEP | CustomResourceDefinition | — | hardwareprofiles.infrastructure.opendatahub.io | — |  |
| 7 | APIs | KEEP | CustomResourceDefinition | — | kueues.components.platform.opendatahub.io | — |  |
| 7 | APIs | KEEP | CustomResourceDefinition | — | modelregistries.components.platform.opendatahub.io | — |  |
| 7 | APIs | KEEP | CustomResourceDefinition | — | monitorings.services.platform.opendatahub.io | — |  |
| 7 | APIs | KEEP | CustomResourceDefinition | — | platforms.config.opendatahub.io | — |  |
| 7 | APIs | KEEP | CustomResourceDefinition | — | rays.components.platform.opendatahub.io | — |  |
| 7 | APIs | KEEP | CustomResourceDefinition | — | sparkoperators.components.platform.opendatahub.io | — |  |
| 7 | APIs | KEEP | CustomResourceDefinition | — | trainers.components.platform.opendatahub.io | — |  |
| 7 | APIs | KEEP | CustomResourceDefinition | — | trainingoperators.components.platform.opendatahub.io | — |  |
| 7 | APIs | KEEP | CustomResourceDefinition | — | trustyais.components.platform.opendatahub.io | — |  |
| 8 | Namespaces | KEEP | Namespace | — | redhat-ods-operator | — |  |

### rhbk-operator (10 resources)

| Phase | Phase Name | Action | Kind | Namespace | Name | UID | Explicit |
|-------|-----------|--------|------|-----------|------|-----|----------|
| 1 | Freeze OLM | DELETE | Subscription | keycloak | rhbk-operator | 909796b7-31e... |  |
| 1 | Freeze OLM | KEEP | ClusterServiceVersion | keycloak | rhbk-operator.v26.6.7-opr.1 | 9774dbc8-002... |  |
| 2 | Trigger operand cleanup | DELETE | Keycloak | keycloak | keycloak | 44b43bc9-c1f... |  |
| 2 | Trigger operand cleanup | DELETE | KeycloakRealmImport | keycloak | maas-realm | b06c8f03-6c6... |  |
| 4 | Remove Operator controllers | DELETE | ClusterServiceVersion | keycloak | rhbk-operator.v26.6.7-opr.1 | 9774dbc8-002... |  |
| 5 | Namespace cleanup | DELETE | OperatorGroup | keycloak | rhbk-operator | 422c03e0-75e... |  |
| 6 | Explicit cleanup | DELETE | StatefulSet | keycloak | postgres | a1556a15-057... | **yes** |
| 7 | APIs | KEEP | CustomResourceDefinition | — | keycloakrealmimports.k8s.keycloak.org | — |  |
| 7 | APIs | KEEP | CustomResourceDefinition | — | keycloaks.k8s.keycloak.org | — |  |
| 8 | Namespaces | KEEP | Namespace | — | keycloak | — |  |

### leader-worker-set (7 resources)

| Phase | Phase Name | Action | Kind | Namespace | Name | UID | Explicit |
|-------|-----------|--------|------|-----------|------|-----|----------|
| 1 | Freeze OLM | DELETE | Subscription | openshift-leaderworkerset | leader-worker-set | db8356ed-283... |  |
| 1 | Freeze OLM | KEEP | ClusterServiceVersion | openshift-leaderworkerset | leader-worker-set.v1.0.1 | 5bfec5ce-af6... |  |
| 4 | Remove Operator controllers | DELETE | ClusterServiceVersion | openshift-leaderworkerset | leader-worker-set.v1.0.1 | 5bfec5ce-af6... |  |
| 5 | Namespace cleanup | DELETE | OperatorGroup | openshift-leaderworkerset | leader-worker-set | b3f4dc2b-6b1... |  |
| 5 | Namespace cleanup | REVIEW | Lease | openshift-leaderworkerset | openshift-lws-operator-lock | 0f89d0dd-fc5... |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | leaderworkersetoperators.operator.openshift.io | — |  |
| 7 | Namespaces | KEEP | Namespace | — | openshift-leaderworkerset | — |  |

### job-set (8 resources)

| Phase | Phase Name | Action | Kind | Namespace | Name | UID | Explicit |
|-------|-----------|--------|------|-----------|------|-----|----------|
| 1 | Freeze OLM | DELETE | Subscription | openshift-jobset | job-set | f4f21e7b-e48... |  |
| 1 | Freeze OLM | KEEP | ClusterServiceVersion | openshift-jobset | jobset-operator.v1.0.1 | 7bba7c4d-249... |  |
| 2 | Trigger operand cleanup | DELETE | JobSetOperator | — | cluster | 7fd7c2ba-c42... |  |
| 4 | Remove Operator controllers | DELETE | ClusterServiceVersion | openshift-jobset | jobset-operator.v1.0.1 | 7bba7c4d-249... |  |
| 5 | Namespace cleanup | DELETE | OperatorGroup | openshift-jobset | job-set | 93c85027-064... |  |
| 5 | Namespace cleanup | REVIEW | Lease | openshift-jobset | openshift-jobset-operator-lock | ff993506-48a... |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | jobsetoperators.operator.openshift.io | — |  |
| 7 | Namespaces | KEEP | Namespace | — | openshift-jobset | — |  |

### kueue-operator (7 resources)

| Phase | Phase Name | Action | Kind | Namespace | Name | UID | Explicit |
|-------|-----------|--------|------|-----------|------|-----|----------|
| 1 | Freeze OLM | DELETE | Subscription | openshift-kueue | kueue-operator | 007736c4-1a0... |  |
| 1 | Freeze OLM | KEEP | ClusterServiceVersion | openshift-kueue | kueue-operator.v1.4.2 | a8a00bc2-c0f... |  |
| 4 | Remove Operator controllers | DELETE | ClusterServiceVersion | openshift-kueue | kueue-operator.v1.4.2 | a8a00bc2-c0f... |  |
| 5 | Namespace cleanup | DELETE | OperatorGroup | openshift-kueue | kueue-operator | f99b742a-6e1... |  |
| 5 | Namespace cleanup | REVIEW | Lease | openshift-kueue | openshift-kueue-operator-lock | 594a9a45-d30... |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | kueues.kueue.openshift.io | — |  |
| 7 | Namespaces | KEEP | Namespace | — | openshift-kueue | — |  |

### servicemeshoperator3 (26 resources)

| Phase | Phase Name | Action | Kind | Namespace | Name | UID | Explicit |
|-------|-----------|--------|------|-----------|------|-----|----------|
| 1 | Freeze OLM | DELETE | Subscription | openshift-servicemesh | servicemeshoperator3 | 56739c23-add... |  |
| 1 | Freeze OLM | KEEP | ClusterServiceVersion | openshift-servicemesh | servicemeshoperator3.v3.4.2 | e0c375d6-ca8... |  |
| 4 | Remove Operator controllers | DELETE | ClusterServiceVersion | openshift-servicemesh | servicemeshoperator3.v3.4.2 | e0c375d6-ca8... |  |
| 5 | Namespace cleanup | DELETE | OperatorGroup | openshift-servicemesh | servicemeshoperator3 | be422652-562... |  |
| 5 | Namespace cleanup | REVIEW | Lease | openshift-servicemesh | sail-operator-lock | 8a707756-b51... |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | trafficextensions.extensions.istio.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | wasmplugins.extensions.istio.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | destinationrules.networking.istio.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | envoyfilters.networking.istio.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | gateways.networking.istio.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | proxyconfigs.networking.istio.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | serviceentries.networking.istio.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | sidecars.networking.istio.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | virtualservices.networking.istio.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | workloadentries.networking.istio.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | workloadgroups.networking.istio.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | ztunnels.sailoperator.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | authorizationpolicies.security.istio.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | peerauthentications.security.istio.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | requestauthentications.security.istio.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | telemetries.telemetry.istio.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | istiocnis.sailoperator.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | istiorevisions.sailoperator.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | istiorevisiontags.sailoperator.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | istios.sailoperator.io | — |  |
| 7 | Namespaces | KEEP | Namespace | — | openshift-servicemesh | — |  |

### nfd (16 resources)

| Phase | Phase Name | Action | Kind | Namespace | Name | UID | Explicit |
|-------|-----------|--------|------|-----------|------|-----|----------|
| 1 | Freeze OLM | DELETE | Subscription | openshift-nfd | nfd | 36ae55f7-067... |  |
| 1 | Freeze OLM | KEEP | ClusterServiceVersion | openshift-nfd | nfd.4.22.0-202609212027 | 0e3ae75f-b5e... |  |
| 2 | Trigger operand cleanup | DELETE | NodeFeature | openshift-nfd | ip-10-0-23-226.us-east-2.compute.internal | 3933aee4-bd6... |  |
| 2 | Trigger operand cleanup | DELETE | NodeFeatureDiscovery | openshift-nfd | nfd-instance | b4c5e454-ad7... |  |
| 4 | Remove Operator controllers | DELETE | ClusterServiceVersion | openshift-nfd | nfd.4.22.0-202609212027 | 0e3ae75f-b5e... |  |
| 5 | Namespace cleanup | DELETE | OperatorGroup | openshift-nfd | nfd | 5b10288e-2a0... |  |
| 5 | Namespace cleanup | REVIEW | Lease | openshift-nfd | 39f5e5c3.nodefeaturediscoveries.nfd.openshift.io | b2186edc-2ea... |  |
| 5 | Namespace cleanup | REVIEW | ConfigMap | openshift-nfd | nfd-manager-config | 11d745ba-6b3... |  |
| 5 | Namespace cleanup | REVIEW | ConfigMap | openshift-nfd | nfd-worker | a5634fc0-13e... |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | nodefeaturediscoveries.nfd.openshift.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | nodefeaturegroups.nfd.k8s-sigs.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | nodefeaturerules.nfd.k8s-sigs.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | nodefeaturerules.nfd.openshift.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | nodefeatures.nfd.k8s-sigs.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | nodefeatures.nfd.openshift.io | — |  |
| 7 | Namespaces | KEEP | Namespace | — | openshift-nfd | — |  |

### gpu-operator-certified (12 resources)

| Phase | Phase Name | Action | Kind | Namespace | Name | UID | Explicit |
|-------|-----------|--------|------|-----------|------|-----|----------|
| 1 | Freeze OLM | DELETE | Subscription | nvidia-gpu-operator | gpu-operator-certified | 3ca6157c-346... |  |
| 1 | Freeze OLM | KEEP | ClusterServiceVersion | nvidia-gpu-operator | gpu-operator-certified.v26.7.1 | 25ebbf41-25f... |  |
| 2 | Trigger operand cleanup | DELETE | ClusterPolicy | — | gpu-cluster-policy | 10b41aa5-469... |  |
| 4 | Remove Operator controllers | DELETE | ClusterServiceVersion | nvidia-gpu-operator | gpu-operator-certified.v26.7.1 | 25ebbf41-25f... |  |
| 5 | Namespace cleanup | DELETE | OperatorGroup | nvidia-gpu-operator | gpu-operator-certified | 79e7b2fe-62c... |  |
| 5 | Namespace cleanup | REVIEW | Lease | nvidia-gpu-operator | 53822513.nvidia.com | 2b20a221-8bd... |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | nvidiadrivers.nvidia.com | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | gpuclusters.nvidia.com | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | computedomains.resource.nvidia.com | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | computedomaincliques.resource.nvidia.com | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | clusterpolicies.nvidia.com | — |  |
| 7 | Namespaces | KEEP | Namespace | — | nvidia-gpu-operator | — |  |

### cert-manager-operator (21 resources)

| Phase | Phase Name | Action | Kind | Namespace | Name | UID | Explicit |
|-------|-----------|--------|------|-----------|------|-----|----------|
| 1 | Freeze OLM | DELETE | Subscription | cert-manager-operator | openshift-cert-manager-operator | e87aab2f-243... |  |
| 1 | Freeze OLM | KEEP | ClusterServiceVersion | cert-manager-operator | cert-manager-operator.v1.20.0 | d3d27294-fe2... |  |
| 2 | Trigger operand cleanup | DELETE | Certificate | openshift-jobset | jobset-metrics-cert | edd11033-f69... |  |
| 2 | Trigger operand cleanup | DELETE | Certificate | openshift-jobset | jobset-serving-cert | d6cdd988-16d... |  |
| 2 | Trigger operand cleanup | DELETE | Issuer | openshift-jobset | jobset-selfsigned-issuer | 21d9bf38-4b3... |  |
| 2 | Trigger operand cleanup | DELETE | CertManager | — | cluster | 99c43085-dc9... |  |
| 4 | Remove Operator controllers | DELETE | ClusterServiceVersion | cert-manager-operator | cert-manager-operator.v1.20.0 | d3d27294-fe2... |  |
| 5 | Namespace cleanup | DELETE | OperatorGroup | cert-manager-operator | openshift-cert-manager-operator | b4596545-b95... |  |
| 5 | Namespace cleanup | REVIEW | Lease | cert-manager-operator | cert-manager-operator-lock | 813ad357-ae2... |  |
| 5 | Namespace cleanup | REVIEW | ConfigMap | cert-manager-operator | cert-manager-operator-trusted-ca-bundle | 7e8eaf4f-1b1... |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | bundles.trust.cert-manager.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | certificaterequests.cert-manager.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | certificates.cert-manager.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | certmanagers.operator.openshift.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | challenges.acme.cert-manager.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | clusterissuers.cert-manager.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | issuers.cert-manager.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | istiocsrs.operator.openshift.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | orders.acme.cert-manager.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | trustmanagers.operator.openshift.io | — |  |
| 7 | Namespaces | KEEP | Namespace | — | cert-manager-operator | — |  |

### rhcl-operator (25 resources)

| Phase | Phase Name | Action | Kind | Namespace | Name | UID | Explicit |
|-------|-----------|--------|------|-----------|------|-----|----------|
| 1 | Freeze OLM | DELETE | Subscription | openshift-rhcl | rhcl-operator | 1ca03138-9fd... |  |
| 1 | Freeze OLM | KEEP | ClusterServiceVersion | openshift-rhcl | rhcl-operator.v1.4.3 | 6cbf6963-a18... |  |
| 2 | Trigger operand cleanup | DELETE | AuthPolicy | openshift-ingress | maas-gateway-auth | 3ae65a06-b6c... |  |
| 2 | Trigger operand cleanup | DELETE | Kuadrant | openshift-rhcl | kuadrant | c9061526-c65... |  |
| 4 | Remove Operator controllers | DELETE | ClusterServiceVersion | openshift-rhcl | rhcl-operator.v1.4.3 | 6cbf6963-a18... |  |
| 5 | Namespace cleanup | KEEP | OperatorGroup | openshift-rhcl | rhcl-operator | 3746fb8a-203... |  |
| 5 | Namespace cleanup | REVIEW | Lease | openshift-rhcl | f139389e.kuadrant.io | 36322248-b59... |  |
| 6 | Explicit cleanup | DELETE | ConsolePlugin | — | kuadrant-console-plugin | b33501b2-f7b... | **yes** |
| 6 | Explicit cleanup | DELETE | Deployment | openshift-rhcl | kuadrant-console-plugin | f48c2899-a52... | **yes** |
| 6 | Explicit cleanup | DELETE | Service | openshift-rhcl | kuadrant-console-plugin | 66f7d874-e72... | **yes** |
| 6 | Explicit cleanup | DELETE | ConfigMap | openshift-rhcl | kuadrant-console-nginx-conf | b3b875ff-7b9... | **yes** |
| 7 | APIs | KEEP | CustomResourceDefinition | — | apikeyapprovals.devportal.kuadrant.io | — |  |
| 7 | APIs | KEEP | CustomResourceDefinition | — | apikeyrequests.devportal.kuadrant.io | — |  |
| 7 | APIs | KEEP | CustomResourceDefinition | — | apikeys.devportal.kuadrant.io | — |  |
| 7 | APIs | KEEP | CustomResourceDefinition | — | apiproducts.devportal.kuadrant.io | — |  |
| 7 | APIs | KEEP | CustomResourceDefinition | — | authpolicies.kuadrant.io | — |  |
| 7 | APIs | KEEP | CustomResourceDefinition | — | dnspolicies.kuadrant.io | — |  |
| 7 | APIs | KEEP | CustomResourceDefinition | — | kuadrants.kuadrant.io | — |  |
| 7 | APIs | KEEP | CustomResourceDefinition | — | oidcpolicies.extensions.kuadrant.io | — |  |
| 7 | APIs | KEEP | CustomResourceDefinition | — | planpolicies.extensions.kuadrant.io | — |  |
| 7 | APIs | KEEP | CustomResourceDefinition | — | ratelimitpolicies.kuadrant.io | — |  |
| 7 | APIs | KEEP | CustomResourceDefinition | — | telemetrypolicies.extensions.kuadrant.io | — |  |
| 7 | APIs | KEEP | CustomResourceDefinition | — | tlspolicies.kuadrant.io | — |  |
| 7 | APIs | KEEP | CustomResourceDefinition | — | tokenratelimitpolicies.kuadrant.io | — |  |
| 8 | Namespaces | KEEP | Namespace | — | openshift-rhcl | — |  |

### authorino-operator (13 resources)

| Phase | Phase Name | Action | Kind | Namespace | Name | UID | Explicit |
|-------|-----------|--------|------|-----------|------|-----|----------|
| 1 | Freeze OLM | DELETE | Subscription | openshift-rhcl | authorino-operator-stable-redhat-operators-openshift-marketplace | 5fb6c7ee-da6... |  |
| 1 | Freeze OLM | KEEP | ClusterServiceVersion | openshift-rhcl | authorino-operator.v1.4.3 | d4856c0d-bf8... |  |
| 2 | Trigger operand cleanup | DELETE | AuthConfig | openshift-rhcl | 002268263f8bb03204567714a8f374dbaf67e0353162e6d450af43df8900c427 | 9a100b93-141... |  |
| 2 | Trigger operand cleanup | DELETE | AuthConfig | openshift-rhcl | 32c5926417ce74d07104e03d2afed39d36dfb3e0cd65e94a5f8f1e7b85163a98 | 175f7ffd-bac... |  |
| 2 | Trigger operand cleanup | DELETE | AuthConfig | openshift-rhcl | 77d78fccf2af9dd49c04b2afd9490521a51584cb63af0ecef56e9bae12d430c1 | a77cbb2a-e12... |  |
| 2 | Trigger operand cleanup | DELETE | AuthConfig | openshift-rhcl | 9a9b0d8c5f8335cb2f5af8be2bef8c1a7ef8846ba736ea4a7135bd4b966f4f63 | fdf29382-e49... |  |
| 2 | Trigger operand cleanup | DELETE | Authorino | openshift-rhcl | authorino | 9719677f-3db... |  |
| 4 | Remove Operator controllers | DELETE | ClusterServiceVersion | openshift-rhcl | authorino-operator.v1.4.3 | d4856c0d-bf8... |  |
| 5 | Namespace cleanup | KEEP | OperatorGroup | openshift-rhcl | rhcl-operator | 3746fb8a-203... |  |
| 5 | Namespace cleanup | REVIEW | Lease | openshift-rhcl | aac3a15d.authorino.kuadrant.io | b64d0a1c-7a7... |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | authconfigs.authorino.kuadrant.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | authorinos.operator.authorino.kuadrant.io | — |  |
| 7 | Namespaces | KEEP | Namespace | — | openshift-rhcl | — |  |

### dns-operator (9 resources)

| Phase | Phase Name | Action | Kind | Namespace | Name | UID | Explicit |
|-------|-----------|--------|------|-----------|------|-----|----------|
| 1 | Freeze OLM | DELETE | Subscription | openshift-rhcl | dns-operator-stable-redhat-operators-openshift-marketplace | cb88ae27-a31... |  |
| 1 | Freeze OLM | KEEP | ClusterServiceVersion | openshift-rhcl | dns-operator.v1.4.2 | d2d35c11-995... |  |
| 4 | Remove Operator controllers | DELETE | ClusterServiceVersion | openshift-rhcl | dns-operator.v1.4.2 | d2d35c11-995... |  |
| 5 | Namespace cleanup | KEEP | OperatorGroup | openshift-rhcl | rhcl-operator | 3746fb8a-203... |  |
| 5 | Namespace cleanup | REVIEW | Lease | openshift-rhcl | a3f98d6c.kuadrant.io | 308313cb-bbb... |  |
| 5 | Namespace cleanup | REVIEW | ConfigMap | openshift-rhcl | dns-operator-controller-env | a1af0a04-4da... |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | dnshealthcheckprobes.kuadrant.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | dnsrecords.kuadrant.io | — |  |
| 7 | Namespaces | KEEP | Namespace | — | openshift-rhcl | — |  |

### limitador-operator (9 resources)

| Phase | Phase Name | Action | Kind | Namespace | Name | UID | Explicit |
|-------|-----------|--------|------|-----------|------|-----|----------|
| 1 | Freeze OLM | DELETE | Subscription | openshift-rhcl | limitador-operator-stable-redhat-operators-openshift-marketplace | 8708f6aa-97c... |  |
| 1 | Freeze OLM | KEEP | ClusterServiceVersion | openshift-rhcl | limitador-operator.v1.4.2 | 4e6c692f-293... |  |
| 2 | Trigger operand cleanup | DELETE | Limitador | openshift-rhcl | limitador | 0e113d61-100... |  |
| 4 | Remove Operator controllers | DELETE | ClusterServiceVersion | openshift-rhcl | limitador-operator.v1.4.2 | 4e6c692f-293... |  |
| 5 | Namespace cleanup | KEEP | OperatorGroup | openshift-rhcl | rhcl-operator | 3746fb8a-203... |  |
| 5 | Namespace cleanup | REVIEW | Lease | openshift-rhcl | 3745a16e.kuadrant.io | 66914f7d-fed... |  |
| 5 | Namespace cleanup | REVIEW | ConfigMap | openshift-rhcl | limitador-operator-manager-config | a3f25092-2b0... |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | limitadors.limitador.kuadrant.io | — |  |
| 7 | Namespaces | KEEP | Namespace | — | openshift-rhcl | — |  |

### cluster-observability-operator (36 resources)

| Phase | Phase Name | Action | Kind | Namespace | Name | UID | Explicit |
|-------|-----------|--------|------|-----------|------|-----|----------|
| 1 | Freeze OLM | DELETE | Subscription | openshift-cluster-observability-operator | cluster-observability-operator | 11ffa38f-d1d... |  |
| 1 | Freeze OLM | KEEP | ClusterServiceVersion | openshift-cluster-observability-operator | cluster-observability-operator.v1.5.2 | 133506cd-f87... |  |
| 2 | Trigger operand cleanup | DELETE | UIPlugin | — | monitoring | 1362af41-28a... |  |
| 2 | Trigger operand cleanup | EXPECT | Perses | openshift-cluster-observability-operator | perses | 1d151267-6a3... |  |
| 2 | Trigger operand cleanup | EXPECT | PersesDashboard | openshift-cluster-observability-operator | accelerators-dashboard | ccde2f90-fb3... |  |
| 2 | Trigger operand cleanup | EXPECT | PersesDashboard | openshift-cluster-observability-operator | apm-dashboard | 45c36877-6dd... |  |
| 2 | Trigger operand cleanup | EXPECT | PersesDatasource | openshift-cluster-observability-operator | accelerators-thanos-querier-datasource | 58b01efa-1b9... |  |
| 2 | Trigger operand cleanup | DELETE | ScrapeConfig | redhat-ods-monitoring | maas-limitador | 333a1ef5-585... |  |
| 2 | Trigger operand cleanup | DELETE | PersesDashboard | openshift-cluster-observability-operator | maas-gateway-gpu-resources | f89966c9-6f5... |  |
| 2 | Trigger operand cleanup | DELETE | PersesDashboard | openshift-cluster-observability-operator | maas-gateway-performance | 24644bc8-83d... |  |
| 2 | Trigger operand cleanup | DELETE | PersesDashboard | redhat-ods-monitoring | dashboard-2-llm-d-traffic-admin | 7db376a9-d60... |  |
| 2 | Trigger operand cleanup | DELETE | PersesDashboard | redhat-ods-monitoring | dashboard-3-llm-d-utilization-admin | 20057131-f05... |  |
| 2 | Trigger operand cleanup | DELETE | PersesDashboard | redhat-ods-monitoring | dashboard-3-maas-usage-admin | f9a7100c-149... |  |
| 2 | Trigger operand cleanup | DELETE | PersesDashboard | redhat-ods-monitoring | dashboard-4-llm-d-performance-admin | a4429c70-3d5... |  |
| 2 | Trigger operand cleanup | DELETE | PersesGlobalDatasource | — | thanos-querier-datasource | 05d6fa68-c7a... |  |
| 4 | Remove Operator controllers | DELETE | ClusterServiceVersion | openshift-cluster-observability-operator | cluster-observability-operator.v1.5.2 | 133506cd-f87... |  |
| 5 | Namespace cleanup | DELETE | OperatorGroup | openshift-cluster-observability-operator | cluster-observability-operator | a349fca8-dab... |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | alertmanagerconfigs.monitoring.rhobs | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | alertmanagers.monitoring.rhobs | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | monitoringstacks.monitoring.rhobs | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | observabilityinstallers.observability.openshift.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | perses.perses.dev | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | persesdashboards.perses.dev | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | persesdatasources.perses.dev | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | persesglobaldatasources.perses.dev | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | podmonitors.monitoring.rhobs | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | probes.monitoring.rhobs | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | prometheusagents.monitoring.rhobs | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | prometheuses.monitoring.rhobs | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | prometheusrules.monitoring.rhobs | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | scrapeconfigs.monitoring.rhobs | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | servicemonitors.monitoring.rhobs | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | thanosqueriers.monitoring.rhobs | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | thanosrulers.monitoring.rhobs | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | uiplugins.observability.openshift.io | — |  |
| 7 | Namespaces | KEEP | Namespace | — | openshift-cluster-observability-operator | — |  |

### opentelemetry-product (10 resources)

| Phase | Phase Name | Action | Kind | Namespace | Name | UID | Explicit |
|-------|-----------|--------|------|-----------|------|-----|----------|
| 1 | Freeze OLM | DELETE | Subscription | openshift-opentelemetry-operator | opentelemetry-product | 9ddaf544-94a... |  |
| 1 | Freeze OLM | KEEP | ClusterServiceVersion | openshift-opentelemetry-operator | opentelemetry-operator.v0.158.0-2 | 9dfd524f-937... |  |
| 4 | Remove Operator controllers | DELETE | ClusterServiceVersion | openshift-opentelemetry-operator | opentelemetry-operator.v0.158.0-2 | 9dfd524f-937... |  |
| 5 | Namespace cleanup | DELETE | OperatorGroup | openshift-opentelemetry-operator | opentelemetry-product | 99faa08d-a46... |  |
| 5 | Namespace cleanup | REVIEW | Lease | openshift-opentelemetry-operator | 9f7554c3.opentelemetry.io | f3002242-9a1... |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | instrumentations.opentelemetry.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | opampbridges.opentelemetry.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | opentelemetrycollectors.opentelemetry.io | — |  |
| 6 | APIs | KEEP | CustomResourceDefinition | — | targetallocators.opentelemetry.io | — |  |
| 7 | Namespaces | KEEP | Namespace | — | openshift-opentelemetry-operator | — |  |

