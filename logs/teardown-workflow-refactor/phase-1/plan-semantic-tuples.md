# Plan Semantic Tuples — 15 Operators (Issue #46 Accepted)

Source: `logs/full-teardown-completion/phase-d-evidence/cycle-a-v3/plans/`

## Summary

| # | Operator | Phases | Resources | DELETE | KEEP | REVIEW | EXPECT | STRIPPED | Explicit |
|---|----------|--------|-----------|--------|------|--------|--------|----------|----------|
| 1 | rhods-operator | 8 | 134 | 42 | 18 | 1 | 73 | 0 | 5 |
| 2 | rhbk-operator | 8 | 10 | 6 | 4 | 0 | 0 | 0 | 1 |
| 3 | leader-worker-set | 7 | 7 | 3 | 3 | 1 | 0 | 0 | 0 |
| 4 | job-set | 7 | 8 | 4 | 3 | 1 | 0 | 0 | 0 |
| 5 | kueue-operator | 7 | 7 | 3 | 3 | 1 | 0 | 0 | 0 |
| 6 | servicemeshoperator3 | 7 | 26 | 3 | 22 | 1 | 0 | 0 | 0 |
| 7 | nfd | 7 | 16 | 5 | 8 | 3 | 0 | 0 | 0 |
| 8 | gpu-operator-certified | 7 | 12 | 4 | 7 | 1 | 0 | 0 | 0 |
| 9 | openshift-cert-manager-operator | 7 | 18 | 4 | 12 | 2 | 0 | 0 | 0 |
| 10 | rhcl-operator | 8 | 25 | 8 | 16 | 1 | 0 | 0 | 4 |
| 11 | authorino-operator | 7 | 8 | 2 | 5 | 1 | 0 | 0 | 0 |
| 12 | dns-operator | 7 | 9 | 2 | 5 | 2 | 0 | 0 | 0 |
| 13 | limitador-operator | 7 | 8 | 3 | 3 | 2 | 0 | 0 | 0 |
| 14 | cluster-observability-operator | 7 | 32 | 8 | 20 | 0 | 4 | 0 | 0 |
| 15 | opentelemetry-product | 7 | 10 | 3 | 6 | 1 | 0 | 0 | 0 |

**Total resources across all operators: 330**

## Nonempty Validation

All 15 operators have nonempty resource sets. No empty-set equality.

## Per-Operator Detail

### rhods-operator

File: `rhods-operator.json` | Schema v2 | 8 phases | 134 resources

| Phase | Name | Action | Group | Kind | Namespace | Name | UID | Explicit |
|-------|------|--------|-------|------|-----------|------|-----|----------|
| 1 | Freeze OLM | DELETE | operators.coreos.com | Subscription | redhat-ods-operator | rhods-operator | d8175cac... |  |
| 1 | Freeze OLM | KEEP | operators.coreos.com | ClusterServiceVersion | redhat-ods-operator | rhods-operator.3.5.1 | f94a3ecb... |  |
| 2 | Trigger operand cleanup | DELETE | datasciencecluster.opendatahub.io | DataScienceCluster | — | default-dsc | fa97159f... |  |
| 2 | Trigger operand cleanup | DELETE | dscinitialization.opendatahub.io | DSCInitialization | — | default-dsci | 03682b4b... |  |
| 2 | Trigger operand cleanup | DELETE | maas.opendatahub.io | Config | — | default | b74610ef... |  |
| 2 | Trigger operand cleanup | EXPECT | components.platform.opendatahub.io | DataSciencePipelines | — | default-datasciencepipelines | 23c16214... |  |
| 2 | Trigger operand cleanup | EXPECT | components.platform.opendatahub.io | ModelRegistry | — | default-modelregistry | 5982aa30... |  |
| 2 | Trigger operand cleanup | EXPECT | components.platform.opendatahub.io | Ray | — | default-ray | c30162ef... |  |
| 2 | Trigger operand cleanup | EXPECT | components.platform.opendatahub.io | Trainer | — | default-trainer | a74381d7... |  |
| 2 | Trigger operand cleanup | EXPECT | components.platform.opendatahub.io | TrainingOperator | — | default-trainingoperator | 6497d729... |  |
| 2 | Trigger operand cleanup | EXPECT | components.platform.opendatahub.io | TrustyAI | — | default-trustyai | b1eb2447... |  |
| 2 | Trigger operand cleanup | EXPECT | infrastructure.opendatahub.io | HardwareProfile | redhat-ods-applications | default-profile | 6e1a5f0f... |  |
| 2 | Trigger operand cleanup | EXPECT | services.platform.opendatahub.io | GatewayConfig | — | default-gateway | 1de66233... |  |
| 2 | Trigger operand cleanup | EXPECT | services.platform.opendatahub.io | Monitoring | — | default-monitoring | 25a9894a... |  |
| 2 | Trigger operand cleanup | EXPECT | components.platform.opendatahub.io | AIGateway | — | default-aigateway | 31943c1a... |  |
| 2 | Trigger operand cleanup | EXPECT | components.platform.opendatahub.io | Dashboard | — | default-dashboard | 17a2f650... |  |
| 2 | Trigger operand cleanup | EXPECT | components.platform.opendatahub.io | FeastOperator | — | default-feastoperator | 3dc9efce... |  |
| 2 | Trigger operand cleanup | EXPECT | components.platform.opendatahub.io | Kserve | — | default-kserve | 59addb4c... |  |
| 2 | Trigger operand cleanup | EXPECT | components.platform.opendatahub.io | MLflowOperator | — | default-mlflowoperator | d455d7e5... |  |
| 2 | Trigger operand cleanup | EXPECT | components.platform.opendatahub.io | OGX | — | default-ogx | 01794ead... |  |
| 2 | Trigger operand cleanup | EXPECT | components.platform.opendatahub.io | Workbenches | — | default-workbenches | 6aac395e... |  |
| 2 | Trigger operand cleanup | EXPECT | console.openshift.io | OdhQuickStart | redhat-ods-applications | create-aikit-notebook | 15c35155... |  |
| 2 | Trigger operand cleanup | EXPECT | console.openshift.io | OdhQuickStart | redhat-ods-applications | create-jupyter-notebook | 55354a2a... |  |
| 2 | Trigger operand cleanup | EXPECT | console.openshift.io | OdhQuickStart | redhat-ods-applications | deploy-python-model | ae0ac1f0... |  |
| 2 | Trigger operand cleanup | EXPECT | console.openshift.io | OdhQuickStart | redhat-ods-applications | openvino-inference-notebook | 51f29ccb... |  |
| 2 | Trigger operand cleanup | EXPECT | console.openshift.io | OdhQuickStart | redhat-ods-applications | pachyderm-beginner-tutorial-notebook | 154c9a6d... |  |
| 2 | Trigger operand cleanup | EXPECT | console.openshift.io | OdhQuickStart | redhat-ods-applications | using-starburst-enterprise | 04f28202... |  |
| 2 | Trigger operand cleanup | EXPECT | dashboard.opendatahub.io | OdhApplication | redhat-ods-applications | agentic-starter-kits | 7fe3e207... |  |
| 2 | Trigger operand cleanup | EXPECT | dashboard.opendatahub.io | OdhApplication | redhat-ods-applications | aikit | ec4103de... |  |
| 2 | Trigger operand cleanup | EXPECT | dashboard.opendatahub.io | OdhApplication | redhat-ods-applications | elastic | c61e201b... |  |
| 2 | Trigger operand cleanup | EXPECT | dashboard.opendatahub.io | OdhApplication | redhat-ods-applications | jupyter | 0d13914e... |  |
| 2 | Trigger operand cleanup | EXPECT | dashboard.opendatahub.io | OdhApplication | redhat-ods-applications | mlflow | e42a26e6... |  |
| 2 | Trigger operand cleanup | EXPECT | dashboard.opendatahub.io | OdhApplication | redhat-ods-applications | nvidia-nim | b864eb9d... |  |
| 2 | Trigger operand cleanup | EXPECT | dashboard.opendatahub.io | OdhApplication | redhat-ods-applications | openvino | 59a13742... |  |
| 2 | Trigger operand cleanup | EXPECT | dashboard.opendatahub.io | OdhApplication | redhat-ods-applications | pachyderm | 6cc6d8b9... |  |
| 2 | Trigger operand cleanup | EXPECT | dashboard.opendatahub.io | OdhApplication | redhat-ods-applications | pgvector | 734d58b0... |  |
| 2 | Trigger operand cleanup | EXPECT | dashboard.opendatahub.io | OdhApplication | redhat-ods-applications | rhoai | 2b680ab3... |  |
| 2 | Trigger operand cleanup | EXPECT | dashboard.opendatahub.io | OdhApplication | redhat-ods-applications | starburstenterprise | 242ce688... |  |
| 2 | Trigger operand cleanup | EXPECT | dashboard.opendatahub.io | OdhApplication | redhat-ods-applications | watson-x-ai | 5b12c52b... |  |
| 2 | Trigger operand cleanup | EXPECT | dashboard.opendatahub.io | OdhDocument | redhat-ods-applications | agentic-starter-kits-a2a-tutorial | 420d44e9... |  |
| 2 | Trigger operand cleanup | EXPECT | dashboard.opendatahub.io | OdhDocument | redhat-ods-applications | agentic-starter-kits-autogen-tutorial | 51edeedd... |  |
| 2 | Trigger operand cleanup | EXPECT | dashboard.opendatahub.io | OdhDocument | redhat-ods-applications | agentic-starter-kits-crewai-tutorial | 72f475a5... |  |
| 2 | Trigger operand cleanup | EXPECT | dashboard.opendatahub.io | OdhDocument | redhat-ods-applications | agentic-starter-kits-google-adk-tutorial | b393fc7a... |  |
| 2 | Trigger operand cleanup | EXPECT | dashboard.opendatahub.io | OdhDocument | redhat-ods-applications | agentic-starter-kits-hitl-tutorial | 90cf0470... |  |
| 2 | Trigger operand cleanup | EXPECT | dashboard.opendatahub.io | OdhDocument | redhat-ods-applications | agentic-starter-kits-langflow-tutorial | de9e4b27... |  |
| 2 | Trigger operand cleanup | EXPECT | dashboard.opendatahub.io | OdhDocument | redhat-ods-applications | agentic-starter-kits-langgraph-tutorial | 87da3ddb... |  |
| 2 | Trigger operand cleanup | EXPECT | dashboard.opendatahub.io | OdhDocument | redhat-ods-applications | agentic-starter-kits-llamaindex-tutorial | e2abf6a6... |  |
| 2 | Trigger operand cleanup | EXPECT | dashboard.opendatahub.io | OdhDocument | redhat-ods-applications | agentic-starter-kits-memory-tutorial | 4cb6c9ef... |  |
| 2 | Trigger operand cleanup | EXPECT | dashboard.opendatahub.io | OdhDocument | redhat-ods-applications | agentic-starter-kits-rag-tutorial | 88aef28f... |  |
| 2 | Trigger operand cleanup | EXPECT | dashboard.opendatahub.io | OdhDocument | redhat-ods-applications | agentic-starter-kits-vanilla-python-tutorial | c12daca6... |  |
| 2 | Trigger operand cleanup | EXPECT | dashboard.opendatahub.io | OdhDocument | redhat-ods-applications | jupyter-install-python-packages | d5a1ba83... |  |
| 2 | Trigger operand cleanup | EXPECT | dashboard.opendatahub.io | OdhDocument | redhat-ods-applications | jupyter-update-server-settings | 99091682... |  |
| 2 | Trigger operand cleanup | EXPECT | dashboard.opendatahub.io | OdhDocument | redhat-ods-applications | jupyter-use-s3-bucket-data | 528c3dd3... |  |
| 2 | Trigger operand cleanup | EXPECT | dashboard.opendatahub.io | OdhDocument | redhat-ods-applications | jupyter-view-installed-packages | 96ccae1f... |  |
| 2 | Trigger operand cleanup | EXPECT | dashboard.opendatahub.io | OdhDocument | redhat-ods-applications | openvino-ovms-serving | 837f4890... |  |
| 2 | Trigger operand cleanup | EXPECT | dashboard.opendatahub.io | OdhDocument | redhat-ods-applications | pachyderm-beginner-tutorial | 08550d4b... |  |
| 2 | Trigger operand cleanup | EXPECT | dashboard.opendatahub.io | OdhDocument | redhat-ods-applications | pachyderm-house-pricing-tutorial | bb74705a... |  |
| 2 | Trigger operand cleanup | EXPECT | dashboard.opendatahub.io | OdhDocument | redhat-ods-applications | rhoai-documentation | 8bdef5fe... |  |
| 2 | Trigger operand cleanup | EXPECT | dashboard.opendatahub.io | OdhDocument | redhat-ods-applications | rhoai-tutorial-fraud | e8c8d67f... |  |
| 2 | Trigger operand cleanup | EXPECT | dashboard.opendatahub.io | OdhDocument | redhat-ods-applications | starburst-enterprise-requirements | 38dc25d0... |  |
| 2 | Trigger operand cleanup | EXPECT | dashboard.opendatahub.io | OdhDocument | redhat-ods-applications | starburst-openshift-deployment | e09a9865... |  |
| 2 | Trigger operand cleanup | EXPECT | dashboard.opendatahub.io | OdhDocument | redhat-ods-applications | starburst-openshift-overview | 4cd08bbf... |  |
| 2 | Trigger operand cleanup | EXPECT | dashboard.opendatahub.io | OdhDocument | redhat-ods-applications | watson-x-use-case | 25b9ca7b... |  |
| 2 | Trigger operand cleanup | EXPECT | maas.opendatahub.io | AITenant | ai-tenants | models-as-a-service | 8b1ad576... |  |
| 2 | Trigger operand cleanup | EXPECT | maas.opendatahub.io | MaasTenantConfig | models-as-a-service | default-tenant | e0cb6e9b... |  |
| 2 | Trigger operand cleanup | EXPECT | serving.kserve.io | ClusterStorageContainer | — | default | fa8e1368... |  |
| 2 | Trigger operand cleanup | EXPECT | trainer.kubeflow.org | ClusterTrainingRuntime | — | torch-distributed | 2a1eac6e... |  |
| 2 | Trigger operand cleanup | EXPECT | trainer.kubeflow.org | ClusterTrainingRuntime | — | torch-distributed-cpu | 47c75876... |  |
| 2 | Trigger operand cleanup | EXPECT | trainer.kubeflow.org | ClusterTrainingRuntime | — | torch-distributed-cpu-torch211-py312 | 182f5657... |  |
| 2 | Trigger operand cleanup | EXPECT | trainer.kubeflow.org | ClusterTrainingRuntime | — | torch-distributed-cuda130-torch211-py312 | 759e1a8e... |  |
| 2 | Trigger operand cleanup | EXPECT | trainer.kubeflow.org | ClusterTrainingRuntime | — | torch-distributed-rocm | fcd689ef... |  |
| 2 | Trigger operand cleanup | EXPECT | trainer.kubeflow.org | ClusterTrainingRuntime | — | torch-distributed-rocm714-torch211-py312 | 63b58f56... |  |
| 2 | Trigger operand cleanup | EXPECT | trainer.kubeflow.org | ClusterTrainingRuntime | — | training-hub | 98fbb91e... |  |
| 2 | Trigger operand cleanup | EXPECT | trainer.kubeflow.org | ClusterTrainingRuntime | — | training-hub-cpu | 2d9c47ad... |  |
| 2 | Trigger operand cleanup | EXPECT | trainer.kubeflow.org | ClusterTrainingRuntime | — | training-hub-rocm | 8affb17f... |  |
| 2 | Trigger operand cleanup | EXPECT | trainer.kubeflow.org | ClusterTrainingRuntime | — | training-hub-th09-cpu-torch211-py312 | 96f36fee... |  |
| 2 | Trigger operand cleanup | EXPECT | trainer.kubeflow.org | ClusterTrainingRuntime | — | training-hub-th09-cuda130-torch211-py312 | 35a7d6fc... |  |
| 2 | Trigger operand cleanup | EXPECT | trainer.kubeflow.org | ClusterTrainingRuntime | — | training-hub-th09-rocm714-torch211-py312 | 43f49a9e... |  |
| 2 | Trigger operand cleanup | DELETE | infrastructure.opendatahub.io | HardwareProfile | redhat-ods-applications | nvidia-gpu-1 | 5866ca65... |  |
| 2 | Trigger operand cleanup | DELETE | services.platform.opendatahub.io | Auth | — | auth | c7edfed8... |  |
| 2 | Trigger operand cleanup | DELETE | mlflow.opendatahub.io | MLflow | — | mlflow | 52805766... |  |
| 3 | Remaining cleanup | DELETE | maas.opendatahub.io | MaaSAuthPolicy | models-as-a-service | admin-auth-policy | 44abc60f... |  |
| 3 | Remaining cleanup | DELETE | maas.opendatahub.io | MaaSAuthPolicy | models-as-a-service | maas-qwen3-06b-users-auth-policy | bdecb970... |  |
| 3 | Remaining cleanup | DELETE | maas.opendatahub.io | MaaSSubscription | models-as-a-service | maas-admins-subscription | ba4200a7... |  |
| 3 | Remaining cleanup | DELETE | maas.opendatahub.io | MaaSSubscription | models-as-a-service | maas-qwen3-06b-users-subscription | ccd4fba5... |  |
| 3 | Remaining cleanup | DELETE | maas.opendatahub.io | MaasTenantConfig | redhat-ods-applications | default-tenant | 2debb138... |  |
| 3 | Remaining cleanup | DELETE | ogx.io | OGXServer | redhat-ods-applications | ogx-server | 08b20ec3... |  |
| 3 | Remaining cleanup | DELETE | opendatahub.io | OdhDashboardConfig | redhat-ods-applications | odh-dashboard-config | ba250171... |  |
| 3 | Remaining cleanup | DELETE | serving.kserve.io | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-decode-template | d042060c... |  |
| 3 | Remaining cleanup | DELETE | serving.kserve.io | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-decode-worker-data-parallel | 5a182f2e... |  |
| 3 | Remaining cleanup | DELETE | serving.kserve.io | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-multi-node-pd-template-nvidia-cuda | 2ac906a5... |  |
| 3 | Remaining cleanup | DELETE | serving.kserve.io | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-multi-node-template-nvidia-cuda | 781be3bd... |  |
| 3 | Remaining cleanup | DELETE | serving.kserve.io | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-prefill-template | 740d97dd... |  |
| 3 | Remaining cleanup | DELETE | serving.kserve.io | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-prefill-worker-data-parallel | 0c793f1f... |  |
| 3 | Remaining cleanup | DELETE | serving.kserve.io | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-router-route | e99a4127... |  |
| 3 | Remaining cleanup | DELETE | serving.kserve.io | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-scheduler | 33229ed7... |  |
| 3 | Remaining cleanup | DELETE | serving.kserve.io | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-scheduler-latency-predictor | a611b44b... |  |
| 3 | Remaining cleanup | DELETE | serving.kserve.io | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-single-node-pd-template-nvidia-cuda | 9ec1fed0... |  |
| 3 | Remaining cleanup | DELETE | serving.kserve.io | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-single-node-template-nvidia-cuda | ac811a02... |  |
| 3 | Remaining cleanup | DELETE | serving.kserve.io | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-template | ca9ddf72... |  |
| 3 | Remaining cleanup | DELETE | serving.kserve.io | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-template-amd-rocm | 9f1c86a4... |  |
| 3 | Remaining cleanup | DELETE | serving.kserve.io | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-template-ibm-spyre-ppc64le | ca3afccd... |  |
| 3 | Remaining cleanup | DELETE | serving.kserve.io | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-template-ibm-spyre-s390x | b3588e0f... |  |
| 3 | Remaining cleanup | DELETE | serving.kserve.io | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-template-ibm-spyre-x86 | 416a9fd3... |  |
| 3 | Remaining cleanup | DELETE | serving.kserve.io | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-template-intel-gaudi | 918cfc5b... |  |
| 3 | Remaining cleanup | DELETE | serving.kserve.io | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-tokenizer | 1651f5c0... |  |
| 3 | Remaining cleanup | DELETE | serving.kserve.io | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-tracing | a4928e94... |  |
| 3 | Remaining cleanup | DELETE | serving.kserve.io | LLMInferenceServiceConfig | redhat-ods-applications | v3-5-1-kserve-config-llm-worker-data-parallel | 76b69d5c... |  |
| 3 | Remaining cleanup | DELETE | trustyai.opendatahub.io | NemoGuardrails | redhat-ods-applications | nemo-guardrails | bfe08c0d... |  |
| 4 | Remove Operator controllers | DELETE | operators.coreos.com | ClusterServiceVersion | redhat-ods-operator | rhods-operator.3.5.1 | f94a3ecb... |  |
| 5 | Namespace cleanup | DELETE | operators.coreos.com | OperatorGroup | redhat-ods-operator | rhods-operator | ba0a0318... |  |
| 5 | Namespace cleanup | REVIEW | coordination.k8s.io | Lease | redhat-ods-operator | 07ed84f7.opendatahub.io | 3588a54d... |  |
| 6 | Explicit cleanup | DELETE | apps | Deployment | redhat-ods-applications | maas-postgres | c71dcc06... | yes |
| 6 | Explicit cleanup | DELETE | apps | StatefulSet | redhat-ods-applications | ogx-postgres | f9060f89... | yes |
| 6 | Explicit cleanup | DELETE | apps | Deployment | rhoai-model-registries | model-catalog | 6b1da06e... | yes |
| 6 | Explicit cleanup | DELETE | gateway.networking.k8s.io | Gateway | openshift-ingress | maas-default-gateway | 9739a44f... | yes |
| 6 | Explicit cleanup | DELETE |  | ConfigMap | openshift-ingress | maas-gateway-options | 0a4f5c32... | yes |
| 7 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | auths.services.platform.opendatahub.io | — |  |
| 7 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | datascienceclusters.datasciencecluster.opendatahub.io | — |  |
| 7 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | datasciencepipelines.components.platform.opendatahub.io | — |  |
| 7 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | dscinitializations.dscinitialization.opendatahub.io | — |  |
| 7 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | featuretrackers.features.opendatahub.io | — |  |
| 7 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | gatewayconfigs.services.platform.opendatahub.io | — |  |
| 7 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | hardwareprofiles.infrastructure.opendatahub.io | — |  |
| 7 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | kueues.components.platform.opendatahub.io | — |  |
| 7 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | modelregistries.components.platform.opendatahub.io | — |  |
| 7 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | monitorings.services.platform.opendatahub.io | — |  |
| 7 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | platforms.config.opendatahub.io | — |  |
| 7 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | rays.components.platform.opendatahub.io | — |  |
| 7 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | sparkoperators.components.platform.opendatahub.io | — |  |
| 7 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | trainers.components.platform.opendatahub.io | — |  |
| 7 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | trainingoperators.components.platform.opendatahub.io | — |  |
| 7 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | trustyais.components.platform.opendatahub.io | — |  |
| 8 | Namespaces | KEEP |  | Namespace | — | redhat-ods-operator | — |  |

### rhbk-operator

File: `rhbk-operator.json` | Schema v2 | 8 phases | 10 resources

| Phase | Name | Action | Group | Kind | Namespace | Name | UID | Explicit |
|-------|------|--------|-------|------|-----------|------|-----|----------|
| 1 | Freeze OLM | DELETE | operators.coreos.com | Subscription | keycloak | rhbk-operator | 909796b7... |  |
| 1 | Freeze OLM | KEEP | operators.coreos.com | ClusterServiceVersion | keycloak | rhbk-operator.v26.6.7-opr.1 | 9774dbc8... |  |
| 2 | Trigger operand cleanup | DELETE | k8s.keycloak.org | Keycloak | keycloak | keycloak | 44b43bc9... |  |
| 2 | Trigger operand cleanup | DELETE | k8s.keycloak.org | KeycloakRealmImport | keycloak | maas-realm | b06c8f03... |  |
| 4 | Remove Operator controllers | DELETE | operators.coreos.com | ClusterServiceVersion | keycloak | rhbk-operator.v26.6.7-opr.1 | 9774dbc8... |  |
| 5 | Namespace cleanup | DELETE | operators.coreos.com | OperatorGroup | keycloak | rhbk-operator | 422c03e0... |  |
| 6 | Explicit cleanup | DELETE | apps | StatefulSet | keycloak | postgres | a1556a15... | yes |
| 7 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | keycloakrealmimports.k8s.keycloak.org | — |  |
| 7 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | keycloaks.k8s.keycloak.org | — |  |
| 8 | Namespaces | KEEP |  | Namespace | — | keycloak | — |  |

### leader-worker-set

File: `leader-worker-set.json` | Schema v2 | 7 phases | 7 resources

| Phase | Name | Action | Group | Kind | Namespace | Name | UID | Explicit |
|-------|------|--------|-------|------|-----------|------|-----|----------|
| 1 | Freeze OLM | DELETE | operators.coreos.com | Subscription | openshift-leaderworkerset | leader-worker-set | db8356ed... |  |
| 1 | Freeze OLM | KEEP | operators.coreos.com | ClusterServiceVersion | openshift-leaderworkerset | leader-worker-set.v1.0.1 | 5bfec5ce... |  |
| 4 | Remove Operator controllers | DELETE | operators.coreos.com | ClusterServiceVersion | openshift-leaderworkerset | leader-worker-set.v1.0.1 | 5bfec5ce... |  |
| 5 | Namespace cleanup | DELETE | operators.coreos.com | OperatorGroup | openshift-leaderworkerset | leader-worker-set | b3f4dc2b... |  |
| 5 | Namespace cleanup | REVIEW | coordination.k8s.io | Lease | openshift-leaderworkerset | openshift-lws-operator-lock | 0f89d0dd... |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | leaderworkersetoperators.operator.openshift.io | — |  |
| 7 | Namespaces | KEEP |  | Namespace | — | openshift-leaderworkerset | — |  |

### job-set

File: `job-set.json` | Schema v2 | 7 phases | 8 resources

| Phase | Name | Action | Group | Kind | Namespace | Name | UID | Explicit |
|-------|------|--------|-------|------|-----------|------|-----|----------|
| 1 | Freeze OLM | DELETE | operators.coreos.com | Subscription | openshift-jobset | job-set | f4f21e7b... |  |
| 1 | Freeze OLM | KEEP | operators.coreos.com | ClusterServiceVersion | openshift-jobset | jobset-operator.v1.0.1 | 7bba7c4d... |  |
| 2 | Trigger operand cleanup | DELETE | operator.openshift.io | JobSetOperator | — | cluster | 7fd7c2ba... |  |
| 4 | Remove Operator controllers | DELETE | operators.coreos.com | ClusterServiceVersion | openshift-jobset | jobset-operator.v1.0.1 | 7bba7c4d... |  |
| 5 | Namespace cleanup | DELETE | operators.coreos.com | OperatorGroup | openshift-jobset | job-set | 93c85027... |  |
| 5 | Namespace cleanup | REVIEW | coordination.k8s.io | Lease | openshift-jobset | openshift-jobset-operator-lock | ff993506... |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | jobsetoperators.operator.openshift.io | — |  |
| 7 | Namespaces | KEEP |  | Namespace | — | openshift-jobset | — |  |

### kueue-operator

File: `kueue-operator.json` | Schema v2 | 7 phases | 7 resources

| Phase | Name | Action | Group | Kind | Namespace | Name | UID | Explicit |
|-------|------|--------|-------|------|-----------|------|-----|----------|
| 1 | Freeze OLM | DELETE | operators.coreos.com | Subscription | openshift-kueue | kueue-operator | 007736c4... |  |
| 1 | Freeze OLM | KEEP | operators.coreos.com | ClusterServiceVersion | openshift-kueue | kueue-operator.v1.4.2 | a8a00bc2... |  |
| 4 | Remove Operator controllers | DELETE | operators.coreos.com | ClusterServiceVersion | openshift-kueue | kueue-operator.v1.4.2 | a8a00bc2... |  |
| 5 | Namespace cleanup | DELETE | operators.coreos.com | OperatorGroup | openshift-kueue | kueue-operator | f99b742a... |  |
| 5 | Namespace cleanup | REVIEW | coordination.k8s.io | Lease | openshift-kueue | openshift-kueue-operator-lock | 594a9a45... |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | kueues.kueue.openshift.io | — |  |
| 7 | Namespaces | KEEP |  | Namespace | — | openshift-kueue | — |  |

### servicemeshoperator3

File: `servicemeshoperator3.json` | Schema v2 | 7 phases | 26 resources

| Phase | Name | Action | Group | Kind | Namespace | Name | UID | Explicit |
|-------|------|--------|-------|------|-----------|------|-----|----------|
| 1 | Freeze OLM | DELETE | operators.coreos.com | Subscription | openshift-servicemesh | servicemeshoperator3 | 56739c23... |  |
| 1 | Freeze OLM | KEEP | operators.coreos.com | ClusterServiceVersion | openshift-servicemesh | servicemeshoperator3.v3.4.2 | e0c375d6... |  |
| 4 | Remove Operator controllers | DELETE | operators.coreos.com | ClusterServiceVersion | openshift-servicemesh | servicemeshoperator3.v3.4.2 | e0c375d6... |  |
| 5 | Namespace cleanup | DELETE | operators.coreos.com | OperatorGroup | openshift-servicemesh | servicemeshoperator3 | be422652... |  |
| 5 | Namespace cleanup | REVIEW | coordination.k8s.io | Lease | openshift-servicemesh | sail-operator-lock | 8a707756... |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | trafficextensions.extensions.istio.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | wasmplugins.extensions.istio.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | destinationrules.networking.istio.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | envoyfilters.networking.istio.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | gateways.networking.istio.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | proxyconfigs.networking.istio.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | serviceentries.networking.istio.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | sidecars.networking.istio.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | virtualservices.networking.istio.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | workloadentries.networking.istio.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | workloadgroups.networking.istio.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | ztunnels.sailoperator.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | authorizationpolicies.security.istio.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | peerauthentications.security.istio.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | requestauthentications.security.istio.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | telemetries.telemetry.istio.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | istiocnis.sailoperator.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | istiorevisions.sailoperator.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | istiorevisiontags.sailoperator.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | istios.sailoperator.io | — |  |
| 7 | Namespaces | KEEP |  | Namespace | — | openshift-servicemesh | — |  |

### nfd

File: `nfd-final.json` | Schema v2 | 7 phases | 16 resources

| Phase | Name | Action | Group | Kind | Namespace | Name | UID | Explicit |
|-------|------|--------|-------|------|-----------|------|-----|----------|
| 1 | Freeze OLM | DELETE | operators.coreos.com | Subscription | openshift-nfd | nfd | 36ae55f7... |  |
| 1 | Freeze OLM | KEEP | operators.coreos.com | ClusterServiceVersion | openshift-nfd | nfd.4.22.0-202609212027 | 0e3ae75f... |  |
| 2 | Trigger operand cleanup | DELETE | nfd.k8s-sigs.io | NodeFeature | openshift-nfd | ip-10-0-23-226.us-east-2.compute.internal | 3933aee4... |  |
| 2 | Trigger operand cleanup | DELETE | nfd.openshift.io | NodeFeatureDiscovery | openshift-nfd | nfd-instance | b4c5e454... |  |
| 4 | Remove Operator controllers | DELETE | operators.coreos.com | ClusterServiceVersion | openshift-nfd | nfd.4.22.0-202609212027 | 0e3ae75f... |  |
| 5 | Namespace cleanup | DELETE | operators.coreos.com | OperatorGroup | openshift-nfd | nfd | 5b10288e... |  |
| 5 | Namespace cleanup | REVIEW | coordination.k8s.io | Lease | openshift-nfd | 39f5e5c3.nodefeaturediscoveries.nfd.openshift.io | b2186edc... |  |
| 5 | Namespace cleanup | REVIEW |  | ConfigMap | openshift-nfd | nfd-manager-config | 11d745ba... |  |
| 5 | Namespace cleanup | REVIEW |  | ConfigMap | openshift-nfd | nfd-worker | a5634fc0... |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | nodefeaturediscoveries.nfd.openshift.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | nodefeaturegroups.nfd.k8s-sigs.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | nodefeaturerules.nfd.k8s-sigs.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | nodefeaturerules.nfd.openshift.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | nodefeatures.nfd.k8s-sigs.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | nodefeatures.nfd.openshift.io | — |  |
| 7 | Namespaces | KEEP |  | Namespace | — | openshift-nfd | — |  |

### gpu-operator-certified

File: `gpu-operator-certified-final.json` | Schema v2 | 7 phases | 12 resources

| Phase | Name | Action | Group | Kind | Namespace | Name | UID | Explicit |
|-------|------|--------|-------|------|-----------|------|-----|----------|
| 1 | Freeze OLM | DELETE | operators.coreos.com | Subscription | nvidia-gpu-operator | gpu-operator-certified | 3ca6157c... |  |
| 1 | Freeze OLM | KEEP | operators.coreos.com | ClusterServiceVersion | nvidia-gpu-operator | gpu-operator-certified.v26.7.1 | 25ebbf41... |  |
| 2 | Trigger operand cleanup | DELETE | nvidia.com | ClusterPolicy | — | gpu-cluster-policy | 10b41aa5... |  |
| 4 | Remove Operator controllers | DELETE | operators.coreos.com | ClusterServiceVersion | nvidia-gpu-operator | gpu-operator-certified.v26.7.1 | 25ebbf41... |  |
| 5 | Namespace cleanup | DELETE | operators.coreos.com | OperatorGroup | nvidia-gpu-operator | gpu-operator-certified | 79e7b2fe... |  |
| 5 | Namespace cleanup | REVIEW | coordination.k8s.io | Lease | nvidia-gpu-operator | 53822513.nvidia.com | 2b20a221... |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | nvidiadrivers.nvidia.com | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | gpuclusters.nvidia.com | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | computedomains.resource.nvidia.com | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | computedomaincliques.resource.nvidia.com | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | clusterpolicies.nvidia.com | — |  |
| 7 | Namespaces | KEEP |  | Namespace | — | nvidia-gpu-operator | — |  |

### openshift-cert-manager-operator

File: `cert-manager-operator-final.json` | Schema v2 | 7 phases | 18 resources

| Phase | Name | Action | Group | Kind | Namespace | Name | UID | Explicit |
|-------|------|--------|-------|------|-----------|------|-----|----------|
| 1 | Freeze OLM | DELETE | operators.coreos.com | Subscription | cert-manager-operator | openshift-cert-manager-operator | e87aab2f... |  |
| 1 | Freeze OLM | KEEP | operators.coreos.com | ClusterServiceVersion | cert-manager-operator | cert-manager-operator.v1.20.0 | d3d27294... |  |
| 2 | Trigger operand cleanup | DELETE | operator.openshift.io | CertManager | — | cluster | 99c43085... |  |
| 4 | Remove Operator controllers | DELETE | operators.coreos.com | ClusterServiceVersion | cert-manager-operator | cert-manager-operator.v1.20.0 | d3d27294... |  |
| 5 | Namespace cleanup | DELETE | operators.coreos.com | OperatorGroup | cert-manager-operator | openshift-cert-manager-operator | b4596545... |  |
| 5 | Namespace cleanup | REVIEW | coordination.k8s.io | Lease | cert-manager-operator | cert-manager-operator-lock | 813ad357... |  |
| 5 | Namespace cleanup | REVIEW |  | ConfigMap | cert-manager-operator | cert-manager-operator-trusted-ca-bundle | 7e8eaf4f... |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | bundles.trust.cert-manager.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | certificaterequests.cert-manager.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | certificates.cert-manager.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | certmanagers.operator.openshift.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | challenges.acme.cert-manager.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | clusterissuers.cert-manager.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | issuers.cert-manager.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | istiocsrs.operator.openshift.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | orders.acme.cert-manager.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | trustmanagers.operator.openshift.io | — |  |
| 7 | Namespaces | KEEP |  | Namespace | — | cert-manager-operator | — |  |

### rhcl-operator

File: `rhcl-operator.json` | Schema v2 | 8 phases | 25 resources

| Phase | Name | Action | Group | Kind | Namespace | Name | UID | Explicit |
|-------|------|--------|-------|------|-----------|------|-----|----------|
| 1 | Freeze OLM | DELETE | operators.coreos.com | Subscription | openshift-rhcl | rhcl-operator | 1ca03138... |  |
| 1 | Freeze OLM | KEEP | operators.coreos.com | ClusterServiceVersion | openshift-rhcl | rhcl-operator.v1.4.3 | 6cbf6963... |  |
| 2 | Trigger operand cleanup | DELETE | kuadrant.io | AuthPolicy | openshift-ingress | maas-gateway-auth | 3ae65a06... |  |
| 2 | Trigger operand cleanup | DELETE | kuadrant.io | Kuadrant | openshift-rhcl | kuadrant | c9061526... |  |
| 4 | Remove Operator controllers | DELETE | operators.coreos.com | ClusterServiceVersion | openshift-rhcl | rhcl-operator.v1.4.3 | 6cbf6963... |  |
| 5 | Namespace cleanup | KEEP | operators.coreos.com | OperatorGroup | openshift-rhcl | rhcl-operator | 3746fb8a... |  |
| 5 | Namespace cleanup | REVIEW | coordination.k8s.io | Lease | openshift-rhcl | f139389e.kuadrant.io | 36322248... |  |
| 6 | Explicit cleanup | DELETE | console.openshift.io | ConsolePlugin | — | kuadrant-console-plugin | b33501b2... | yes |
| 6 | Explicit cleanup | DELETE | apps | Deployment | openshift-rhcl | kuadrant-console-plugin | f48c2899... | yes |
| 6 | Explicit cleanup | DELETE |  | Service | openshift-rhcl | kuadrant-console-plugin | 66f7d874... | yes |
| 6 | Explicit cleanup | DELETE |  | ConfigMap | openshift-rhcl | kuadrant-console-nginx-conf | b3b875ff... | yes |
| 7 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | apikeyapprovals.devportal.kuadrant.io | — |  |
| 7 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | apikeyrequests.devportal.kuadrant.io | — |  |
| 7 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | apikeys.devportal.kuadrant.io | — |  |
| 7 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | apiproducts.devportal.kuadrant.io | — |  |
| 7 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | authpolicies.kuadrant.io | — |  |
| 7 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | dnspolicies.kuadrant.io | — |  |
| 7 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | kuadrants.kuadrant.io | — |  |
| 7 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | oidcpolicies.extensions.kuadrant.io | — |  |
| 7 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | planpolicies.extensions.kuadrant.io | — |  |
| 7 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | ratelimitpolicies.kuadrant.io | — |  |
| 7 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | telemetrypolicies.extensions.kuadrant.io | — |  |
| 7 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | tlspolicies.kuadrant.io | — |  |
| 7 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | tokenratelimitpolicies.kuadrant.io | — |  |
| 8 | Namespaces | KEEP |  | Namespace | — | openshift-rhcl | — |  |

### authorino-operator

File: `authorino-operator-final.json` | Schema v2 | 7 phases | 8 resources

| Phase | Name | Action | Group | Kind | Namespace | Name | UID | Explicit |
|-------|------|--------|-------|------|-----------|------|-----|----------|
| 1 | Freeze OLM | DELETE | operators.coreos.com | Subscription | openshift-rhcl | authorino-operator-stable-redhat-operators-openshift-marketplace | 5fb6c7ee... |  |
| 1 | Freeze OLM | KEEP | operators.coreos.com | ClusterServiceVersion | openshift-rhcl | authorino-operator.v1.4.3 | d4856c0d... |  |
| 4 | Remove Operator controllers | DELETE | operators.coreos.com | ClusterServiceVersion | openshift-rhcl | authorino-operator.v1.4.3 | d4856c0d... |  |
| 5 | Namespace cleanup | KEEP | operators.coreos.com | OperatorGroup | openshift-rhcl | rhcl-operator | 3746fb8a... |  |
| 5 | Namespace cleanup | REVIEW | coordination.k8s.io | Lease | openshift-rhcl | aac3a15d.authorino.kuadrant.io | b64d0a1c... |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | authconfigs.authorino.kuadrant.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | authorinos.operator.authorino.kuadrant.io | — |  |
| 7 | Namespaces | KEEP |  | Namespace | — | openshift-rhcl | — |  |

### dns-operator

File: `dns-operator-final.json` | Schema v2 | 7 phases | 9 resources

| Phase | Name | Action | Group | Kind | Namespace | Name | UID | Explicit |
|-------|------|--------|-------|------|-----------|------|-----|----------|
| 1 | Freeze OLM | DELETE | operators.coreos.com | Subscription | openshift-rhcl | dns-operator-stable-redhat-operators-openshift-marketplace | cb88ae27... |  |
| 1 | Freeze OLM | KEEP | operators.coreos.com | ClusterServiceVersion | openshift-rhcl | dns-operator.v1.4.2 | d2d35c11... |  |
| 4 | Remove Operator controllers | DELETE | operators.coreos.com | ClusterServiceVersion | openshift-rhcl | dns-operator.v1.4.2 | d2d35c11... |  |
| 5 | Namespace cleanup | KEEP | operators.coreos.com | OperatorGroup | openshift-rhcl | rhcl-operator | 3746fb8a... |  |
| 5 | Namespace cleanup | REVIEW | coordination.k8s.io | Lease | openshift-rhcl | a3f98d6c.kuadrant.io | 308313cb... |  |
| 5 | Namespace cleanup | REVIEW |  | ConfigMap | openshift-rhcl | dns-operator-controller-env | a1af0a04... |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | dnshealthcheckprobes.kuadrant.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | dnsrecords.kuadrant.io | — |  |
| 7 | Namespaces | KEEP |  | Namespace | — | openshift-rhcl | — |  |

### limitador-operator

File: `limitador-operator-final.json` | Schema v2 | 7 phases | 8 resources

| Phase | Name | Action | Group | Kind | Namespace | Name | UID | Explicit |
|-------|------|--------|-------|------|-----------|------|-----|----------|
| 1 | Freeze OLM | DELETE | operators.coreos.com | Subscription | openshift-rhcl | limitador-operator-stable-redhat-operators-openshift-marketplace | 8708f6aa... |  |
| 1 | Freeze OLM | KEEP | operators.coreos.com | ClusterServiceVersion | openshift-rhcl | limitador-operator.v1.4.2 | 4e6c692f... |  |
| 4 | Remove Operator controllers | DELETE | operators.coreos.com | ClusterServiceVersion | openshift-rhcl | limitador-operator.v1.4.2 | 4e6c692f... |  |
| 5 | Namespace cleanup | DELETE | operators.coreos.com | OperatorGroup | openshift-rhcl | rhcl-operator | 3746fb8a... |  |
| 5 | Namespace cleanup | REVIEW | coordination.k8s.io | Lease | openshift-rhcl | 3745a16e.kuadrant.io | 66914f7d... |  |
| 5 | Namespace cleanup | REVIEW |  | ConfigMap | openshift-rhcl | limitador-operator-manager-config | a3f25092... |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | limitadors.limitador.kuadrant.io | — |  |
| 7 | Namespaces | KEEP |  | Namespace | — | openshift-rhcl | — |  |

### cluster-observability-operator

File: `cluster-observability-operator-final.json` | Schema v2 | 7 phases | 32 resources

| Phase | Name | Action | Group | Kind | Namespace | Name | UID | Explicit |
|-------|------|--------|-------|------|-----------|------|-----|----------|
| 1 | Freeze OLM | DELETE | operators.coreos.com | Subscription | openshift-cluster-observability-operator | cluster-observability-operator | 11ffa38f... |  |
| 1 | Freeze OLM | KEEP | operators.coreos.com | ClusterServiceVersion | openshift-cluster-observability-operator | cluster-observability-operator.v1.5.2 | 133506cd... |  |
| 2 | Trigger operand cleanup | DELETE | observability.openshift.io | UIPlugin | — | monitoring | 1362af41... |  |
| 2 | Trigger operand cleanup | EXPECT | perses.dev | Perses | openshift-cluster-observability-operator | perses | 1d151267... |  |
| 2 | Trigger operand cleanup | EXPECT | perses.dev | PersesDashboard | openshift-cluster-observability-operator | accelerators-dashboard | ccde2f90... |  |
| 2 | Trigger operand cleanup | EXPECT | perses.dev | PersesDashboard | openshift-cluster-observability-operator | apm-dashboard | 45c36877... |  |
| 2 | Trigger operand cleanup | EXPECT | perses.dev | PersesDatasource | openshift-cluster-observability-operator | accelerators-thanos-querier-datasource | 58b01efa... |  |
| 2 | Trigger operand cleanup | DELETE | monitoring.rhobs | ScrapeConfig | redhat-ods-monitoring | maas-limitador | 333a1ef5... |  |
| 2 | Trigger operand cleanup | DELETE | perses.dev | PersesDashboard | openshift-cluster-observability-operator | maas-gateway-gpu-resources | f89966c9... |  |
| 2 | Trigger operand cleanup | DELETE | perses.dev | PersesDashboard | openshift-cluster-observability-operator | maas-gateway-performance | 24644bc8... |  |
| 2 | Trigger operand cleanup | DELETE | perses.dev | PersesGlobalDatasource | — | thanos-querier-datasource | 05d6fa68... |  |
| 4 | Remove Operator controllers | DELETE | operators.coreos.com | ClusterServiceVersion | openshift-cluster-observability-operator | cluster-observability-operator.v1.5.2 | 133506cd... |  |
| 5 | Namespace cleanup | DELETE | operators.coreos.com | OperatorGroup | openshift-cluster-observability-operator | cluster-observability-operator | a349fca8... |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | alertmanagerconfigs.monitoring.rhobs | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | alertmanagers.monitoring.rhobs | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | monitoringstacks.monitoring.rhobs | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | observabilityinstallers.observability.openshift.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | perses.perses.dev | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | persesdashboards.perses.dev | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | persesdatasources.perses.dev | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | persesglobaldatasources.perses.dev | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | podmonitors.monitoring.rhobs | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | probes.monitoring.rhobs | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | prometheusagents.monitoring.rhobs | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | prometheuses.monitoring.rhobs | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | prometheusrules.monitoring.rhobs | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | scrapeconfigs.monitoring.rhobs | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | servicemonitors.monitoring.rhobs | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | thanosqueriers.monitoring.rhobs | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | thanosrulers.monitoring.rhobs | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | uiplugins.observability.openshift.io | — |  |
| 7 | Namespaces | KEEP |  | Namespace | — | openshift-cluster-observability-operator | — |  |

### opentelemetry-product

File: `opentelemetry-product-final.json` | Schema v2 | 7 phases | 10 resources

| Phase | Name | Action | Group | Kind | Namespace | Name | UID | Explicit |
|-------|------|--------|-------|------|-----------|------|-----|----------|
| 1 | Freeze OLM | DELETE | operators.coreos.com | Subscription | openshift-opentelemetry-operator | opentelemetry-product | 9ddaf544... |  |
| 1 | Freeze OLM | KEEP | operators.coreos.com | ClusterServiceVersion | openshift-opentelemetry-operator | opentelemetry-operator.v0.158.0-2 | 9dfd524f... |  |
| 4 | Remove Operator controllers | DELETE | operators.coreos.com | ClusterServiceVersion | openshift-opentelemetry-operator | opentelemetry-operator.v0.158.0-2 | 9dfd524f... |  |
| 5 | Namespace cleanup | DELETE | operators.coreos.com | OperatorGroup | openshift-opentelemetry-operator | opentelemetry-product | 99faa08d... |  |
| 5 | Namespace cleanup | REVIEW | coordination.k8s.io | Lease | openshift-opentelemetry-operator | 9f7554c3.opentelemetry.io | f3002242... |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | instrumentations.opentelemetry.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | opampbridges.opentelemetry.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | opentelemetrycollectors.opentelemetry.io | — |  |
| 6 | APIs | KEEP | apiextensions.k8s.io | CustomResourceDefinition | — | targetallocators.opentelemetry.io | — |  |
| 7 | Namespaces | KEEP |  | Namespace | — | openshift-opentelemetry-operator | — |  |

