/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package tenant

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/yaml"

	aigatewayv1alpha1 "github.com/opendatahub-io/ai-gateway-controller/api/aigateway/v1alpha1"
	"github.com/opendatahub-io/ai-gateway-controller/pkg/guardrail"
)

var updateNemoContract = flag.Bool("update", false, "rewrite test/testdata/nemo-callout-contract")

const postAuthExtproc = `server:
  grpc_address: "0.0.0.0:9004"
filter_chains:
  - name: ipp
    filters:
      - filter: request_id

insecure_options:
  allow_unbounded_body: true
`

func TestConfigureNemoCalloutsWithoutAcceptance(t *testing.T) {
	resources := nemoCalloutFixtures("red", "gw")
	if err := configureNemoCallouts(resources, "red", "gw", nil); err != nil {
		t.Fatalf("configureNemoCallouts: %v", err)
	}
	if data, _, _ := unstructured.NestedStringMap(resources[3].Object, "data"); data["extproc.yaml"] != postAuthExtproc {
		t.Fatalf("extproc.yaml changed without accepted callouts:\n%s", data["extproc.yaml"])
	}
	if egress, _, _ := unstructured.NestedSlice(resources[2].Object, "spec", "egress"); len(egress) != 1 {
		t.Fatalf("egress = %v, want the rendered rule only", egress)
	}
	if _, found, _ := unstructured.NestedString(resources[0].Object, "spec", "template", "metadata", "annotations", nemoCalloutConfigAnnotation); found {
		t.Fatal("pod template was annotated without callouts")
	}
}

func TestConfigureNemoCalloutsCompilesAcceptedEndpoint(t *testing.T) {
	resources := nemoCalloutFixtures("red", "gw")
	callouts := []nemoCallout{
		{name: "zeta", endpoint: "http://zeta.other.svc", serviceNamespace: "other", checks: []nemoCheck{{configID: "zeta-v1", header: "h-zeta", response: true}}},
		{name: "alpha", endpoint: "http://nemo.infra.svc.cluster.local", serviceNamespace: "infra", timeout: 5 * time.Second, checks: []nemoCheck{
			{configID: "pii-v1", header: "h-pii", request: true},
			{configID: "jailbreak-v1", header: "h-jailbreak", request: true},
		}},
		{name: "beta", endpoint: "http://nemo.infra.svc.cluster.local/v1/checks", serviceNamespace: "infra", checks: []nemoCheck{
			{configID: "toxicity-v1", header: "h-toxicity", request: true, response: true},
		}},
	}
	if err := configureNemoCallouts(resources, "red", "gw", callouts); err != nil {
		t.Fatalf("configureNemoCallouts: %v", err)
	}
	data, _, _ := unstructured.NestedStringMap(findResource(resources, "ConfigMap", PayloadProcessingPluginsConfigMapForTenant("red"), "gw").Object, "data")
	config := data["extproc.yaml"]
	if data["pre-extproc.yaml"] != "pre" {
		t.Fatal("pre-auth config was rewritten")
	}
	doc, filters := parseCompiled(t, config)
	if first, _ := filters[0].(map[string]any); first["filter"] != "request_id" {
		t.Fatalf("request_id is no longer the first filter:\n%s", config)
	}
	const infra = "http://nemo.infra.svc.cluster.local/v1/checks"
	type compiledCheck struct {
		configID, endpoint, header string
		request, response          bool
	}
	want := []compiledCheck{
		{"pii-v1", infra, "h-pii", true, false},
		{"jailbreak-v1", infra, "h-jailbreak", true, false},
		{"toxicity-v1", infra, "h-toxicity", true, false},
		{"zeta-v1", "http://zeta.other.svc/v1/checks", "h-zeta", false, true},
		{"toxicity-v1", infra, "h-toxicity", false, true},
	}
	if len(filters) != len(want)+2 {
		t.Fatalf("filters = %d, want request_id, %d checks and the header cleanup:\n%s", len(filters), len(want), config)
	}
	for i, w := range want {
		entry, _ := filters[i+1].(map[string]any)
		provider, _ := entry["provider"].(map[string]any)
		phase, _ := entry["phase"].(map[string]any)
		guardrails, _ := provider["guardrails"].(map[string]any)
		ids, _ := guardrails["config_ids"].([]any)
		if entry["filter"] != "ai_guardrails" || provider["type"] != "nemo" || len(ids) != 1 || ids[0] != w.configID ||
			provider["endpoint"] != w.endpoint || phase["request"] != w.request || phase["response"] != w.response {
			t.Fatalf("check %d = %v, want %+v (input order, then reversed output order)", i, entry, w)
		}
		if provider["model"] != nemoCheckModel {
			t.Fatalf("check %d model = %v, want %s", i, provider["model"], nemoCheckModel)
		}
		conditions, _ := entry["conditions"].([]any)
		var when map[string]any
		if len(conditions) == 1 {
			when, _ = conditions[0].(map[string]any)["when"].(map[string]any)
		}
		headers, _ := when["headers"].(map[string]any)
		if len(headers) != 1 || headers[w.header] != "true" {
			t.Fatalf("check %d conditions = %v, want it to run only when %s is \"true\"", i, entry["conditions"], w.header)
		}
		_, hasTimeout := provider["timeout_ms"]
		if hasTimeout != (w.endpoint == infra && w.configID != "toxicity-v1") {
			t.Fatalf("check %d timeout_ms = %v, want it only on the policy that sets one", i, provider["timeout_ms"])
		}
	}
	cleanup, _ := filters[len(filters)-1].(map[string]any)
	removed, _ := cleanup["request_remove"].([]any)
	wantRemoved := []any{"h-pii", "h-jailbreak", "h-toxicity", "h-zeta"}
	if cleanup["filter"] != "headers" || len(removed) != len(wantRemoved) {
		t.Fatalf("last filter = %v, want a headers filter removing %v", cleanup, wantRemoved)
	}
	for i := range wantRemoved {
		if removed[i] != wantRemoved[i] {
			t.Fatalf("request_remove = %v, want each selection header once: %v", removed, wantRemoved)
		}
	}
	insecure, _ := doc["insecure_options"].(map[string]any)
	if insecure["allow_private_upstreams"] != true || insecure["allow_unbounded_body"] != true {
		t.Fatalf("insecure_options = %v, want private upstreams added and unbounded body kept", insecure)
	}

	egress, _, _ := unstructured.NestedSlice(findResource(resources, "NetworkPolicy", PayloadProcessingNetworkPolicyName("red"), "gw").Object, "spec", "egress")
	if len(egress) != 2 {
		t.Fatalf("egress = %v, want the rendered rule plus one NeMo rule", egress)
	}
	rule, _ := egress[1].(map[string]any)
	ports, _ := rule["ports"].([]any)
	port, _ := ports[0].(map[string]any)
	if len(ports) != 1 || port["port"] != nemoServerPort || port["protocol"] != "TCP" {
		t.Fatalf("NeMo egress ports = %v, want TCP %d", ports, nemoServerPort)
	}
	var namespaces []string
	peers, _ := rule["to"].([]any)
	for _, peer := range peers {
		labels, _, _ := unstructured.NestedStringMap(peer.(map[string]any), "namespaceSelector", "matchLabels")
		namespaces = append(namespaces, labels["kubernetes.io/metadata.name"])
	}
	if len(namespaces) != 2 || namespaces[0] != "infra" || namespaces[1] != "other" {
		t.Fatalf("NeMo egress namespaces = %v, want [infra other]", namespaces)
	}

	hash, _, _ := unstructured.NestedString(findResource(resources, "Deployment", PayloadProcessingDeploymentName("red"), "gw").Object,
		"spec", "template", "metadata", "annotations", nemoCalloutConfigAnnotation)
	if hash == "" {
		t.Fatal("post-auth pod template has no config hash; Praxis would keep the old extproc.yaml")
	}
	if _, found, _ := unstructured.NestedString(findResource(resources, "Deployment", PayloadPreProcessingDeploymentName("red"), "gw").Object,
		"spec", "template", "metadata", "annotations", nemoCalloutConfigAnnotation); found {
		t.Fatal("pre-auth pod was annotated")
	}
}

func TestConfigureNemoCalloutsWithoutNetworkPolicy(t *testing.T) {
	resources := nemoCalloutFixtures("red", "gw")
	resources = append(resources[:2], resources[3])
	callouts := []nemoCallout{{name: "safety", endpoint: "http://nemo.infra.svc", serviceNamespace: "infra", checks: []nemoCheck{{configID: "pii-v1", request: true}}}}
	if err := configureNemoCallouts(resources, "red", "gw", callouts); err != nil {
		t.Fatalf("configureNemoCallouts without a NetworkPolicy: %v", err)
	}
}

func TestCompileNemoExtprocRequiresRequestIDFilter(t *testing.T) {
	callouts := []nemoCallout{{name: "safety", endpoint: "http://nemo.infra.svc", checks: []nemoCheck{{configID: "pii-v1", request: true}}}}
	if _, err := compileNemoExtproc("filter_chains:\n  - name: ipp\n    filters: []\n", callouts); err == nil {
		t.Fatal("compiled checks into a chain with no request_id anchor")
	}
	if _, err := compileNemoExtproc("filter_chains: [", callouts); err == nil {
		t.Fatal("compiled checks into an unparseable config")
	}
}

func TestNemoCalloutChangedIgnoresConditionChurn(t *testing.T) {
	before := acceptedPolicy("safety", 3, 3, "http://nemo.infra.svc")
	after := before.DeepCopy()
	after.Status.Conditions[0].LastTransitionTime = metav1.Now()
	after.Status.Conditions = append(after.Status.Conditions, metav1.Condition{Type: guardrail.ConditionProviderReady, Status: metav1.ConditionTrue})
	after.Finalizers = []string{"x"}
	if NemoCalloutChanged().Update(event.UpdateEvent{ObjectOld: before, ObjectNew: after}) {
		t.Fatal("a condition timestamp or finalizer change requeued the tenant")
	}
	for name, mutate := range map[string]func(*aigatewayv1alpha1.AIGuardrail){
		"generation": func(p *aigatewayv1alpha1.AIGuardrail) { p.Generation++ },
		"accepted":   func(p *aigatewayv1alpha1.AIGuardrail) { p.Status.Conditions[0].Status = metav1.ConditionFalse },
		"revision":   func(p *aigatewayv1alpha1.AIGuardrail) { p.Status.BindingRevision = "rev2" },
		"endpoint":   func(p *aigatewayv1alpha1.AIGuardrail) { p.Status.ProviderEndpoint = "http://nemo.moved.svc" },
		"deleting":   func(p *aigatewayv1alpha1.AIGuardrail) { now := metav1.Now(); p.DeletionTimestamp = &now },
	} {
		changed := before.DeepCopy()
		mutate(changed)
		if !NemoCalloutChanged().Update(event.UpdateEvent{ObjectOld: before, ObjectNew: changed}) {
			t.Errorf("%s change did not requeue the tenant", name)
		}
	}
}

// TestNemoCalloutContract pins the post-auth extproc.yaml the controller
// compiles. Praxis builds a pipeline from the same file in its register
// tests (filters/testdata/ai-gateway-controller-extproc.yaml), so a field
// Praxis does not accept fails there. Regenerate with -update and copy the
// file to the Praxis repo in the same change.
func TestNemoCalloutContract(t *testing.T) {
	compiled, err := compileNemoExtproc(postAuthExtproc, []nemoCallout{{
		name:             "safety",
		endpoint:         "http://nemo.nemo-infra.svc.cluster.local",
		serviceNamespace: "nemo-infra",
		timeout:          5 * time.Second,
		checks: []nemoCheck{{
			configID: "pii-v1",
			header:   guardrail.CheckHeaderName("tenant-a", "safety", "pii"),
			request:  true,
			response: true,
		}},
	}})
	if err != nil {
		t.Fatalf("compileNemoExtproc: %v", err)
	}
	path := filepath.Join("..", "..", "test", "testdata", "nemo-callout-contract", "v1", "extproc.yaml")
	if *updateNemoContract {
		if err := os.WriteFile(path, []byte(compiled), 0o600); err != nil {
			t.Fatalf("write contract: %v", err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read contract: %v", err)
	}
	if string(want) != compiled {
		t.Fatalf("compiled extproc.yaml drifted from %s; rerun with -update and update the Praxis copy:\n%s", path, compiled)
	}
}

func TestAcceptedNemoCalloutsSkipsStalePolicy(t *testing.T) {
	current := acceptedPolicy("current", 3, 3, "http://nemo.infra.svc.cluster.local")
	stale := acceptedPolicy("stale", 4, 3, "http://nemo.infra.svc.cluster.local")
	refused := acceptedPolicy("refused", 3, 3, "http://nemo.infra.svc.cluster.local")
	refused.Status.Conditions[0].Status = metav1.ConditionFalse
	callouts := calloutsFor(t, current, stale, refused)
	if len(callouts) != 1 || callouts[0].name != "current" || len(callouts[0].checks) != 1 || !callouts[0].checks[0].request || callouts[0].checks[0].response {
		t.Fatalf("callouts = %#v, want only the current input policy", callouts)
	}
	if callouts[0].serviceNamespace != "infra" {
		t.Fatalf("namespace = %q, want infra from the Service host", callouts[0].serviceNamespace)
	}
}

// TestAcceptedNemoCalloutsUseCheckSelectionHeader pins that each check is
// keyed by the shared x-aigateway-guardrail-<id> header for its namespace,
// AIGuardrail name and check name, not its NeMo config ID.
func TestAcceptedNemoCalloutsUseCheckSelectionHeader(t *testing.T) {
	policy := acceptedPolicy("safety", 3, 3, "http://nemo.infra.svc")
	callouts := calloutsFor(t, policy)
	if len(callouts) != 1 || len(callouts[0].checks) != 1 {
		t.Fatalf("callouts = %#v, want one check", callouts)
	}
	if got, want := callouts[0].checks[0].header, guardrail.CheckHeaderName("tenant-a", "safety", "pii"); got != want {
		t.Fatalf("header = %q, want %q", got, want)
	}
	reader := fake.NewClientBuilder().WithScheme(mtcSchemeForTests()).WithObjects(policy).Build()
	if has, err := HasNemoCallouts(context.Background(), reader, "tenant-a"); err != nil || !has {
		t.Fatalf("HasNemoCallouts = %v, %v; want true", has, err)
	}
}

// TestAcceptedNemoCalloutsIsolatesBrokenPolicy pins that one policy that
// cannot be compiled is left out instead of failing the whole tenant.
func TestAcceptedNemoCalloutsIsolatesBrokenPolicy(t *testing.T) {
	good := acceptedPolicy("good", 3, 3, "http://nemo.infra.svc")
	broken := map[string]string{
		"external-host":  "http://attacker.example",
		"other-service":  "http://other.infra.svc",
		"bad-namespace":  "http://nemo.in_fra.svc",
		"wrong-port":     "http://nemo.infra.svc:8443",
		"pathed":         "http://nemo.infra.svc/proxy",
		"userinfo":       "http://user:pw@nemo.infra.svc",
		"query":          "http://nemo.infra.svc/?x=1",
		"other-scheme":   "ftp://nemo.infra.svc",
		"https":          "https://nemo.infra.svc",
		"not-a-svc-name": "http://nemo.infra.pod",
	}
	policies := []*aigatewayv1alpha1.AIGuardrail{good}
	for name, endpoint := range broken {
		policies = append(policies, acceptedPolicy(name, 3, 3, endpoint))
	}
	noConfig := acceptedPolicy("no-config", 3, 3, "http://nemo.infra.svc")
	noConfig.Spec.Checks[0].ConfigID = ""
	policies = append(policies, noConfig)
	callouts := calloutsFor(t, policies...)
	if len(callouts) != 1 || callouts[0].name != "good" {
		t.Fatalf("callouts = %#v, want only the valid policy", callouts)
	}
}

func parseCompiled(t *testing.T, config string) (map[string]any, []any) {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(config), &doc); err != nil {
		t.Fatalf("compiled extproc.yaml does not parse: %v\n%s", err, config)
	}
	chains, _ := doc["filter_chains"].([]any)
	chain, _ := chains[0].(map[string]any)
	filters, _ := chain["filters"].([]any)
	if len(filters) == 0 {
		t.Fatalf("compiled extproc.yaml has no filters:\n%s", config)
	}
	return doc, filters
}

func calloutsFor(t *testing.T, policies ...*aigatewayv1alpha1.AIGuardrail) []nemoCallout {
	t.Helper()
	builder := fake.NewClientBuilder().WithScheme(mtcSchemeForTests())
	for _, policy := range policies {
		builder = builder.WithObjects(policy)
	}
	callouts, err := acceptedNemoCallouts(context.Background(), builder.Build(), "tenant-a", logr.Discard())
	if err != nil {
		t.Fatalf("acceptedNemoCallouts: %v", err)
	}
	return callouts
}

// acceptedPolicy references NemoGuardrails "nemo" and has an Accepted
// condition observed at the given generation.
func acceptedPolicy(name string, generation, observed int64, endpoint string) *aigatewayv1alpha1.AIGuardrail {
	return &aigatewayv1alpha1.AIGuardrail{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "tenant-a", Generation: generation},
		Spec: aigatewayv1alpha1.AIGuardrailSpec{
			Provider: aigatewayv1alpha1.AIGuardrailProvider{
				Nemo: aigatewayv1alpha1.AIGuardrailNemoProvider{Ref: aigatewayv1alpha1.AIGuardrailNamespacedReference{Name: "nemo"}},
			},
			Checks: []aigatewayv1alpha1.AIGuardrailCheck{{
				Name: "pii", ConfigID: "pii-v1", Phases: []aigatewayv1alpha1.GuardrailPhase{aigatewayv1alpha1.GuardrailPhaseInput},
			}},
		},
		Status: aigatewayv1alpha1.AIGuardrailStatus{
			BindingRevision:  "rev",
			ProviderEndpoint: endpoint,
			Conditions: []metav1.Condition{{
				Type:               guardrail.ConditionAccepted,
				Status:             metav1.ConditionTrue,
				ObservedGeneration: observed,
			}},
		},
	}
}

// nemoCalloutFixtures returns the post-auth Deployment, the pre-auth
// Deployment, the NetworkPolicy and the plugins ConfigMap, in that order.
func nemoCalloutFixtures(tenantID, namespace string) []unstructured.Unstructured {
	deployment := deploymentFixture(PayloadProcessingDeploymentName(tenantID), PayloadProcessingName, PayloadProcessingServiceAccountName(tenantID), PayloadProcessingPluginsConfigMapForTenant(tenantID))
	deployment.SetNamespace(namespace)
	pre := deploymentFixture(PayloadPreProcessingDeploymentName(tenantID), PayloadPreProcessingName, PayloadProcessingServiceAccountName(tenantID), PayloadProcessingPluginsConfigMapForTenant(tenantID))
	pre.SetNamespace(namespace)
	policy := unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "networking.k8s.io/v1",
		"kind":       "NetworkPolicy",
		"metadata":   map[string]any{"name": PayloadProcessingNetworkPolicyName(tenantID), "namespace": namespace},
		"spec": map[string]any{
			"egress": []any{map[string]any{"ports": []any{map[string]any{"protocol": "TCP", "port": int64(6443)}}}},
		},
	}}
	configMap := unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata":   map[string]any{"name": PayloadProcessingPluginsConfigMapForTenant(tenantID), "namespace": namespace},
		"data":       map[string]any{"extproc.yaml": postAuthExtproc, "pre-extproc.yaml": "pre"},
	}}
	return []unstructured.Unstructured{deployment, pre, policy, configMap}
}
