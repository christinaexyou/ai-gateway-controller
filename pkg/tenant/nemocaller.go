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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/yaml"

	aigatewayv1alpha1 "github.com/opendatahub-io/ai-gateway-controller/api/aigateway/v1alpha1"
	"github.com/opendatahub-io/ai-gateway-controller/pkg/guardrail"
)

const (
	// nemoCalloutConfigAnnotation rolls the post-auth pod when the compiled
	// callouts change. Praxis reads extproc.yaml only at start.
	nemoCalloutConfigAnnotation = "aigateway.opendatahub.io/nemo-callouts-sha256"

	// nemoServerPort is the NeMo server's pod port. Its Service maps port 80
	// to it; OpenShift matches NetworkPolicy egress against the pod port.
	nemoServerPort int64 = 8000

	nemoChecksPath = "/v1/checks"
)

// errUncompilableCallout is returned, joined with one error per policy, when
// an accepted AIGuardrail cannot be compiled. The callouts returned alongside
// it are the policies that compiled; one bad policy does not drop the others.
var errUncompilableCallout = errors.New("accepted AIGuardrail cannot be compiled")

// nemoCallout is one accepted AIGuardrail. Each of its checks is compiled
// as its own ai_guardrails filter on the shared post-auth ExtProc.
type nemoCallout struct {
	name     string
	endpoint string
	// serviceNamespace is where the NeMo Service runs; egress is opened to it.
	serviceNamespace string
	timeout          time.Duration
	checks           []nemoCheck
}

// nemoCheck is one AIGuardrail check. Request and response are the Input
// and Output phases. A check with both phases is compiled twice so the
// response path can run in reverse catalog order.
type nemoCheck struct {
	configID string
	// header turns the check on for a request when its value is "true".
	header   string
	request  bool
	response bool
}

// nemoFilter is one compiled ai_guardrails entry. Exactly one of request
// or response is set.
type nemoFilter struct {
	endpoint string
	configID string
	header   string
	timeout  time.Duration
	request  bool
	response bool
}

// acceptedNemoCallouts returns the tenant's current accepted NeMo callouts.
// A refused, stale, deleting, or endpoint-less policy is left out. A policy
// that cannot be compiled is also left out and reported through
// errUncompilableCallout, so the caller can surface it without dropping the
// policies that did compile or failing the rest of the tenant.
func acceptedNemoCallouts(ctx context.Context, reader client.Reader, tenantNamespace string) ([]nemoCallout, error) {
	var policies aigatewayv1alpha1.AIGuardrailList
	if err := reader.List(ctx, &policies, client.InNamespace(tenantNamespace)); err != nil {
		return nil, fmt.Errorf("list AIGuardrails in %s: %w", tenantNamespace, err)
	}
	callouts := make([]nemoCallout, 0, len(policies.Items))
	var rejected []error
	for i := range policies.Items {
		policy := &policies.Items[i]
		if policy.Status.ProviderEndpoint == "" {
			continue
		}
		callout, err := nemoCalloutFrom(policy)
		if err != nil {
			rejected = append(rejected, err)
			continue
		}
		callouts = append(callouts, callout)
	}
	sort.Slice(callouts, func(i, j int) bool { return callouts[i].name < callouts[j].name })
	if len(rejected) > 0 {
		return callouts, fmt.Errorf("%w: %w", errUncompilableCallout, errors.Join(rejected...))
	}
	return callouts, nil
}

// HasNemoCallouts reports whether the tenant post-auth ExtProc compiles at
// least one NeMo check. ExternalModel routes keep that filter enabled only
// then.
func HasNemoCallouts(ctx context.Context, reader client.Reader, tenantNamespace string) (bool, error) {
	callouts, err := acceptedNemoCallouts(ctx, reader, tenantNamespace)
	if err != nil && !errors.Is(err, errUncompilableCallout) {
		return false, err
	}
	return len(callouts) > 0, nil
}

// nemoCalloutInputs is everything acceptedNemoCallouts reads from a policy.
type nemoCalloutInputs struct {
	generation int64
	deleting   bool
	accepted   bool
	revision   string
	endpoint   string
}

func calloutInputs(policy *aigatewayv1alpha1.AIGuardrail) nemoCalloutInputs {
	return nemoCalloutInputs{
		generation: policy.Generation,
		deleting:   !policy.DeletionTimestamp.IsZero(),
		accepted:   guardrail.BindingAccepted(policy),
		revision:   policy.Status.BindingRevision,
		endpoint:   policy.Status.ProviderEndpoint,
	}
}

// NemoCalloutChanged drops AIGuardrail updates that cannot change the
// compiled callouts, such as condition timestamps and finalizer patches.
func NemoCalloutChanged() predicate.Funcs {
	return predicate.Funcs{UpdateFunc: func(e event.UpdateEvent) bool {
		before, okBefore := e.ObjectOld.(*aigatewayv1alpha1.AIGuardrail)
		after, okAfter := e.ObjectNew.(*aigatewayv1alpha1.AIGuardrail)
		if !okBefore || !okAfter {
			return true
		}
		return calloutInputs(before) != calloutInputs(after)
	}}
}

func nemoCalloutFrom(policy *aigatewayv1alpha1.AIGuardrail) (nemoCallout, error) {
	if guardrail.ProviderTimeoutTooFine(policy.Spec.Provider.Timeout.Duration) {
		return nemoCallout{}, fmt.Errorf("AIGuardrail %s/%s timeout %s is below 1ms", policy.Namespace, policy.Name, policy.Spec.Provider.Timeout.Duration)
	}
	namespace, err := nemoServiceNamespace(policy.Status.ProviderEndpoint, policy.Spec.Provider.Nemo.Ref.Name)
	if err != nil {
		return nemoCallout{}, err
	}
	callout := nemoCallout{
		name:             policy.Name,
		endpoint:         policy.Status.ProviderEndpoint,
		serviceNamespace: namespace,
		timeout:          policy.Spec.Provider.Timeout.Duration,
	}
	for _, check := range policy.Spec.Checks {
		if check.ConfigID == "" {
			return nemoCallout{}, fmt.Errorf("AIGuardrail %s/%s check %q has an empty configId", policy.Namespace, policy.Name, check.Name)
		}
		compiled := nemoCheck{
			configID: check.ConfigID,
			header:   guardrail.CheckHeaderName(policy.Namespace, policy.Name, check.Name),
		}
		for _, phase := range check.Phases {
			switch phase {
			case aigatewayv1alpha1.GuardrailPhaseInput:
				compiled.request = true
			case aigatewayv1alpha1.GuardrailPhaseOutput:
				compiled.response = true
			default:
				return nemoCallout{}, fmt.Errorf("AIGuardrail %s/%s check %q has unknown phase %q", policy.Namespace, policy.Name, check.Name, phase)
			}
		}
		if !compiled.request && !compiled.response {
			return nemoCallout{}, fmt.Errorf("AIGuardrail %s/%s check %q has no compilable phase", policy.Namespace, policy.Name, check.Name)
		}
		callout.checks = append(callout.checks, compiled)
	}
	if len(callout.checks) == 0 {
		return nemoCallout{}, fmt.Errorf("AIGuardrail %s/%s has no compilable checks", policy.Namespace, policy.Name)
	}
	return callout, nil
}

// nemoServiceNamespace returns the namespace of the referenced provider's
// http Service that endpoint addresses. Anything else is refused: the egress
// rule opened for the callout is scoped to that namespace.
func nemoServiceNamespace(endpoint, provider string) (string, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", fmt.Errorf("provider endpoint %q is not a plain base URL", endpoint)
	}
	if parsed.Scheme != "http" {
		return "", fmt.Errorf("provider endpoint %q must be http", endpoint)
	}
	if port := parsed.Port(); port != "" && port != "80" {
		return "", fmt.Errorf("provider endpoint %q must use the Service's port 80", endpoint)
	}
	switch strings.TrimSuffix(parsed.Path, "/") {
	case "", nemoChecksPath:
	default:
		return "", fmt.Errorf("provider endpoint %q must be the NeMo base URL", endpoint)
	}
	// The provider name is a DNS subdomain, so it may contain dots. Cutting the
	// host at the first dot would treat "my.rails.infra.svc" as service "my".
	host := strings.TrimSuffix(parsed.Hostname(), ".cluster.local")
	namespace, svc, _ := strings.Cut(strings.TrimPrefix(host, provider+"."), ".")
	if !strings.HasPrefix(host, provider+".") || svc != "svc" || len(validation.IsDNS1123Label(namespace)) > 0 {
		return "", fmt.Errorf("provider endpoint %q is not the in-cluster Service of NemoGuardrails %q", endpoint, provider)
	}
	return namespace, nil
}

// checksEndpoint is the NeMo checks URL Praxis posts to. status.providerEndpoint
// is the server base URL; a value that already ends at /v1/checks is kept.
func checksEndpoint(endpoint string) (string, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	parsed.Path = nemoChecksPath
	parsed.RawPath = ""
	return parsed.String(), nil
}

// configureNemoCallouts compiles the callouts into the post-auth extproc.yaml
// and opens egress to each NeMo namespace. With no callouts the rendered
// resources are left as they are.
func configureNemoCallouts(resources []unstructured.Unstructured, tenantID, gatewayNamespace string, callouts []nemoCallout) error {
	if len(callouts) == 0 {
		return nil
	}
	deploymentName := PayloadProcessingDeploymentName(tenantID)
	deployment := findResource(resources, "Deployment", deploymentName, gatewayNamespace)
	if deployment == nil {
		return fmt.Errorf("payload-processing Deployment %s is missing", deploymentName)
	}
	configMapName := PayloadProcessingPluginsConfigMapForTenant(tenantID)
	configMap := findResource(resources, "ConfigMap", configMapName, gatewayNamespace)
	if configMap == nil {
		return fmt.Errorf("payload-processing ConfigMap %s is missing", configMapName)
	}
	data, found, err := unstructured.NestedStringMap(configMap.Object, "data")
	if err != nil || !found {
		if err == nil {
			err = errors.New("data is missing")
		}
		return fmt.Errorf("read payload-processing ConfigMap: %w", err)
	}
	compiled, err := compileNemoExtproc(data["extproc.yaml"], callouts)
	if err != nil {
		return err
	}
	data["extproc.yaml"] = compiled
	if err := unstructured.SetNestedStringMap(configMap.Object, data, "data"); err != nil {
		return fmt.Errorf("write payload-processing ConfigMap: %w", err)
	}
	if err := ensureNemoEgress(resources, tenantID, gatewayNamespace, callouts); err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(compiled))
	if err := unstructured.SetNestedField(deployment.Object, hex.EncodeToString(sum[:]), "spec", "template", "metadata", "annotations", nemoCalloutConfigAnnotation); err != nil {
		return fmt.Errorf("write NeMo callout config hash: %w", err)
	}
	return nil
}

// compileNemoExtproc inserts the checks right after the post-auth chain's
// request_id filter and opts the config into private upstreams, which the
// in-cluster NeMo Service needs. Each check runs only when its selection
// header is "true". A headers filter after the checks removes those
// headers so they are not forwarded to the model.
func compileNemoExtproc(config string, callouts []nemoCallout) (string, error) {
	if len(callouts) == 0 {
		return config, nil
	}
	sorted := append([]nemoCallout(nil), callouts...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].name < sorted[j].name })
	filters, err := expandNemoChecks(sorted)
	if err != nil {
		return "", err
	}
	compiled := make([]any, 0, len(filters)+1)
	seen := map[string]bool{}
	headers := make([]any, 0, len(filters))
	for _, filter := range filters {
		compiled = append(compiled, nemoFilterEntry(filter))
		if !seen[filter.header] {
			seen[filter.header] = true
			headers = append(headers, filter.header)
		}
	}
	compiled = append(compiled, map[string]any{"filter": "headers", "request_remove": headers})

	var doc map[string]any
	if err := yaml.Unmarshal([]byte(config), &doc); err != nil {
		return "", fmt.Errorf("parse post-auth extproc.yaml: %w", err)
	}
	if !insertAfterRequestID(doc, compiled) {
		return "", errors.New("post-auth extproc.yaml has no request_id filter")
	}
	insecure, _ := doc["insecure_options"].(map[string]any)
	if insecure == nil {
		insecure = map[string]any{}
		doc["insecure_options"] = insecure
	}
	insecure["allow_private_upstreams"] = true
	out, err := yaml.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("write post-auth extproc.yaml: %w", err)
	}
	return string(out), nil
}

func insertAfterRequestID(doc map[string]any, entries []any) bool {
	chains, _ := doc["filter_chains"].([]any)
	for _, item := range chains {
		chain, ok := item.(map[string]any)
		if !ok {
			continue
		}
		filters, _ := chain["filters"].([]any)
		for i, filter := range filters {
			if entry, ok := filter.(map[string]any); !ok || entry["filter"] != "request_id" {
				continue
			}
			out := make([]any, 0, len(filters)+len(entries))
			out = append(out, filters[:i+1]...)
			out = append(out, entries...)
			chain["filters"] = append(out, filters[i+1:]...)
			return true
		}
	}
	return false
}

// nemoFilterEntry runs one check when its selection header is "true". A
// request that skips the check also skips its response hook. The model is
// omitted so NeMo calls the model named in the selected configuration
// rather than a name this controller invents.
func nemoFilterEntry(filter nemoFilter) map[string]any {
	provider := map[string]any{
		"type":       "nemo",
		"endpoint":   filter.endpoint,
		"guardrails": map[string]any{"config_ids": []any{filter.configID}},
	}
	// A positive duration below 1ms truncates to 0, which Praxis rejects.
	// nemoCalloutFrom already excludes that policy; this keeps a missed
	// check from writing timeout_ms: 0 into the shared config.
	if ms := filter.timeout.Milliseconds(); ms > 0 {
		provider["timeout_ms"] = ms
	}
	return map[string]any{
		"filter": "ai_guardrails",
		"conditions": []any{map[string]any{
			"when": map[string]any{"headers": map[string]any{filter.header: "true"}},
		}},
		"provider": provider,
		"phase":    map[string]any{"request": filter.request, "response": filter.response},
	}
}

// expandNemoChecks emits one filter per phase. Input entries stay in
// policy-name and spec.checks order. Output entries are appended in the
// reverse of that order.
func expandNemoChecks(callouts []nemoCallout) ([]nemoFilter, error) {
	forward := make([]nemoFilter, 0, len(callouts))
	output := make([]nemoFilter, 0, len(callouts))
	for _, callout := range callouts {
		endpoint, err := checksEndpoint(callout.endpoint)
		if err != nil {
			return nil, fmt.Errorf("AIGuardrail %s: %w", callout.name, err)
		}
		for _, check := range callout.checks {
			filter := nemoFilter{endpoint: endpoint, configID: check.configID, header: check.header, timeout: callout.timeout}
			if check.request {
				input := filter
				input.request = true
				forward = append(forward, input)
			}
			if check.response {
				filter.response = true
				output = append(output, filter)
			}
		}
	}
	for i := len(output) - 1; i >= 0; i-- {
		forward = append(forward, output[i])
	}
	if len(forward) == 0 {
		return nil, errors.New("accepted guardrails have no compilable checks")
	}
	return forward, nil
}

// ensureNemoEgress opens TCP 8000 from the post-auth pod to each NeMo
// namespace. The vendored NetworkPolicy allows the API server ports only. A
// missing policy is left alone: SkipNetworkPolicy removes it before this
// runs.
func ensureNemoEgress(resources []unstructured.Unstructured, tenantID, gatewayNamespace string, callouts []nemoCallout) error {
	policy := findResource(resources, "NetworkPolicy", PayloadProcessingNetworkPolicyName(tenantID), gatewayNamespace)
	if policy == nil {
		return nil
	}
	egress, _, err := unstructured.NestedSlice(policy.Object, "spec", "egress")
	if err != nil {
		return fmt.Errorf("read payload-processing NetworkPolicy egress: %w", err)
	}
	namespaces := map[string]struct{}{}
	for _, callout := range callouts {
		namespaces[callout.serviceNamespace] = struct{}{}
	}
	sorted := make([]string, 0, len(namespaces))
	for namespace := range namespaces {
		sorted = append(sorted, namespace)
	}
	sort.Strings(sorted)
	peers := make([]any, 0, len(sorted))
	for _, namespace := range sorted {
		peers = append(peers, map[string]any{
			"namespaceSelector": map[string]any{
				"matchLabels": map[string]any{"kubernetes.io/metadata.name": namespace},
			},
		})
	}
	egress = append(egress, map[string]any{
		"to":    peers,
		"ports": []any{map[string]any{"protocol": "TCP", "port": nemoServerPort}},
	})
	if err := unstructured.SetNestedSlice(policy.Object, egress, "spec", "egress"); err != nil {
		return fmt.Errorf("write payload-processing NetworkPolicy egress: %w", err)
	}
	return nil
}

func findResource(resources []unstructured.Unstructured, kind, name, namespace string) *unstructured.Unstructured {
	for i := range resources {
		resource := &resources[i]
		if resource.GetKind() == kind && resource.GetName() == name && resource.GetNamespace() == namespace {
			return resource
		}
	}
	return nil
}
