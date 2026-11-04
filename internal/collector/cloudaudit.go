package collector

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"
)

const cloudMaxRecords = 10000
const cloudMaxRefs = 32

// CloudAuditOptions controls offline heuristic analysis. A burst is a fixed
// volume threshold, not a learned baseline or proof of unauthorized billing.
type CloudAuditOptions struct{ BurstThreshold int }

// ParseCloudAuditFiles imports only supplied files. It never contacts cloud
// APIs, invokes a model, follows a resource path, or retains request bodies.
func ParseCloudAuditFiles(ctx context.Context, paths []string, opts CloudAuditOptions) Result {
	r := NewResult("cloudaudit")
	if opts.BurstThreshold <= 0 {
		opts.BurstThreshold = 100
	}
	if opts.BurstThreshold > 100000 {
		opts.BurstThreshold = 100000
	}
	total, rejected, ignored, duplicates := 0, 0, 0, 0
	truncated := false
	seen := map[string]bool{}
	var sources []map[string]any
	if len(paths) > traceMaxFiles {
		paths = paths[:traceMaxFiles]
		truncated = true
	}
	for _, path := range paths {
		if ctx.Err() != nil {
			break
		}
		if total >= traceMaxTotalBytes || len(r.Records) >= cloudMaxRecords {
			truncated = true
			break
		}
		if st, err := os.Stat(path); err != nil || !st.Mode().IsRegular() {
			r.Fail(fmt.Sprintf("cloud audit file %q: unreadable or not regular", path))
			continue
		}
		data, err := readAgentTrace(path, min(int64(traceMaxBytes), int64(traceMaxTotalBytes-total)))
		total += len(data)
		if err != nil {
			r.Fail(fmt.Sprintf("cloud audit file %q: unreadable, oversized, changed or not regular", path))
			continue
		}
		sum := sha256.Sum256(data)
		hash := hex.EncodeToString(sum[:])
		sources = append(sources, map[string]any{"path": path, "sha256": hash, "bytes": len(data)})
		add := func(raw map[string]any, locator string, n int) {
			if ctx.Err() != nil {
				return
			}
			if len(r.Records) >= cloudMaxRecords {
				truncated = true
				return
			}
			f, supported := normalizeCloudEvent(raw)
			if !supported {
				ignored++
				return
			}
			if f == nil {
				rejected++
				return
			}
			key := cloudEventKey(f)
			if seen[key] {
				duplicates++
				return
			}
			seen[key] = true
			f["source_file"], f["source_sha256"], f[locator] = path, hash, n
			var fs []Finding
			if f["status"] == "success" {
				switch f["category"] {
				case "logging_disabled":
					fs = append(fs, Finding{"llm.logging_disabled", SevSuspect, "T1562.008", 65, "a supplied audit event reports successful deletion of model invocation logging configuration; verify authorization and remaining logging coverage"})
				case "enable":
					fs = append(fs, Finding{"llm.service_or_deployment_enabled", SevNotable, "T1496", 35, "a supplied audit event reports model-service enablement, access configuration or deployment creation/update; authorized provisioning has the same shape"})
				}
			}
			r.Add(f, fs...)
		}
		// JSON documents (native envelopes/arrays or a single event) and JSONL.
		var doc any
		d := json.NewDecoder(bytes.NewReader(data))
		d.UseNumber()
		var extra any
		if d.Decode(&doc) == nil && d.Decode(&extra) == io.EOF {
			cloudDocumentRows(doc, func(raw map[string]any, n int) { add(raw, "source_event", n) }, &rejected)
		} else {
			s := bufio.NewScanner(bytes.NewReader(data))
			s.Buffer(make([]byte, 4096), 4<<20)
			line := 0
			for s.Scan() {
				line++
				if ctx.Err() != nil || len(r.Records) >= cloudMaxRecords {
					truncated = true
					break
				}
				if len(bytes.TrimSpace(s.Bytes())) == 0 {
					continue
				}
				var raw map[string]any
				dec := json.NewDecoder(bytes.NewReader(s.Bytes()))
				dec.UseNumber()
				if dec.Decode(&raw) != nil || raw == nil || dec.Decode(&extra) != io.EOF {
					rejected++
					continue
				}
				add(raw, "source_line", line)
			}
			if s.Err() != nil {
				rejected++
				truncated = true
			}
		}
	}
	if ctx.Err() != nil {
		r.Fail("cloud import interrupted: " + ctx.Err().Error())
	}
	if rejected > 0 {
		r.Fail(fmt.Sprintf("%d malformed or invalid cloud event(s) omitted", rejected))
	}
	if len(r.Records) == 0 {
		r.Fail("no supported model-service audit events imported")
	}
	if truncated {
		r.Fail("cloud input limit reached; analysis covers only retained events")
	}
	r.SetMeta("imported_events", len(r.Records))
	if ctx.Err() == nil {
		analyzeCloudWindows(r, opts)
	}
	r.SetMeta("sources", sources)
	r.SetMeta("bytes_read", total)
	r.SetMeta("rejected_records", rejected)
	r.SetMeta("ignored_events", ignored)
	r.SetMeta("duplicate_events", duplicates)
	r.SetMeta("truncated", truncated)
	r.SetMeta("content_policy", "allowlisted audit metadata only; no prompts, responses, request/response bodies, API keys, headers or unknown fields")
	r.SetMeta("coverage", "supplied events only; absent data-plane logging, missing identity/region fields and collection gaps remain unknown; logs are not authenticated; rate thresholds do not establish compromise or billing impact")
	r.SetMeta("burst_threshold", opts.BurstThreshold)
	r.SetMeta("window", "5m")
	r.SetMeta("context_window", "30m")
	return r.Finish()
}

func cloudDocumentRows(doc any, add func(map[string]any, int), rejected *int) {
	var rows []any
	switch v := doc.(type) {
	case []any:
		rows = v
	case map[string]any:
		for _, key := range []string{"Records", "records", "entries"} {
			if a, ok := v[key].([]any); ok {
				rows = a
				break
			}
		}
		if rows == nil {
			add(v, 1)
			return
		}
	default:
		*rejected++
		return
	}
	for i, v := range rows {
		if raw, ok := v.(map[string]any); ok {
			add(raw, i+1)
		} else {
			*rejected++
		}
	}
}

func cloudMap(v any) map[string]any { m, _ := v.(map[string]any); return m }
func cloudName(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return stringField(cloudMap(v), "value")
}

// normalizeCloudEvent returns false for unrelated/unsupported events, and
// nil,true for a recognized but malformed event. Native stream-completion
// records and unfinished Azure operations never count as invocations.
func normalizeCloudEvent(raw map[string]any) (map[string]any, bool) {
	if raw == nil {
		return nil, false
	}
	provider, tenant, principal, region, service, op, resource, stamp, status, eventID, requestID, ip := "", "", "", "", "", "", "", "", "unknown", "", "", ""
	switch {
	case raw["provider"] != nil:
		provider = strings.ToLower(stringField(raw, "provider"))
		tenant = stringField(raw, "tenant")
		principal = stringField(raw, "principal")
		region = stringField(raw, "region")
		service = stringField(raw, "service")
		op = stringField(raw, "operation")
		resource = stringField(raw, "resource")
		stamp = stringField(raw, "timestamp")
		status = stringField(raw, "status")
		eventID = stringField(raw, "event_id")
		requestID = stringField(raw, "request_id")
		ip = stringField(raw, "source_ip")
	case raw["eventSource"] != nil:
		if stringField(raw, "eventType") != "AwsApiCall" {
			return nil, false
		}
		provider = "aws"
		identity := cloudMap(raw["userIdentity"])
		tenant = firstNonEmpty(stringField(raw, "recipientAccountId"), stringField(identity, "accountId"))
		principal = firstNonEmpty(stringField(identity, "arn"), stringField(identity, "principalId"))
		region = stringField(raw, "awsRegion")
		service = stringField(raw, "eventSource")
		op = stringField(raw, "eventName")
		stamp = stringField(raw, "eventTime")
		status = "success"
		if stringField(raw, "errorCode") != "" {
			status = "failure"
		}
		eventID = stringField(raw, "eventID")
		requestID = stringField(raw, "requestID")
		ip = stringField(raw, "sourceIPAddress")
		params := cloudMap(raw["requestParameters"])
		resource = stringField(params, "modelId")
	case raw["protoPayload"] != nil:
		provider = "gcp"
		p := cloudMap(raw["protoPayload"])
		service = stringField(p, "serviceName")
		op = stringField(p, "methodName")
		resource = stringField(p, "resourceName")
		labels := cloudMap(cloudMap(raw["resource"])["labels"])
		tenant = stringField(labels, "project_id")
		if tenant == "" {
			tenant = cloudPathPart(stringField(raw, "logName"), "projects")
		}
		principal = firstNonEmpty(stringField(cloudMap(p["authenticationInfo"]), "principalEmail"), stringField(cloudMap(p["authenticationInfo"]), "principalSubject"))
		stamp = stringField(raw, "timestamp")
		eventID = stringField(raw, "insertId")
		ip = stringField(cloudMap(p["requestMetadata"]), "callerIp")
		status = "success"
		if code := cloudMap(p["status"])["code"]; code != nil && fmt.Sprint(code) != "0" {
			status = "failure"
		}
		if service == "serviceusage.googleapis.com" {
			request := cloudMap(p["request"])
			resource = firstNonEmpty(resource, stringField(request, "name"))
			if ids, ok := request["serviceIds"].([]any); ok {
				for _, id := range ids {
					if s, ok := id.(string); ok && (s == "aiplatform.googleapis.com" || s == "generativelanguage.googleapis.com") {
						resource = strings.TrimSuffix(resource, "/") + "/services/" + s
						break
					}
				}
			}
		}
	case raw["operationName"] != nil:
		provider = "azure"
		op = cloudName(raw["operationName"])
		resource = firstNonEmpty(stringField(raw, "resourceId"), stringField(raw, "resourceId_s"))
		service = "Microsoft.CognitiveServices"
		if strings.HasPrefix(strings.ToLower(op), "microsoft.authorization/") {
			service = "Microsoft.Authorization"
		}
		tenant = firstNonEmpty(stringField(raw, "subscriptionId"), cloudPathPart(resource, "subscriptions"))
		principal = stringField(raw, "caller")
		stamp = firstNonEmpty(stringField(raw, "eventTimestamp"), stringField(raw, "time"))
		eventID = firstNonEmpty(stringField(raw, "eventDataId"), stringField(raw, "eventId"))
		// Azure correlationId identifies a workflow, not necessarily a unique
		// invocation. Do not use it to collapse distinct model requests.
		ip = firstNonEmpty(stringField(raw, "callerIpAddress"), stringField(raw, "callerIpAddress_s"))
		switch strings.ToLower(cloudName(raw["status"])) {
		case "succeeded", "success":
			status = "success"
		case "failed", "failure":
			status = "failure"
		case "started", "accepted":
			return nil, false
		}
		// Only Cognitive Services resources may supply Azure operation names.
		if !strings.Contains(strings.ToLower(resource), "/providers/microsoft.cognitiveservices/") {
			return nil, false
		}
	default:
		return nil, false
	}
	category := cloudCategory(provider, service, op, resource)
	if category == "" {
		return nil, false
	}
	t, err := time.Parse(time.RFC3339Nano, stamp)
	if err != nil || t.IsZero() {
		return nil, true
	}
	if status != "success" && status != "failure" && status != "unknown" {
		return nil, true
	}
	f := map[string]any{"kind": "event", "provider": provider, "category": category, "timestamp": t.UTC(), "status": status}
	resourceScope := ""
	if provider == "azure" {
		resourceScope = strings.Split(strings.ToLower(resource), "/deployments/")[0]
		resourceScope = strings.Split(resourceScope, "/providers/microsoft.authorization/")[0]
	}
	// Group by unredacted identities, then retain only their digest. Redaction
	// must never collapse two distinct principals into one correlation scope.
	scope, _ := json.Marshal([]string{provider, tenant, principal, region, resourceScope})
	f["scope_id"] = fmt.Sprintf("%x", sha256.Sum256(scope))
	principalScope, _ := json.Marshal([]string{provider, tenant, principal})
	f["principal_scope_id"] = fmt.Sprintf("%x", sha256.Sum256(principalScope))
	identity := []any{f["scope_id"], service, op, status}
	if requestID != "" {
		identity = append(identity, "request", requestID)
	} else if eventID != "" {
		identity = append(identity, "event", eventID)
	} else {
		identity = append(identity, t.UTC(), resource, ip)
	}
	b, _ := json.Marshal(identity)
	f["event_key_sha256"] = fmt.Sprintf("%x", sha256.Sum256(b))
	f["correlation_eligible"] = tenant != "" && principal != "" && (provider != "aws" || region != "") &&
		(provider != "azure" || strings.Contains(resourceScope, "/providers/microsoft.cognitiveservices/accounts/"))
	for k, v := range map[string]string{"tenant": tenant, "principal": principal, "region": region, "service": service, "operation": op, "resource": resource, "event_id": eventID, "request_id": requestID} {
		if v != "" {
			if len(v) > 2048 {
				return nil, true
			}
			f[k] = redactSecrets(v)
		}
	}
	if a, err := netip.ParseAddr(ip); err == nil {
		f["source_ip"] = a.Unmap().String()
	}
	return f, true
}

func cloudPathPart(path, key string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i := 0; i+1 < len(parts); i++ {
		if strings.EqualFold(parts[i], key) {
			return parts[i+1]
		}
	}
	return ""
}

func cloudCategory(provider, service, op, resource string) string {
	s, o := strings.ToLower(service), strings.ToLower(op)
	switch provider {
	case "aws":
		if s == "iam.amazonaws.com" {
			switch o {
			case "createaccesskey", "attachuserpolicy", "attachrolepolicy", "putuserpolicy", "putrolepolicy":
				return "identity_change"
			}
		}
		if s != "bedrock.amazonaws.com" && s != "bedrock-runtime.amazonaws.com" {
			return ""
		}
		switch o {
		case "invokemodel", "invokemodelwithresponsestream", "converse", "conversestream", "invokemodelwithbidirectionalstream":
			return "invoke"
		case "listfoundationmodels", "listinferenceprofiles", "getfoundationmodelavailability":
			return "discover"
		case "putusecaseformodelaccess", "createfoundationmodelagreement":
			return "enable"
		case "deletemodelinvocationloggingconfiguration":
			return "logging_disabled"
		case "putmodelinvocationloggingconfiguration":
			return "logging_changed"
		}
	case "gcp":
		if s == "iam.googleapis.com" && strings.HasSuffix(o, ".createserviceaccountkey") {
			return "identity_change"
		}
		if s == "cloudresourcemanager.googleapis.com" && (o == "setiampolicy" || strings.HasSuffix(o, ".setiampolicy")) {
			return "identity_change"
		}
		if s == "serviceusage.googleapis.com" && (strings.HasSuffix(o, ".enableservice") || strings.HasSuffix(o, ".batchenableservices")) &&
			(strings.HasSuffix(resource, "/services/aiplatform.googleapis.com") || strings.HasSuffix(resource, "/services/generativelanguage.googleapis.com")) {
			return "enable"
		}
		if s != "aiplatform.googleapis.com" && s != "generativelanguage.googleapis.com" {
			return ""
		}
		method := o[strings.LastIndex(o, ".")+1:]
		switch method {
		case "generatecontent", "streamgeneratecontent", "predict", "rawpredict", "streamrawpredict":
			return "invoke"
		case "listmodels", "listendpoints", "listpublishermodels":
			return "discover"
		}
	case "azure":
		if s == "microsoft.authorization" && o == "microsoft.authorization/roleassignments/write" {
			return "identity_change"
		}
		if s != "microsoft.cognitiveservices" {
			return ""
		}
		switch o {
		case "microsoft.cognitiveservices/accounts/deployments/write":
			return "enable"
		case "microsoft.cognitiveservices/accounts/deployments/read", "microsoft.cognitiveservices/accounts/read":
			return "discover"
		case "chatcompletions_create", "completions_create":
			return "invoke"
		}
	}
	return ""
}

func cloudEventKey(f map[string]any) string {
	// Calculated before redaction so distinct request IDs cannot collapse.
	return stringField(f, "event_key_sha256")
}

func analyzeCloudWindows(r *Result, opts CloudAuditOptions) {
	groups := map[string][]int{}
	globalIdentityChanges := map[string][]int{}
	for i, rec := range r.Records {
		f := rec.Fields
		if f["correlation_eligible"] != true {
			continue
		}
		key := stringField(f, "scope_id")
		groups[key] = append(groups[key], i)
		if f["provider"] == "aws" && f["category"] == "identity_change" {
			id := stringField(f, "principal_scope_id")
			globalIdentityChanges[id] = append(globalIdentityChanges[id], i)
		}
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		indices := groups[key]
		sort.SliceStable(indices, func(i, j int) bool {
			return graphTime(r.Records[indices[i]].Fields["timestamp"]).Before(graphTime(r.Records[indices[j]].Fields["timestamp"]))
		})
		var invocations []int
		for _, i := range indices {
			f := r.Records[i].Fields
			if f["category"] == "invoke" && f["status"] == "success" {
				invocations = append(invocations, i)
			}
		}
		left, bestStart, bestEnd := 0, 0, 0
		for right, i := range invocations {
			end := graphTime(r.Records[i].Fields["timestamp"])
			for left < right && end.Sub(graphTime(r.Records[invocations[left]].Fields["timestamp"])) > 5*time.Minute {
				left++
			}
			if right+1-left > bestEnd-bestStart {
				bestStart, bestEnd = left, right+1
			}
		}
		if bestEnd-bestStart < opts.BurstThreshold {
			continue
		}
		window := invocations[bestStart:bestEnd]
		start := graphTime(r.Records[window[0]].Fields["timestamp"])
		end := graphTime(r.Records[window[len(window)-1]].Fields["timestamp"])
		disabled, enabled, discoveries, identityChanges := false, false, 0, 0
		refs := append([]int(nil), window[:min(len(window), cloudMaxRefs)]...)
		contextCount := 0
		contextIndices := append([]int(nil), indices...)
		anchor := r.Records[window[0]].Fields
		for _, i := range globalIdentityChanges[stringField(anchor, "principal_scope_id")] {
			if r.Records[i].Fields["scope_id"] != anchor["scope_id"] {
				contextIndices = append(contextIndices, i)
			}
		}
		for _, i := range contextIndices {
			f := r.Records[i].Fields
			t := graphTime(f["timestamp"])
			if f["status"] != "success" || t.Before(start.Add(-30*time.Minute)) || t.After(end) {
				continue
			}
			if f["category"] == "invoke" {
				continue
			}
			switch f["category"] {
			case "logging_disabled":
				disabled = true
			case "enable":
				enabled = true
			case "discover":
				discoveries++
			case "identity_change":
				identityChanges++
			default:
				continue
			}
			contextCount++
			if len(refs) < 2*cloudMaxRefs {
				refs = append(refs, i)
			}
		}
		f := r.Records[window[0]].Fields
		fields := map[string]any{"kind": "analysis", "provider": f["provider"], "tenant": f["tenant"], "principal": f["principal"], "region": f["region"], "window_start": start, "window_end": end,
			"successful_invocations": len(window), "identity_change_events": identityChanges, "supporting_events": refs, "supporting_events_omitted": len(window) + contextCount - len(refs)}
		fs := []Finding{{"llm.invocation_burst", SevNotable, "T1496", 45, fmt.Sprintf("%d unique successful model API calls in a five-minute window meet the configured threshold of %d; normal batch workloads can do this and supplied logs may be incomplete", len(window), opts.BurstThreshold)}}
		if disabled || ((enabled || identityChanges > 0) && discoveries >= 3) {
			fs = append(fs, Finding{"llm.possible_resource_hijack", SevSuspect, "T1496", 70, "a model-call burst has logging deletion, or enablement/identity changes plus discovery by the same cloud principal and tenant; AWS IAM changes apply across regions. Changes describe the actor, not proof that a newly created credential was used. Investigate authorization and usage baselines before attributing LLMjacking"})
		}
		r.Add(fields, fs...)
	}
}
