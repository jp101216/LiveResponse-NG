package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func cloudTestEvent(op, id string, n int) map[string]any {
	return map[string]any{"provider": "aws", "tenant": "111122223333", "principal": "arn:aws:iam::111122223333:user/test", "region": "us-east-1",
		"service": "bedrock.amazonaws.com", "operation": op, "timestamp": time.Date(2026, 11, 1, 12, 0, n, 0, time.UTC).Format(time.RFC3339), "event_id": id, "status": "success"}
}

func importCloudTest(t *testing.T, rows []map[string]any, threshold int) Result {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	var data strings.Builder
	for _, row := range rows {
		b, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		data.Write(b)
		data.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(data.String()), 0600); err != nil {
		t.Fatal(err)
	}
	return ParseCloudAuditFiles(context.Background(), []string{path}, CloudAuditOptions{threshold})
}

func cloudHasRule(r Result, rule string) bool {
	for _, rec := range r.Records {
		if hasRule(rec.Findings, rule) {
			return true
		}
	}
	return false
}

func TestCloudBurstWithCorroborationAndProvenance(t *testing.T) {
	r := importCloudTest(t, []map[string]any{cloudTestEvent("DeleteModelInvocationLoggingConfiguration", "log", 0), cloudTestEvent("InvokeModel", "a", 1), cloudTestEvent("InvokeModel", "b", 2), cloudTestEvent("InvokeModel", "c", 3)}, 3)
	if len(r.Errors) > 0 || r.Meta["imported_events"] != 4 || len(r.Records) != 5 || !cloudHasRule(r, "llm.possible_resource_hijack") {
		t.Fatalf("unexpected result: %+v", r)
	}
	for _, rec := range r.Records[:4] {
		if rec.Fields["source_sha256"] == "" || rec.Fields["source_line"] == nil {
			t.Fatal("missing event provenance")
		}
	}
	for _, i := range r.Records[4].Fields["supporting_events"].([]int) {
		if i < 0 || i >= 4 {
			t.Fatal("invalid evidence reference")
		}
	}
	g := BuildEvidenceGraph([]Result{r}, "")
	if len(graphEdges(g, "contributes_to_analysis")) != 4 {
		t.Fatalf("cloud graph links missing: %+v", g.Meta)
	}
}

func TestCloudRateScopeAndFalsePositiveControls(t *testing.T) {
	for _, mode := range []string{"ordinary_batch", "duplicate", "other_tenant", "other_region", "other_principal", "failed", "unknown", "missing_identity", "outside_window", "redaction_collision"} {
		rows := []map[string]any{cloudTestEvent("InvokeModel", "a", 1), cloudTestEvent("InvokeModel", "b", 2), cloudTestEvent("InvokeModel", "c", 3)}
		expectBurst := mode == "ordinary_batch"
		switch mode {
		case "duplicate":
			for _, r := range rows {
				r["request_id"] = "same-request"
			}
		case "other_tenant":
			rows[2]["tenant"] = "444455556666"
		case "other_region":
			rows[2]["region"] = "eu-west-1"
		case "other_principal":
			rows[2]["principal"] = "other-user"
		case "failed":
			rows[2]["status"] = "failure"
		case "unknown":
			rows[2]["status"] = "unknown"
		case "missing_identity":
			rows[2]["principal"] = ""
		case "outside_window":
			rows[2]["timestamp"] = "2026-11-01T12:06:00Z"
		case "redaction_collision":
			rows[0]["principal"] = "api_key=one"
			rows[1]["principal"] = "api_key=one"
			rows[2]["principal"] = "api_key=two"
		}
		r := importCloudTest(t, rows, 3)
		if cloudHasRule(r, "llm.invocation_burst") != expectBurst {
			t.Errorf("%s: incorrect burst: %+v", mode, r)
		}
		if cloudHasRule(r, "llm.possible_resource_hijack") {
			t.Errorf("%s: ordinary traffic claimed as hijack", mode)
		}
	}
}

func TestCloudNativeAWSStreamingAndDuplicateExports(t *testing.T) {
	base := map[string]any{"eventType": "AwsApiCall", "eventSource": "bedrock.amazonaws.com", "eventName": "ConverseStream", "eventTime": "2026-11-01T12:00:00Z",
		"recipientAccountId": "111122223333", "awsRegion": "us-east-1", "userIdentity": map[string]any{"arn": "arn:aws:iam::111122223333:user/test", "accessKeyId": "DO-NOT-COPY-KEY"},
		"requestID": "unique-request", "eventID": "management-copy", "requestParameters": map[string]any{"modelId": "test-model", "body": "DO-NOT-COPY-PROMPT"}, "responseElements": map[string]any{"text": "DO-NOT-COPY-RESPONSE"}}
	dataCopy := map[string]any{}
	for k, v := range base {
		dataCopy[k] = v
	}
	dataCopy["eventID"] = "data-copy"
	completion := map[string]any{}
	for k, v := range base {
		completion[k] = v
	}
	completion["eventType"] = "AwsServiceEvent"
	completion["eventID"] = "stream-finished"
	r := importCloudTest(t, []map[string]any{base, dataCopy, completion}, 2)
	if r.Meta["imported_events"] != 1 || r.Meta["duplicate_events"] != 1 || r.Meta["ignored_events"] != 1 || cloudHasRule(r, "llm.invocation_burst") {
		t.Fatalf("stream or duplicate inflation: %+v", r)
	}
	b, _ := json.Marshal(r)
	for _, secret := range []string{"DO-NOT-COPY-KEY", "DO-NOT-COPY-PROMPT", "DO-NOT-COPY-RESPONSE"} {
		if strings.Contains(string(b), secret) {
			t.Fatal("sensitive body copied")
		}
	}
}

func TestCloudNativeGCPAndAzure(t *testing.T) {
	gcp := map[string]any{"timestamp": "2026-11-01T12:00:00Z", "insertId": "gcp-event", "logName": "projects/demo-project/logs/activity",
		"protoPayload": map[string]any{"serviceName": "serviceusage.googleapis.com", "methodName": "google.api.serviceusage.v1.ServiceUsage.EnableService", "resourceName": "projects/demo-project/services/aiplatform.googleapis.com",
			"authenticationInfo": map[string]any{"principalEmail": "operator@example.invalid"}, "request": map[string]any{"secret": "EXCLUDE-ME"}}}
	azure := map[string]any{"eventTimestamp": "2026-11-01T12:00:01Z", "eventDataId": "azure-event", "operationName": map[string]any{"value": "Microsoft.CognitiveServices/accounts/deployments/write"},
		"status": map[string]any{"value": "Succeeded"}, "caller": "operator@example.invalid", "resourceId": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/test/deployments/model"}
	for _, raw := range []map[string]any{gcp, azure} {
		f, ok := normalizeCloudEvent(raw)
		if !ok || f == nil || f["category"] != "enable" || f["status"] != "success" || f["tenant"] == "" {
			t.Fatalf("native parser: %+v", f)
		}
	}
	azure["status"] = map[string]any{"value": "Started"}
	if _, ok := normalizeCloudEvent(azure); ok {
		t.Fatal("unfinished Azure operation counted")
	}
	gcp["protoPayload"].(map[string]any)["resourceName"] = "projects/demo-project/services/storage.googleapis.com"
	if _, ok := normalizeCloudEvent(gcp); ok {
		t.Fatal("unrelated service enablement classified")
	}
}

func TestCloudDocumentsMalformedInputAndLimits(t *testing.T) {
	for _, envelope := range []string{"Records", "records", "entries", "array"} {
		path := filepath.Join(t.TempDir(), "audit.json")
		var document any = []any{cloudTestEvent("InvokeModel", "a", 0)}
		if envelope != "array" {
			document = map[string]any{envelope: document}
		}
		b, _ := json.Marshal(document)
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
		r := ParseCloudAuditFiles(context.Background(), []string{path}, CloudAuditOptions{100})
		if r.Meta["imported_events"] != 1 || len(r.Errors) != 0 {
			t.Fatalf("%s: %+v", envelope, r)
		}
	}
	path := filepath.Join(t.TempDir(), "bad.jsonl")
	if err := os.WriteFile(path, []byte("{DO-NOT-QUOTE-SECRET}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r := ParseCloudAuditFiles(context.Background(), []string{path}, CloudAuditOptions{})
	if len(r.Errors) == 0 || strings.Contains(strings.Join(r.Errors, " "), "DO-NOT-QUOTE-SECRET") {
		t.Fatal("parser error leaked input or hid failure")
	}
	rows := make([]map[string]any, cloudMaxRecords+2)
	for i := range rows {
		rows[i] = cloudTestEvent("InvokeModel", fmt.Sprint(i), 0)
	}
	r = importCloudTest(t, rows, 100000)
	if r.Meta["imported_events"] != cloudMaxRecords || r.Meta["truncated"] != true {
		t.Fatal("record cap not enforced")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r = ParseCloudAuditFiles(ctx, []string{path}, CloudAuditOptions{})
	if len(r.Records) != 0 || len(r.Errors) == 0 {
		t.Fatal("cancelled import continued")
	}
}

func TestCloudIdentityChangeContextIsActorScoped(t *testing.T) {
	for _, sameActor := range []bool{true, false} {
		change := cloudTestEvent("CreateAccessKey", "key-created", 0)
		change["service"] = "iam.amazonaws.com"
		change["region"] = "us-east-1"
		if !sameActor {
			change["principal"] = "other-operator"
		}
		rows := []map[string]any{change}
		for i := 1; i <= 3; i++ {
			e := cloudTestEvent("ListFoundationModels", fmt.Sprintf("discovery-%d", i), i)
			e["region"] = "us-west-2"
			rows = append(rows, e)
		}
		for i := 4; i <= 6; i++ {
			e := cloudTestEvent("InvokeModel", fmt.Sprintf("call-%d", i), i)
			e["region"] = "us-west-2"
			rows = append(rows, e)
		}
		r := importCloudTest(t, rows, 3)
		if cloudHasRule(r, "llm.possible_resource_hijack") != sameActor {
			t.Fatalf("same actor=%v: %+v", sameActor, r)
		}
	}
	aws := map[string]any{"eventType": "AwsApiCall", "eventSource": "iam.amazonaws.com", "eventName": "CreateAccessKey", "eventTime": "2026-11-01T12:00:00Z", "awsRegion": "us-east-1",
		"recipientAccountId": "111122223333", "userIdentity": map[string]any{"arn": "operator"}, "responseElements": map[string]any{"accessKey": map[string]any{"secretAccessKey": "NEVER-RETAIN-THIS-SECRET"}}}
	f, ok := normalizeCloudEvent(aws)
	if !ok || f == nil || f["category"] != "identity_change" {
		t.Fatal("native identity event not normalized")
	}
	b, _ := json.Marshal(f)
	if strings.Contains(string(b), "NEVER-RETAIN") {
		t.Fatal("credential response leaked")
	}
}

func FuzzNormalizeCloudAudit(f *testing.F) {
	b, _ := json.Marshal(cloudTestEvent("InvokeModel", "seed", 0))
	f.Add(b)
	f.Add([]byte(`{"protoPayload":{"request":{"prompt":"secret"}}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		var raw map[string]any
		if json.Unmarshal(b, &raw) != nil {
			return
		}
		fields, _ := normalizeCloudEvent(raw)
		if fields != nil {
			if _, err := json.Marshal(fields); err != nil {
				t.Fatal(err)
			}
		}
	})
}
