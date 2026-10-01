package protocol

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

func TestReadRequestRequiresBoundedUTF8NewlineFrame(t *testing.T) {
	valid := []byte(`{"protocol_version":1,"id":"one","method":"describe"}` + "\n")
	if got, err := ReadRequest(bufio.NewReader(bytes.NewReader(valid))); err != nil || got.ID != "one" {
		t.Fatalf("valid request: got %#v, err %v", got, err)
	}
	for name, raw := range map[string][]byte{
		"empty":        {},
		"unterminated": []byte(`{"protocol_version":1,"id":"one","method":"describe"}`),
		"malformed":    []byte("{\n"),
		"invalid utf8": append([]byte(`{"protocol_version":1,"id":"`), append([]byte{0xff}, []byte(`","method":"describe"}`+"\n")...)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ReadRequest(bufio.NewReader(bytes.NewReader(raw))); err == nil {
				t.Fatal("expected invalid frame to be rejected")
			}
		})
	}
}

func TestReadRequestFrameLimitExcludesLF(t *testing.T) {
	prefix := []byte(`{"protocol_version":1,"id":"x","method":"unknown","padding":"`)
	suffix := []byte(`"}`)
	pad := MaxFrameBytes - len(prefix) - len(suffix)
	maxFrame := append(append(append([]byte{}, prefix...), bytes.Repeat([]byte{'a'}, pad)...), suffix...)
	if len(maxFrame) != MaxFrameBytes {
		t.Fatalf("test frame length = %d", len(maxFrame))
	}
	if _, err := ReadRequest(bufio.NewReader(bytes.NewReader(append(maxFrame, '\n')))); err != nil {
		t.Fatalf("exactly max-sized frame rejected: %v", err)
	}
	tooLarge := append(append([]byte{}, maxFrame...), ' ')
	if _, err := ReadRequest(bufio.NewReader(bytes.NewReader(append(tooLarge, '\n')))); err == nil {
		t.Fatal("oversized frame accepted")
	}
}

func TestParseFrameRejectsWrongVersionAndAmbiguousResponse(t *testing.T) {
	if _, err := ParseFrame([]byte(`{"protocol_version":2,"id":"x","method":"describe"}`)); !errors.Is(err, ErrUnsupportedProtocolVersion) {
		t.Fatalf("version error = %v", err)
	}
	if _, err := ParseFrame([]byte(`{"protocol_version":1,"id":"x","result":{},"error":{"code":"bad"}}`)); err == nil {
		t.Fatal("ambiguous response accepted")
	}
}

func TestMetadataNilAndKnownEmptyRemainDistinct(t *testing.T) {
	empty := ""
	want := MetadataResult{Metadata: StreamMetadata{Title: nil, Description: &empty}}
	data, err := jsonMarshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var got MetadataResult
	if err := jsonUnmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Metadata.Title != nil || got.Metadata.Description == nil || *got.Metadata.Description != "" {
		t.Fatalf("metadata nil/empty semantics changed: %#v", got.Metadata)
	}
}

func jsonMarshal(v any) ([]byte, error)   { return json.Marshal(v) }
func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

func TestDescriptorValidation(t *testing.T) {
	d := Descriptor{ID: "example", Name: "Example", Version: "1.0.0", ProtocolVersion: Version, Capabilities: []string{CapabilityResolve}, InputSchema: Schema{Fields: []Field{}}, ConfigurationSchema: Schema{Fields: []Field{}}, MediaTypes: []string{"hls"}}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	d.Capabilities = append(d.Capabilities, CapabilityResolve)
	if err := d.Validate(); err == nil {
		t.Fatal("duplicate capability accepted")
	}
}

func TestSchemaValidationCoversV1ConditionsAndCycles(t *testing.T) {
	valid := Schema{Fields: []Field{
		{Key: "enabled", Control: "boolean", Label: "Enabled"},
		{Key: "name", Control: "text", Label: "Name", VisibleWhen: json.RawMessage(`{"field":"enabled","truthy":true}`)},
	}}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid conditional schema: %v", err)
	}
	invalid := Schema{Fields: []Field{
		{Key: "first", Control: "text", Label: "First", VisibleWhen: json.RawMessage(`{"field":"second","equals":"x"}`)},
		{Key: "second", Control: "text", Label: "Second", VisibleWhen: json.RawMessage(`{"field":"first","equals":"x"}`)},
	}}
	if err := invalid.Validate(); err == nil {
		t.Fatal("visibility dependency cycle accepted")
	}
	secretRef := Schema{Fields: []Field{
		{Key: "password", Control: "secret", Label: "Password"},
		{Key: "other", Control: "text", Label: "Other", VisibleWhen: json.RawMessage(`{"field":"password","truthy":true}`)},
	}}
	if err := secretRef.Validate(); err == nil {
		t.Fatal("visibility condition referencing secret accepted")
	}
}
