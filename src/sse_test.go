package main

import (
	"reflect"
	"testing"
)

func TestSSEStreamParserPreservesEveryDataFrame(t *testing.T) {
	cases := []struct {
		name   string
		chunks []string
		want   []string
	}{
		{
			name:   "standard spaced frames",
			chunks: []string{"data: {\"a\":1}\n\ndata: {\"a\":2}\n\n"},
			want:   []string{`{"a":1}`, `{"a":2}`},
		},
		{
			name:   "no space after colon is still a data frame",
			chunks: []string{"data:{\"a\":1}\n\n"},
			want:   []string{`{"a":1}`},
		},
		{
			name:   "event line does not discard its data",
			chunks: []string{"event: agy.progress\ndata: {\"phase\":\"tool\"}\n\n"},
			want:   []string{`{"phase":"tool"}`},
		},
		{
			name:   "multi-line data rejoins into one payload",
			chunks: []string{"data: {\ndata: }\n\n"},
			want:   []string{"{\n}"},
		},
		{
			name:   "frame split across reads reassembles",
			chunks: []string{"data: {\"re", "asoning_content\":\"x\"}\n\n"},
			want:   []string{`{"reasoning_content":"x"}`},
		},
		{
			name:   "reasoning content survives untouched",
			chunks: []string{"data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"thinking\"}}]}\n\n"},
			want:   []string{`{"choices":[{"delta":{"reasoning_content":"thinking"}}]}`},
		},
		{
			name:   "keep-alive comment yields nothing",
			chunks: []string{": keep-alive\n\n"},
			want:   nil,
		},
		{
			name:   "done marker is not forwarded",
			chunks: []string{"data: [DONE]\n\n"},
			want:   nil,
		},
		{
			name:   "crlf framing normalises",
			chunks: []string{"data: {\"a\":1}\r\n\r\n"},
			want:   []string{`{"a":1}`},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parser := &sseStreamParser{}
			var got []string
			for _, chunk := range tc.chunks {
				for _, event := range parser.feed([]byte(chunk)) {
					got = append(got, string(event))
				}
			}
			for _, event := range parser.flush() {
				got = append(got, string(event))
			}
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("events = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestSSEStreamParserFlushesTrailingEventWithoutBlankLine(t *testing.T) {
	parser := &sseStreamParser{}
	if events := parser.feed([]byte("data: {\"last\":true}\n")); len(events) != 0 {
		t.Fatalf("incomplete frame must wait for its blank line, got %q", events)
	}
	events := parser.flush()
	if len(events) != 1 || string(events[0]) != `{"last":true}` {
		t.Fatalf("flush events = %q, want the trailing data frame", events)
	}
}
