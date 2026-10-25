package app

import (
	"encoding/json"
	"strconv"
	"time"
)

type Document = map[string]any

func object(v any) Document {
	d, _ := v.(map[string]any)
	if d == nil {
		return Document{}
	}
	return d
}
func text(v any) string { s, _ := v.(string); return s }
func yes(v any) bool    { b, _ := v.(bool); return b }
func number(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case float32:
		return float64(n)
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case json.Number:
		f, _ := n.Float64()
		return f
	}
	return 0
}
func integer(v any) (int, bool) {
	f := number(v)
	switch v.(type) {
	case float64, int, int64, json.Number:
	default:
		return 0, false
	}
	return int(f), f >= 0 && f == float64(int(f))
}
func list(v any) []Document {
	out := []Document{}
	switch a := v.(type) {
	case []any:
		for _, v := range a {
			if d, ok := v.(map[string]any); ok {
				out = append(out, d)
			}
		}
	case []map[string]any:
		out = append(out, a...)
	}
	return out
}
func clone(d Document) Document {
	b, _ := json.Marshal(d)
	var out Document
	_ = json.Unmarshal(b, &out)
	return out
}
func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
func nullableTime(v any) any {
	if v == nil {
		return nil
	}
	return stamp(time.Unix(0, int64(number(v)*1e9)))
}

var zone = time.FixedZone("Asia/Singapore", 8*60*60)

func dayAt(t time.Time) string { return t.In(zone).Format("2006-01-02") }
func decimal(i int64) string   { return strconv.FormatInt(i, 10) }
