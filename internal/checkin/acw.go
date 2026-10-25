package checkin

// The bounded permutation/XOR decoder follows the MIT-licensed Metapi
// newApiShield.ts and the project's Python decoder. JavaScript is never run.
import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	acwMarker   = regexp.MustCompile(`\bvar\s+arg1\s*=`)
	acwEnvelope = regexp.MustCompile(`(?s)^\s*<html>\s*<script>\s*(.*?)\s*</script>\s*</html>\s*$`)
	acwArg      = regexp.MustCompile(`var\s+arg1\s*=\s*(['"])([0-9a-fA-F]+)(['"]);`)
	acwMapping  = regexp.MustCompile(`for\(var m=\[([^\]]+)\],p=L\(0x115\)`)
	acwTable    = regexp.MustCompile(`function a0i\(\)\{var N=\[([^\]]+)\];`)
	acwItem     = regexp.MustCompile(`^'([a-zA-Z0-9+/]+)'$`)
	acwNumber   = regexp.MustCompile(`^(?:0[xX][0-9a-fA-F]+|[0-9]+)$`)
	hex40       = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
)

func IsACWChallenge(html string) bool {
	return len(html) <= 16384 && strings.Contains(html, "acw_sc__v2") && acwMarker.MatchString(html)
}

// SolveACW accepts only the full known template. Any unexpected script,
// ambiguity, helper change, or oversized input is rejected without side effects.
func SolveACW(html string) (string, bool) {
	if !IsACWChallenge(html) {
		return "", false
	}
	env := acwEnvelope.FindStringSubmatch(html)
	if env == nil {
		return "", false
	}
	script := env[1]
	args, mappings, tables := acwArg.FindAllStringSubmatchIndex(script, -1), acwMapping.FindAllStringSubmatchIndex(script, -1), acwTable.FindAllStringSubmatchIndex(script, -1)
	if len(args) != 1 || len(mappings) != 1 || len(tables) != 1 {
		return "", false
	}
	a, m, t := args[0], mappings[0], tables[0]
	if script[a[2]:a[3]] != script[a[6]:a[7]] {
		return "", false
	}
	arg := script[a[4]:a[5]]
	if !hex40.MatchString(arg) {
		return "", false
	}
	parts := strings.Split(script[m[2]:m[3]], ",")
	if len(parts) != 40 {
		return "", false
	}
	permutation := make([]int, 40)
	seen := make(map[int]bool)
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if len(part) > 4 || !acwNumber.MatchString(part) {
			return "", false
		}
		base := 10
		if strings.HasPrefix(strings.ToLower(part), "0x") {
			base, part = 16, part[2:]
		}
		n, err := strconv.ParseInt(part, base, 32)
		if err != nil || n < 1 || n > 40 || seen[int(n)] {
			return "", false
		}
		permutation[i], seen[int(n)] = int(n), true
	}
	table := script[t[2]:t[3]]
	items := strings.Split(table, ",")
	if len(items) < 1 || len(items) > 64 {
		return "", false
	}
	var seed, literal string
	for _, item := range items {
		match := acwItem.FindStringSubmatch(item)
		if match == nil || len(match[1]) > 256 {
			return "", false
		}
		encoded := strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' {
				return r - 'a' + 'A'
			}
			if r >= 'A' && r <= 'Z' {
				return r - 'A' + 'a'
			}
			return r
		}, match[1])
		decoded, err := base64.RawStdEncoding.DecodeString(encoded)
		if err != nil {
			return "", false
		}
		for _, b := range decoded {
			if b > 127 {
				return "", false
			}
		}
		if hex40.Match(decoded) {
			if seed != "" {
				return "", false
			}
			seed, literal = string(decoded), item
		}
	}
	if seed == "" {
		return "", false
	}
	type replacement struct {
		start, end int
		value      string
	}
	seedAt := t[2] + strings.Index(table, literal)
	replacements := []replacement{{a[0], a[1], "var arg1='<ARG1>';"}, {m[2], m[3], "<MAPPING>"}, {seedAt, seedAt + len(literal), "'<XOR_SEED>'"}}
	sort.Slice(replacements, func(i, j int) bool { return replacements[i].start > replacements[j].start })
	normal := script
	for _, item := range replacements {
		normal = normal[:item.start] + item.value + normal[item.end:]
	}
	for _, r := range normal {
		if r > 127 {
			return "", false
		}
	}
	hash := sha256.Sum256([]byte(normal))
	if hex.EncodeToString(hash[:]) != "ffee4ea88fa2701ab12030014c7687d83464c40a6b31c42ce1ca78a0109713f4" {
		return "", false
	}
	shuffled := make([]byte, 40)
	for i, n := range permutation {
		shuffled[i] = arg[n-1]
	}
	source, err := hex.DecodeString(string(shuffled))
	if err != nil {
		return "", false
	}
	seedBytes, err := hex.DecodeString(seed)
	if err != nil {
		return "", false
	}
	for i := range source {
		source[i] ^= seedBytes[i]
	}
	return hex.EncodeToString(source), true
}
