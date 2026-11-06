package blocklistfmt

import (
	"strings"
	"testing"
)

const header = "# blocklist.conf\n\ngeo $blocked_source {\n    default        \"\";\n\n"

func TestValidateAccepts(t *testing.T) {
	data := header +
		"    1.2.3.4    emerging-block-ips;\n" +
		"    10.0.0.0/8    local;\n" +
		"    2001:db8::/32    ipsum-5+compromised-ips;\n" +
		"    ::ffff:1.2.3.4    local;\n" +
		"\n}"
	n, err := Validate([]byte(data), 10)
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 {
		t.Fatalf("got %d entries, want 4", n)
	}
	if _, err := Validate([]byte(header+"\n}"), 10); err != nil {
		t.Fatalf("empty list rejected: %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]string{
		"include":            header + "    include /etc/shadow;\n}",
		"directive after":    header + "}\naccess_log /etc/cron.d/x;",
		"second geo":         header + "}\ngeo $blocked_source {\n}",
		"no default":         "geo $blocked_source {\n    1.2.3.4    x;\n}",
		"duplicate default":  header + "    default \"\";\n}",
		"other variable":     "geo $remote_user {\n    default \"\";\n}",
		"unclosed":           header + "    1.2.3.4    x;\n",
		"quoted label":       header + "    1.2.3.4    \"x\";\n}",
		"label zero":         header + "    1.2.3.4    0;\n}",
		"brace in label":     header + "    1.2.3.4    x}y;\n}",
		"missing semicolon":  header + "    1.2.3.4    x\n}",
		"extra token":        header + "    1.2.3.4    x    y;\n}",
		"hostname":           header + "    example.com    x;\n}",
		"zone":               header + "    fe80::1%eth0    x;\n}",
		"leading zeros":      header + "    01.2.3.4    x;\n}",
		"ipv4 everything":    header + "    0.0.0.0/0    x;\n}",
		"ipv4 too broad":     header + "    0.0.0.0/7    x;\n}",
		"ipv6 everything":    header + "    ::/0    x;\n}",
		"ipv6 too broad":     header + "    2000::/3    x;\n}",
		"mapped too broad":   header + "    ::ffff:0.0.0.0/96    x;\n}",
		"geo with ranges":    "geo $blocked_source {\n    ranges;\n    default \"\";\n}",
		"line too long":      header + "    1.2.3.4    " + strings.Repeat("a", 5000) + ";\n}",
		"crlf smuggled line": header + "    1.2.3.4    x;\r\n    include /x;\n}",
	}
	for name, data := range cases {
		if _, err := Validate([]byte(data), 10); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestValidateEntryLimit(t *testing.T) {
	data := header + strings.Repeat("    1.2.3.4    x;\n", 3) + "}"
	if _, err := Validate([]byte(data), 2); err == nil {
		t.Fatal("entry limit not enforced")
	}
}

func TestValidateDoesNotEchoContent(t *testing.T) {
	_, err := Validate([]byte(header+"    secret-from-shadow\n}"), 10)
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("error %v should report the line number only", err)
	}
}
