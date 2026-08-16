package parser

import "testing"

func TestIISParser(t *testing.T) {
	parser, err := New("iis_w3c", "iis")
	if err != nil {
		t.Fatal(err)
	}
	_, err = parser.Parse("#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken")
	if err != nil {
		t.Fatal(err)
	}
	event, err := parser.Parse("2026-08-06 10:00:01 10.0.0.5 GET /login.aspx user=admin 443 - 203.0.113.10 Mozilla/5.0 - 401 0 0 21")
	if err != nil {
		t.Fatal(err)
	}
	if event.HTTP.Path != "/login.aspx" || event.HTTP.Status != 401 || event.Network.SourceIP != "203.0.113.10" {
		t.Fatalf("unexpected event: %+v", event)
	}
}

func TestNginxParser(t *testing.T) {
	parser, err := New("nginx_combined", "nginx")
	if err != nil {
		t.Fatal(err)
	}
	event, err := parser.Parse(`203.0.113.10 - alice [06/Aug/2026:17:42:01 +0700] "GET /api/items?id=9 HTTP/1.1" 200 123 "-" "curl/8.0"`)
	if err != nil {
		t.Fatal(err)
	}
	if event.HTTP.Path != "/api/items" || event.HTTP.Query != "id=9" || event.HTTP.Status != 200 {
		t.Fatalf("unexpected event: %+v", event)
	}
}

func TestCaddyJSONParser(t *testing.T) {
	parser, err := New("caddy_json", "caddy")
	if err != nil {
		t.Fatal(err)
	}
	event, err := parser.Parse(`{"ts":1786887721.25,"msg":"handled request","request":{"remote_ip":"198.51.100.7","remote_port":"55123","client_ip":"203.0.113.10","proto":"HTTP/3.0","method":"GET","host":"app.example.com","uri":"/assets/app.js?v=9","headers":{"User-Agent":["test-agent"],"Referer":["https://app.example.com/"]}},"duration":0.012,"size":1234,"status":200}`)
	if err != nil {
		t.Fatal(err)
	}
	if event.Kind != "web.request" || event.HTTP.Path != "/assets/app.js" || event.HTTP.Query != "v=9" || event.Network.SourceIP != "203.0.113.10" || event.HTTP.DurationMS != 12 {
		t.Fatalf("unexpected Caddy event: %+v", event)
	}
}

func TestMySQLParserFingerprintsQuery(t *testing.T) {
	parser, err := New("mysql_general", "mysql")
	if err != nil {
		t.Fatal(err)
	}
	event, err := parser.Parse("2026-08-06T10:00:01.000000Z 12 Query SELECT * FROM users WHERE id=42")
	if err != nil {
		t.Fatal(err)
	}
	if event.Kind != "database.query" || event.Database.QueryFingerprint == "" {
		t.Fatalf("unexpected event: %+v", event)
	}
}
