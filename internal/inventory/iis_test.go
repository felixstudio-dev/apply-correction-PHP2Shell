package inventory

import (
	"strings"
	"testing"
)

func TestParseIISFastCGIBindings(t *testing.T) {
	config := `<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <fastCgi>
      <application fullPath="C:\PHP\php-cgi.exe" arguments="-d password=secret-value" />
      <application fullPath="C:\Python\python.exe" />
    </fastCgi>
    <handlers>
      <add name="PHP" path="*.php" modules="FastCgiModule" scriptProcessor="C:\PHP\php-cgi.exe|-d secret=hidden-value" />
      <add name="NonFastCGI" modules="IsapiModule" scriptProcessor="C:\PHP\php-cgi.exe" />
    </handlers>
  </system.webServer>
  <location path="Example Site">
    <system.webServer>
      <handlers>
        <add name="SitePHP" path="*.php" modules="StaticFileModule, FastCgiModule" scriptProcessor="D:\PHP\php-cgi.exe" />
        <add name="Ruby" modules="FastCgiModule" scriptProcessor="C:\Ruby\ruby.exe" />
      </handlers>
    </system.webServer>
  </location>
</configuration>`
	bindings, err := ParseIISFastCGI(strings.NewReader(config))
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 3 {
		t.Fatalf("want 3 PHP bindings, got %+v", bindings)
	}
	if bindings[0].Executable != `C:\PHP\php-cgi.exe` || bindings[0].Source != "FASTCGI_APPLICATION" || bindings[0].Scope != "global" {
		t.Fatalf("unexpected FastCGI application: %+v", bindings[0])
	}
	if bindings[1].Executable != `C:\PHP\php-cgi.exe` || bindings[1].Source != "HANDLER_MAPPING" || bindings[1].Scope != "global" {
		t.Fatalf("unexpected global handler: %+v", bindings[1])
	}
	if bindings[2].Executable != `D:\PHP\php-cgi.exe` || bindings[2].Scope != "Example Site" {
		t.Fatalf("unexpected site mapping: %+v", bindings[2])
	}
	for _, binding := range bindings {
		if binding.Status != "CONFIGURED_ONLY" || strings.Contains(binding.Executable, "secret") {
			t.Fatalf("invalid IIS binding status or leaked arguments: %+v", binding)
		}
	}
}

func TestParseIISFastCGIRejectsMalformedAndOversized(t *testing.T) {
	for _, value := range []string{`<configuration><fastCgi>`, strings.Repeat("x", maxIISConfigBytes+1)} {
		if _, err := ParseIISFastCGI(strings.NewReader(value)); err == nil {
			t.Fatal("invalid or oversized IIS configuration was accepted")
		}
	}
}

func TestParseIISFastCGIIgnoresUnrelatedPathsAndDeduplicates(t *testing.T) {
	config := `<configuration><system.webServer><handlers>
<add modules="FastCgiModule" scriptProcessor="C:\PHP\php-cgi.exe" />
<add modules="FastCgiModule" scriptProcessor="C:\PHP\php-cgi.exe" />
<add modules="StaticFileModule" scriptProcessor="C:\PHP\php-cgi.exe" />
<add modules="FastCgiModule" scriptProcessor="C:\PHP\php-cgi.exe.bad" />
</handlers></system.webServer></configuration>`
	bindings, err := ParseIISFastCGI(strings.NewReader(config))
	if err != nil || len(bindings) != 1 {
		t.Fatalf("unsafe IIS bindings: %+v, err=%v", bindings, err)
	}
}
