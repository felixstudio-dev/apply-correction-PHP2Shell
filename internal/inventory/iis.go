package inventory

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

const maxIISConfigBytes = 8 << 20

// IISBinding is configuration evidence only; it does not prove the executable
// exists, is currently serving requests, or contains a security correction.
type IISBinding struct {
	Executable string `json:"executable"`
	Source     string `json:"source"`
	Scope      string `json:"scope"`
	Status     string `json:"status"`
}

type IISReport struct {
	Status      string       `json:"status"`
	Bindings    []IISBinding `json:"bindings"`
	Limitations []string     `json:"limitations"`
}

// ParseIISFastCGI extracts PHP CGI executable paths from IIS global FastCGI
// application registrations and inherited or site-scoped handler mappings.
// It never executes paths or includes arguments, environment variables,
// credentials, or application settings from the source XML in its output.
func ParseIISFastCGI(reader io.Reader) ([]IISBinding, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxIISConfigBytes+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read IIS configuration: %w", err)
	}
	if len(data) > maxIISConfigBytes {
		return nil, errors.New("IIS configuration exceeds bounded inspection limit")
	}
	decoder := xml.NewDecoder(strings.NewReader(string(data)))
	type frame struct {
		name, scope string
	}
	var stack []frame
	var bindings []IISBinding
	seen := make(map[string]struct{})
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.New("invalid IIS configuration XML")
		}
		switch element := token.(type) {
		case xml.StartElement:
			if len(stack) == 0 && element.Name.Local != "configuration" {
				return nil, errors.New("invalid IIS configuration root")
			}
			scope := "global"
			if len(stack) > 0 {
				scope = stack[len(stack)-1].scope
			}
			if element.Name.Local == "location" && len(stack) == 1 && stack[0].name == "configuration" {
				if path := iisAttribute(element.Attr, "path"); path != "" {
					scope = path
				}
			}
			if len(stack) >= 2 && stack[len(stack)-2].name == "system.webServer" {
				parent := stack[len(stack)-1].name
				source, executable := "", ""
				if parent == "fastCgi" && element.Name.Local == "application" {
					source, executable = "FASTCGI_APPLICATION", iisAttribute(element.Attr, "fullPath")
				}
				if parent == "handlers" && element.Name.Local == "add" && iisFastCGIModule(iisAttribute(element.Attr, "modules")) {
					source, executable = "HANDLER_MAPPING", strings.SplitN(iisAttribute(element.Attr, "scriptProcessor"), "|", 2)[0]
				}
				executable = strings.TrimSpace(executable)
				if source != "" && iisPHPExecutable(executable) && !strings.ContainsAny(scope, "\r\n\x00") {
					key := strings.ToLower(scope + "\x00" + source + "\x00" + executable)
					if _, duplicate := seen[key]; !duplicate {
						seen[key] = struct{}{}
						bindings = append(bindings, IISBinding{Executable: executable, Source: source, Scope: scope, Status: "CONFIGURED_ONLY"})
					}
				}
			}
			stack = append(stack, frame{name: element.Name.Local, scope: scope})
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, errors.New("unbalanced IIS configuration")
			}
			stack = stack[:len(stack)-1]
		}
	}
	if len(stack) != 0 {
		return nil, errors.New("incomplete IIS configuration")
	}
	return bindings, nil
}

func iisAttribute(attrs []xml.Attr, name string) string {
	for _, attr := range attrs {
		if attr.Name.Local == name {
			return attr.Value
		}
	}
	return ""
}

func iisFastCGIModule(modules string) bool {
	for _, module := range strings.Split(modules, ",") {
		if strings.EqualFold(strings.TrimSpace(module), "FastCgiModule") {
			return true
		}
	}
	return false
}

func iisPHPExecutable(path string) bool {
	if path == "" || strings.ContainsAny(path, "\r\n\x00") || len(path) > 4096 {
		return false
	}
	name := path
	if index := strings.LastIndexAny(path, `\/`); index >= 0 {
		name = path[index+1:]
	}
	return strings.EqualFold(name, "php-cgi.exe")
}
