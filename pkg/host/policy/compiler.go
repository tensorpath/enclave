package policy

import (
	"bytes"
	"fmt"
	"text/template"
)

const tetragonTemplate = `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "jit-policy-{{.SessionID}}"
spec:
  kprobes:
  {{- if not .Verdict.AllowNetwork }}
  # 1. Network Killswitch
  - call: "sys_connect"
    syscall: true
    selectors:
    - matchActions:
      - action: Override
        argError: -1
  {{- end }}

  # 2. File System Guard
  - call: "security_file_open"
    args:
    - index: 0
      type: "file"
    selectors:
    - matchArgs:
      - index: 0
        operator: "NotIn"
        values:
          {{- range .Verdict.AllowedReadPaths }}
          - "{{.}}"
          {{- end }}
          - "/lib/"
          - "/usr/"
          - "/etc/ld.so.cache"
          - "/etc/passwd"  # Strictly for resolution
      matchActions:
      - action: Override
        argError: -1
`

type CompilerInput struct {
	SessionID string
	Verdict   *Verdict
}

func Compile(input CompilerInput) (string, error) {
	tmpl, err := template.New("tetragon").Parse(tetragonTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, input); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}
