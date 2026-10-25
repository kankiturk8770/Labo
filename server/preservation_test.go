package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"testing"
)

// Compare parsed function declarations, ignoring whitespace but not code.
// These functions form the original authentication/routing/proxy contract.
func TestOriginalLogicUnchanged(t *testing.T) {
	names := map[string]bool{"ServeHTTP": true, "Valid": true, "NewBackendPool": true, "newReverseProxy": true, "loadConfig": true, "parseTarget": true, "requiredEnv": true, "envOrDefault": true, "durationEnv": true}
	extract := func(path string) map[string]string {
		data, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		fs := token.NewFileSet()
		file, e := parser.ParseFile(fs, path, data, 0)
		if e != nil {
			t.Fatal(e)
		}
		out := map[string]string{}
		for _, d := range file.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && names[fn.Name.Name] {
				var b bytes.Buffer
				printer.Fprint(&b, fs, fn)
				key := fn.Name.Name
				if fn.Recv != nil {
					var recv bytes.Buffer
					printer.Fprint(&recv, fs, fn.Recv)
					key += recv.String()
				}
				out[key] = b.String()
			}
		}
		return out
	}
	before, after := extract("original/main.go"), extract("main.go")
	if len(before) != len(after) {
		t.Fatal("protected function count changed")
	}
	for k, v := range before {
		if after[k] != v {
			t.Errorf("original function changed: %s", k)
		}
	}
}
