// Run from the patched Katana module: go run /path/to/this/file.go -file saved.js -sha256 digest.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/projectdiscovery/katana/pkg/utils"
	"os"
	"strings"
)

func main() {
	file := flag.String("file", "", "Saved bundle path")
	expected := flag.String("sha256", "", "Expected SHA256")
	reference := flag.String("reference", "./address-suggestions.js", "Reference to inspect")
	flag.Parse()
	info, err := os.Stat(*file)
	if err != nil || info.Size() > 5_000_000 {
		panic("saved bundle unavailable or oversized")
	}
	data, err := os.ReadFile(*file)
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(data)
	actual := hex.EncodeToString(digest[:])
	if actual != *expected {
		panic("saved bundle SHA mismatch")
	}
	selectRefs := func(items []string) []string {
		result := []string{}
		for _, item := range items {
			if strings.TrimPrefix(item, "./") == strings.TrimPrefix(*reference, "./") {
				result = append(result, item)
			}
		}
		return result
	}
	masked := utils.MaskBundledModuleReferences(string(data))
	report := map[string]any{"sha256": actual, "bytes": len(data), "source_masked": masked != string(data), "before_body": selectRefs(utils.ExtractBodyEndpoints(string(data))), "after_body": selectRefs(utils.ExtractBodyEndpoints(masked)), "before_script": selectRefs(utils.ExtractScriptEndpoints(string(data))), "after_script": selectRefs(utils.ExtractScriptEndpoints(masked))}
	out, _ := json.Marshal(report)
	fmt.Println(string(out))
}
