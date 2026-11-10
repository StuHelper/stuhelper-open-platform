package openplatform

import _ "embed"

//go:embed contracts/open-platform.openapi.json
var contract []byte

func OpenAPI() []byte { return append([]byte(nil), contract...) }
