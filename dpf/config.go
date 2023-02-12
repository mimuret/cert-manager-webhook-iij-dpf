package dpf

import (
	"encoding/json"
	"fmt"

	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

type DPFProviderSolverConfig struct {
	Endpoint       string                   `json:"endpoint"`
	TokenSecretRef cmmeta.SecretKeySelector `json:"tokenSecretRef"`
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (DPFProviderSolverConfig, error) {
	cfg := DPFProviderSolverConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}
