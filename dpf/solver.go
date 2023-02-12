package dpf

import (
	"context"
	"fmt"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/miekg/dns"
	dpfapi "github.com/mimuret/golang-iij-dpf/pkg/api"
	"github.com/mimuret/golang-iij-dpf/pkg/apis/dpf/v1/zones"
	"github.com/mimuret/golang-iij-dpf/pkg/apiutils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ webhook.Solver = &DPFSolver{}

// customDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
// interface.
type DPFSolver struct {
	kubeClient *kubernetes.Clientset
	stopCh     <-chan struct{}
}

func (c *DPFSolver) Initialize(kubeClientConfig *restclient.Config, stopCh <-chan struct{}) error {
	var err error
	c.kubeClient, err = kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}
	c.stopCh = stopCh
	return nil
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *DPFSolver) Name() string {
	return "iij-dpf"
}

func (c *DPFSolver) getClient(cfgJSON *extapi.JSON, namespace string) (dpfapi.ClientInterface, error) {
	cfg, err := loadConfig(cfgJSON)
	if err != nil {
		return nil, err
	}
	secretName := cfg.TokenSecretRef.LocalObjectReference.Name
	sec, err := c.kubeClient.CoreV1().Secrets(namespace).Get(context.Background(), secretName, metav1.GetOptions{})

	if err != nil {
		return nil, fmt.Errorf("failed to get secret %s: %w", secretName, err)
	}

	token, exist := sec.Data[cfg.TokenSecretRef.Key]

	if !exist {
		return nil, fmt.Errorf("failed to get key: %s", cfg.TokenSecretRef.Key)
	}

	return dpfapi.NewClient(string(token), cfg.Endpoint, nil), nil
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *DPFSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cl, err := c.getClient(ch.Config, ch.ResourceNamespace)
	if err != nil {
		return err
	}
	z, err := apiutils.GetZoneFromZonename(context.Background(), cl, dns.CanonicalName(ch.ResolvedZone))
	if err != nil {
		return err
	}
	targetName := dns.CanonicalName(ch.DNSName)
	r, err := apiutils.GetRecordFromZoneID(context.Background(), cl, z.ID, targetName, zones.TypeTXT)
	if err != nil && err != apiutils.ErrRecordNotFound {
		return err
	}
	if err != apiutils.ErrRecordNotFound {
		// create rrset
		r = &zones.Record{
			AttributeMeta: zones.AttributeMeta{
				ZoneID: z.ID,
			},
			Name:   targetName,
			TTL:    300,
			RRType: zones.TypeTXT,
			RData: []zones.RecordRDATA{
				{Value: ch.Key},
			},
			Description: "create by cert-manager-webhook-iij-dpf",
		}
		reqID, _, err := apiutils.SyncCancel(context.Background(), cl, r)
		if err != nil {
			return fmt.Errorf("failed to create record task_id: %s error: %w", reqID, err)
		}
	} else {
		r.RData = append(r.RData, zones.RecordRDATA{Value: ch.Key})
		reqID, _, err := apiutils.SyncUpdate(context.Background(), cl, r, nil)
		if err != nil {
			return fmt.Errorf("failed to update record task_id: %s error: %w", reqID, err)
		}
	}
	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *DPFSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cl, err := c.getClient(ch.Config, ch.ResourceNamespace)
	if err != nil {
		return err
	}
	z, err := apiutils.GetZoneFromZonename(context.Background(), cl, dns.CanonicalName(ch.ResolvedZone))
	if err != nil {
		return err
	}
	targetName := dns.CanonicalName(ch.DNSName)
	r, err := apiutils.GetRecordFromZoneID(context.Background(), cl, z.ID, targetName, zones.TypeTXT)
	if err == apiutils.ErrRecordNotFound {
		return nil
	}
	if err != nil {
		return err
	}
	rdata := zones.RecordRDATASlice{}
	for _, v := range r.RData {
		if v.Value != ch.Key {
			rdata = append(rdata, v)
		}
	}
	if len(rdata) == 0 {
		// delete rrset
		reqID, _, err := apiutils.SyncDelete(context.Background(), cl, r)
		if err != nil {
			return fmt.Errorf("failed to delete record task_id: %s error: %w", reqID, err)
		}
	} else {
		// remove rdata
		reqID, _, err := apiutils.SyncUpdate(context.Background(), cl, r, nil)
		if err != nil {
			return fmt.Errorf("failed to update record task_id: %s error: %w", reqID, err)
		}
	}
	return nil
}
