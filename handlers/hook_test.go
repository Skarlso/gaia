package handlers

import (
	"bytes"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gaia-pipeline/gaia/security"

	"github.com/gaia-pipeline/gaia"
	"github.com/gaia-pipeline/gaia/pipeline"
	"github.com/gaia-pipeline/gaia/services"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/labstack/echo"
)

type HookMockVault struct {
	security.VaultAPI
	Error error
}

func (hmv *HookMockVault) LoadSecrets() error {
	return nil
}

func (hmv *HookMockVault) Get(key string) ([]byte, error) {
	return []byte("superawesomesecretgithubpassword"), nil
}

func TestHookReceive(t *testing.T) {
	dataDir, _ := ioutil.TempDir("", "TestHookReceive")

	defer func() {
		gaia.Cfg = nil
	}()
	gaia.Cfg = &gaia.Config{
		Logger:    hclog.NewNullLogger(),
		DataPath:  dataDir,
		CAPath:    dataDir,
		VaultPath: dataDir,
		HomePath:  dataDir,
	}

	m := new(HookMockVault)
	services.MockVaultService(m)
	e := echo.New()
	defer func() { services.MockVaultService(nil) }()
	// Initialize global active pipelines
	ap := pipeline.NewActivePipelines()
	pipeline.GlobalActivePipelines = ap

	p := gaia.Pipeline{
		ID:      1,
		Name:    "Pipeline A",
		Type:    gaia.PTypeGolang,
		Created: time.Now(),
		Repo: gaia.GitRepo{
			URL: "https://github.com/Codertocat/Hello-World",
		},
	}

	ap.Append(p)

	InitHandlers(e)

	t.Run("successfully extracting path information from payload", func(t *testing.T) {
		payload, _ := ioutil.ReadFile(filepath.Join("fixtures", "hook_basic_push_payload.json"))
		req := httptest.NewRequest(echo.POST, "/api/"+apiVersion+"/pipeline/githook", bytes.NewBuffer(payload))
		req.Header.Set("Content-Type", "application/json")
		// Use https://www.freeformatter.com/hmac-generator.html#ad-output for example
		// to calculate a new sha if the fixture would change.
		req.Header.Set("x-hub-signature", "sha1=940e53f44518a6cf9ba002c29c8ace7799af2b13")
		req.Header.Set("x-github-event", "push")
		req.Header.Set("X-github-delivery", "1234asdf")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		GitWebHook(c)

		// Expected failure because repository does not exist
		if rec.Code != http.StatusInternalServerError {
			body, _ := ioutil.ReadAll(rec.Body)
			log.Println("body was: ", string(body))
			t.Fatalf("want response code %v got %v", http.StatusInternalServerError, rec.Code)
		}

		// Checking body to make sure it's the failure we want
		body, _ := ioutil.ReadAll(rec.Body)
		want := "failed to build pipeline:  repository does not exist\n"
		if string(body) != want {
			t.Fatalf("want body: %s, got: %s", want, string(body))
		}
	})
}
