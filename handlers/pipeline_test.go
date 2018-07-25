package handlers

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gaia-pipeline/gaia"
	"github.com/gaia-pipeline/gaia/pipeline"
	"github.com/gaia-pipeline/gaia/store"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/labstack/echo"
)

func TestPipelineGitLSRemote(t *testing.T) {
	dataDir, err := ioutil.TempDir("", "temp")
	if err != nil {
		t.Fatalf("error creating data dir %v", err.Error())
	}

	defer func() {
		gaia.Cfg = nil
		os.RemoveAll(dataDir)
	}()

	gaia.Cfg = &gaia.Config{
		Logger:   hclog.NewNullLogger(),
		DataPath: dataDir,
	}

	dataStore := store.NewStore()
	err = dataStore.Init()
	if err != nil {
		t.Fatalf("cannot initialize store: %v", err.Error())
	}

	e := echo.New()
	InitHandlers(e, dataStore, nil)

	t.Run("fails with invalid data", func(t *testing.T) {
		req := httptest.NewRequest(echo.POST, "/api/"+apiVersion+"/pipeline/gitlsremote", nil)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		PipelineGitLSRemote(c)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected response code %v got %v", http.StatusOK, rec.Code)
		}
	})

	t.Run("fails with invalid access", func(t *testing.T) {
		repoURL := "https://example.com"
		body := map[string]string{
			"url":      repoURL,
			"username": "admin",
			"password": "admin",
		}
		bodyBytes, _ := json.Marshal(body)
		req := httptest.NewRequest(echo.POST, "/api/"+apiVersion+"/pipeline/gitlsremote", bytes.NewBuffer(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		PipelineGitLSRemote(c)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected response code %v got %v", http.StatusOK, rec.Code)
		}
	})

	t.Run("otherwise succeed", func(t *testing.T) {
		repoURL := "https://github.com/gaia-pipeline/gaia"
		body := map[string]string{
			"url":      repoURL,
			"username": "admin",
			"password": "admin",
		}
		bodyBytes, _ := json.Marshal(body)
		req := httptest.NewRequest(echo.POST, "/api/"+apiVersion+"/pipeline/gitlsremote", bytes.NewBuffer(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		PipelineGitLSRemote(c)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected response code %v got %v", http.StatusOK, rec.Code)
		}
	})
}

func TestPipelineUpdate(t *testing.T) {
	dataDir, err := ioutil.TempDir("", "temp")
	if err != nil {
		t.Fatalf("error creating data dir %v", err.Error())
	}
	defer os.RemoveAll(dataDir)

	gaia.Cfg = &gaia.Config{
		Logger:   hclog.NewNullLogger(),
		DataPath: dataDir,
	}

	// Initialize store
	dataStore := store.NewStore()
	err = dataStore.Init()
	if err != nil {
		t.Fatalf("cannot initialize store: %v", err.Error())
	}

	// Initialize global active pipelines
	ap := pipeline.NewActivePipelines()
	pipeline.GlobalActivePipelines = ap

	// Initialize echo
	e := echo.New()
	InitHandlers(e, dataStore, nil)

	pipeline1 := gaia.Pipeline{
		ID:      1,
		Name:    "Pipeline A",
		Type:    gaia.PTypeGolang,
		Created: time.Now(),
	}

	pipeline2 := gaia.Pipeline{
		ID:      2,
		Name:    "Pipeline B",
		Type:    gaia.PTypeGolang,
		Created: time.Now(),
	}

	// Add to store
	err = dataStore.PipelinePut(&pipeline1)
	if err != nil {
		t.Fatal(err)
	}
	// Add to active pipelines
	ap.Append(pipeline1)
	// Create binary
	src := pipeline.GetExecPath(pipeline1)
	f, _ := os.Create(src)
	defer f.Close()
	defer os.Remove(src)

	t.Run("fails for non-existent pipeline", func(t *testing.T) {
		bodyBytes, _ := json.Marshal(pipeline2)
		req := httptest.NewRequest(echo.PUT, "/", bytes.NewBuffer(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPath("/api/" + apiVersion + "/pipeline/:pipelineid")
		c.SetParamNames("pipelineid")
		c.SetParamValues("2")

		PipelineUpdate(c)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected response code %v got %v", http.StatusNotFound, rec.Code)
		}
	})

	t.Run("works for existing pipeline", func(t *testing.T) {
		bodyBytes, _ := json.Marshal(pipeline1)
		req := httptest.NewRequest(echo.PUT, "/", bytes.NewBuffer(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPath("/api/" + apiVersion + "/pipeline/:pipelineid")
		c.SetParamNames("pipelineid")
		c.SetParamValues("1")

		PipelineUpdate(c)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected response code %v got %v", http.StatusNotFound, rec.Code)
		}
	})

}

func TestPipelineDelete(t *testing.T) {
	dataDir, err := ioutil.TempDir("", "temp")
	if err != nil {
		t.Fatalf("error creating data dir %v", err.Error())
	}
	defer os.RemoveAll(dataDir)

	gaia.Cfg = &gaia.Config{
		Logger:       hclog.NewNullLogger(),
		DataPath:     dataDir,
		PipelinePath: dataDir,
	}

	// Initialize store
	dataStore := store.NewStore()
	err = dataStore.Init()
	if err != nil {
		t.Fatalf("cannot initialize store: %v", err.Error())
	}

	// Initialize global active pipelines
	ap := pipeline.NewActivePipelines()
	pipeline.GlobalActivePipelines = ap

	// Initialize echo
	e := echo.New()
	InitHandlers(e, dataStore, nil)

	p := gaia.Pipeline{
		ID:      1,
		Name:    "Pipeline A",
		Type:    gaia.PTypeGolang,
		Created: time.Now(),
	}

	// Add to store
	err = dataStore.PipelinePut(&p)
	if err != nil {
		t.Fatal(err)
	}
	// Add to active pipelines
	ap.Append(p)
	// Create binary
	src := pipeline.GetExecPath(p)
	f, _ := os.Create(src)
	defer f.Close()
	defer os.Remove(src)

	ioutil.WriteFile(src, []byte("testcontent"), 0666)

	t.Run("fails for non-existent pipeline", func(t *testing.T) {
		req := httptest.NewRequest(echo.DELETE, "/", nil)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPath("/api/" + apiVersion + "/pipeline/:pipelineid")
		c.SetParamNames("pipelineid")
		c.SetParamValues("2")

		PipelineDelete(c)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected response code %v got %v", http.StatusNotFound, rec.Code)
		}
	})

	t.Run("works for existing pipeline", func(t *testing.T) {
		req := httptest.NewRequest(echo.DELETE, "/", nil)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPath("/api/" + apiVersion + "/pipeline/:pipelineid")
		c.SetParamNames("pipelineid")
		c.SetParamValues("1")

		PipelineDelete(c)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected response code %v got %v", http.StatusNotFound, rec.Code)
		}
	})

}
