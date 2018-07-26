package security

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/gaia-pipeline/gaia"
	hclog "github.com/hashicorp/go-hclog"
)

func TestNewVault(t *testing.T) {
	tmp := os.TempDir()
	gaia.Cfg = &gaia.Config{}
	gaia.Cfg.VaultPath = tmp
	gaia.Cfg.CAPath = tmp
	buf := new(bytes.Buffer)
	gaia.Cfg.Logger = hclog.New(&hclog.LoggerOptions{
		Level:  hclog.Trace,
		Output: buf,
		Name:   "Gaia",
	})
	c, _ := InitCA()
	v, err := NewVault(c)
	if err != nil {
		t.Fatal(err)
	}
	if v.path != filepath.Join(gaia.Cfg.VaultPath, vaultName) {
		t.Fatal("file path of vault file did not equal expected. was:", v.path)
	}
}

func TestAddAndGet(t *testing.T) {
	tmp := os.TempDir()
	gaia.Cfg = &gaia.Config{}
	gaia.Cfg.VaultPath = tmp
	gaia.Cfg.CAPath = tmp
	buf := new(bytes.Buffer)
	gaia.Cfg.Logger = hclog.New(&hclog.LoggerOptions{
		Level:  hclog.Trace,
		Output: buf,
		Name:   "Gaia",
	})
	c, _ := InitCA()
	v, err := NewVault(c)
	if err != nil {
		t.Fatal(err)
	}
	v.Add("key", []byte("value"))
	val, err := v.Get("key")
	if bytes.Compare(val, []byte("value")) != 0 {
		t.Fatal("value didn't match expected of 'value'. was: ", string(val))
	}
}

func TestCloseLoadSecrets(t *testing.T) {
	tmp := os.TempDir()
	gaia.Cfg = &gaia.Config{}
	gaia.Cfg.VaultPath = tmp
	gaia.Cfg.CAPath = tmp
	buf := new(bytes.Buffer)
	gaia.Cfg.Logger = hclog.New(&hclog.LoggerOptions{
		Level:  hclog.Trace,
		Output: buf,
		Name:   "Gaia",
	})
	c, _ := InitCA()
	v, err := NewVault(c)
	if err != nil {
		t.Fatal(err)
	}
	v.Add("key1", []byte("value1"))
	v.Add("key2", []byte("value2"))
	err = v.SaveSecrets()
	if err != nil {
		t.Fatal(err)
	}
	v.data = make(map[string][]byte, 0)
	err = v.LoadSecrets()
	if err != nil {
		t.Fatal(err)
	}
	val, err := v.Get("key1")
	if bytes.Compare(val, []byte("value1")) != 0 {
		t.Fatal("could not properly retrieve value for key1. was:", string(val))
	}
}

func TestCloseLoadSecretsWithInvalidPassword(t *testing.T) {
	tmp := os.TempDir()
	gaia.Cfg = &gaia.Config{}
	gaia.Cfg.VaultPath = tmp
	gaia.Cfg.CAPath = tmp
	buf := new(bytes.Buffer)
	gaia.Cfg.Logger = hclog.New(&hclog.LoggerOptions{
		Level:  hclog.Trace,
		Output: buf,
		Name:   "Gaia",
	})
	c, _ := InitCA()
	v, err := NewVault(c)
	if err != nil {
		t.Fatal(err)
	}
	v.cert = []byte("test")
	v.Add("key1", []byte("value1"))
	v.Add("key2", []byte("value2"))
	err = v.SaveSecrets()
	if err != nil {
		t.Fatal(err)
	}
	v.data = make(map[string][]byte, 0)
	v.cert = []byte("invalid")
	err = v.LoadSecrets()
	if err == nil {
		t.Fatal("error should not have been nil.")
	}
	expected := "possible mistyped password"
	if err.Error() != expected {
		t.Fatalf("didn't get the right error. expected: \n'%s'\n error was: \n'%s'\n", expected, err.Error())
	}
}

func TestAnExistingVaultFileIsNotOverwritten(t *testing.T) {
	tmp := "."
	gaia.Cfg = &gaia.Config{}
	gaia.Cfg.VaultPath = tmp
	gaia.Cfg.CAPath = tmp
	buf := new(bytes.Buffer)
	gaia.Cfg.Logger = hclog.New(&hclog.LoggerOptions{
		Level:  hclog.Trace,
		Output: buf,
		Name:   "Gaia",
	})
	c, _ := InitCA()
	v, err := NewVault(c)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(vaultName)
	defer os.Remove("ca.crt")
	defer os.Remove("ca.key")
	v.cert = []byte("test")
	v.Add("test", []byte("value"))
	v.SaveSecrets()
	v2, _ := NewVault(c)
	if v2.path != v.path {
		t.Fatal("paths should have equaled. were: ", v2.path, v.path)
	}
	v2.cert = []byte("test")
	v2.LoadSecrets()
	if err != nil {
		t.Fatal(err)
	}
	value, err := v2.Get("test")
	if err != nil {
		t.Fatal("couldn't retrieve value: ", err)
	}
	if bytes.Compare(value, []byte("value")) != 0 {
		t.Fatal("test value didn't equal expected of 'value'. was:", string(value))
	}
}

func TestRemovingFromTheVault(t *testing.T) {
	tmp := os.TempDir()
	gaia.Cfg = &gaia.Config{}
	gaia.Cfg.VaultPath = tmp
	gaia.Cfg.CAPath = tmp
	c, _ := InitCA()
	v, err := NewVault(c)
	if err != nil {
		t.Fatal(err)
	}
	v.Add("key1", []byte("value1"))
	v.Add("key2", []byte("value2"))
	err = v.SaveSecrets()
	if err != nil {
		t.Fatal(err)
	}
	v.data = make(map[string][]byte, 0)
	err = v.LoadSecrets()
	if err != nil {
		t.Fatal(err)
	}
	val, err := v.Get("key1")
	if bytes.Compare(val, []byte("value1")) != 0 {
		t.Fatal("could not properly retrieve value for key1. was:", string(val))
	}
	v.Remove("key1")
	v.SaveSecrets()
	v.data = make(map[string][]byte, 0)
	v.LoadSecrets()
	_, err = v.Get("key1")
	if err == nil {
		t.Fatal("should have failed to retrieve non-existant key")
	}
	expected := "key 'key1' not found in vault"
	if err.Error() != expected {
		t.Fatalf("got the wrong error message. expected: \n'%s'\n was: \n'%s'\n", expected, err.Error())
	}
}

func TestGetAll(t *testing.T) {
	tmp := os.TempDir()
	gaia.Cfg = &gaia.Config{}
	gaia.Cfg.VaultPath = tmp
	gaia.Cfg.CAPath = tmp
	c, _ := InitCA()
	v, err := NewVault(c)
	if err != nil {
		t.Fatal(err)
	}
	v.Add("key1", []byte("value1"))
	err = v.SaveSecrets()
	if err != nil {
		t.Fatal(err)
	}
	err = v.LoadSecrets()
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{"key1"}
	actual := v.GetAll()
	if !reflect.DeepEqual(expected, actual) {
		t.Fatalf("actual did not equal expected. actual was: %+v, expected: %+v.", actual, expected)
	}
}

func TestEditValueWithAddingItAgain(t *testing.T) {
	tmp := os.TempDir()
	gaia.Cfg = &gaia.Config{}
	gaia.Cfg.VaultPath = tmp
	gaia.Cfg.CAPath = tmp
	c, _ := InitCA()
	v, _ := NewVault(c)
	v.Add("key1", []byte("value1"))
	v.SaveSecrets()
	v.data = make(map[string][]byte, 0)
	v.LoadSecrets()
	v.Add("key1", []byte("value2"))
	v.SaveSecrets()
	v.data = make(map[string][]byte, 0)
	v.LoadSecrets()
	val, _ := v.Get("key1")
	if bytes.Compare(val, []byte("value2")) != 0 {
		t.Fatal("value should have equaled expected 'value2'. was: ", string(val))
	}
}