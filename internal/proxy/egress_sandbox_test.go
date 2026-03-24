package proxy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStdioSetEnv_ReplaceExisting(t *testing.T) {
	env := []string{"HOME=/home/user", "HTTP_PROXY=http://old:1234", "PATH=/usr/bin"}
	result := stdioSetEnv(env, "HTTP_PROXY", "http://127.0.0.1:8083")

	assert.Len(t, result, 3)
	assert.Equal(t, "HTTP_PROXY=http://127.0.0.1:8083", result[1])
}

func TestStdioSetEnv_AppendNew(t *testing.T) {
	env := []string{"HOME=/home/user"}
	result := stdioSetEnv(env, "HTTPS_PROXY", "http://127.0.0.1:8083")

	assert.Len(t, result, 2)
	assert.Equal(t, "HTTPS_PROXY=http://127.0.0.1:8083", result[1])
}

func TestStdioSetEnv_EmptyValue(t *testing.T) {
	env := []string{"NO_PROXY=localhost"}
	result := stdioSetEnv(env, "NO_PROXY", "")

	assert.Len(t, result, 1)
	assert.Equal(t, "NO_PROXY=", result[0])
}

func TestStdioSetEnv_NilSlice(t *testing.T) {
	result := stdioSetEnv(nil, "KEY", "value")

	assert.Len(t, result, 1)
	assert.Equal(t, "KEY=value", result[0])
}

func TestStdioProxy_EnvField(t *testing.T) {
	p := &StdioProxy{
		agent: "test-agent",
		Env: map[string]string{
			"HTTP_PROXY":  "http://127.0.0.1:8083",
			"HTTPS_PROXY": "http://127.0.0.1:8083",
		},
	}

	assert.Len(t, p.Env, 2)
	assert.Equal(t, "http://127.0.0.1:8083", p.Env["HTTP_PROXY"])
	assert.Equal(t, "http://127.0.0.1:8083", p.Env["HTTPS_PROXY"])
}

func TestStdioProxy_EnvFieldNil(t *testing.T) {
	p := &StdioProxy{
		agent: "test-agent",
	}

	assert.Nil(t, p.Env)
	assert.Len(t, p.Env, 0)
}
