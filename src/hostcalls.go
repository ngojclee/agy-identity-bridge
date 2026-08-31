package main

import (
	"encoding/json"
	"fmt"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *envelopeError  `json:"error,omitempty"`
}

type envelopeError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type hostAuthListResponse struct {
	Files []pluginapi.HostAuthFileEntry `json:"files"`
}

type hostAuthGetResponse struct {
	AuthIndex string          `json:"auth_index"`
	Name      string          `json:"name,omitempty"`
	Path      string          `json:"path,omitempty"`
	JSON      json.RawMessage `json:"json"`
}

// hostCall invokes a CPA host callback and unwraps its JSON envelope.
func hostCall(method string, payload any) (json.RawMessage, error) {
	var request []byte
	if payload != nil {
		var errMarshal error
		request, errMarshal = json.Marshal(payload)
		if errMarshal != nil {
			return nil, errMarshal
		}
	}
	raw, ok := callHost(method, request)
	if len(raw) == 0 {
		if !ok {
			return nil, fmt.Errorf("host call %s failed", method)
		}
		return nil, nil
	}
	var response envelope
	if errUnmarshal := json.Unmarshal(raw, &response); errUnmarshal != nil {
		return nil, fmt.Errorf("host call %s returned invalid envelope: %w", method, errUnmarshal)
	}
	if !response.OK {
		if response.Error != nil {
			return nil, fmt.Errorf("host call %s: %s: %s", method, response.Error.Code, response.Error.Message)
		}
		return nil, fmt.Errorf("host call %s failed", method)
	}
	return response.Result, nil
}

func hostLog(level, message string, fields map[string]any) {
	payload := map[string]any{
		"level":   level,
		"message": "agy-identity-bridge: " + message,
	}
	if len(fields) > 0 {
		payload["fields"] = fields
	}
	_, _ = hostCall(pluginabi.MethodHostLog, payload)
}

func listHostAuthFiles() ([]pluginapi.HostAuthFileEntry, error) {
	raw, errCall := hostCall(pluginabi.MethodHostAuthList, map[string]any{})
	if errCall != nil {
		return nil, errCall
	}
	if len(raw) == 0 {
		return nil, nil
	}
	var response hostAuthListResponse
	if errUnmarshal := json.Unmarshal(raw, &response); errUnmarshal != nil {
		return nil, fmt.Errorf("decode host auth list: %w", errUnmarshal)
	}
	return response.Files, nil
}

func getHostAuthJSON(authIndex string) (map[string]any, error) {
	raw, errCall := hostCall(pluginabi.MethodHostAuthGet, pluginapi.HostAuthGetRequest{
		AuthIndex: authIndex,
	})
	if errCall != nil {
		return nil, errCall
	}
	var response hostAuthGetResponse
	if errUnmarshal := json.Unmarshal(raw, &response); errUnmarshal != nil {
		return nil, fmt.Errorf("decode host auth details: %w", errUnmarshal)
	}
	var details map[string]any
	if len(response.JSON) == 0 || string(response.JSON) == "null" {
		return nil, nil
	}
	if errUnmarshal := json.Unmarshal(response.JSON, &details); errUnmarshal != nil {
		return nil, fmt.Errorf("decode host auth JSON: %w", errUnmarshal)
	}
	return details, nil
}
