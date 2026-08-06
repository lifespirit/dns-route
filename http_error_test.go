package main

import (
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRenderErrorBuffersTemplateBeforeWriting(t *testing.T) {
	original := templates
	t.Cleanup(func() { templates = original })
	templates = template.Must(template.New("error.html.tmpl").Funcs(template.FuncMap{
		"fail": func() (string, error) { return "", errors.New("template failed") },
	}).Parse(`prefix{{fail}}`))

	recorder := httptest.NewRecorder()
	renderError(recorder, http.StatusTeapot, errors.New("boom"))
	result := recorder.Result()
	defer result.Body.Close()
	if result.StatusCode != http.StatusTeapot {
		t.Fatalf("status=%d, want %d", result.StatusCode, http.StatusTeapot)
	}
	body := recorder.Body.String()
	if strings.Contains(body, "prefix") {
		t.Fatalf("partial template leaked into response: %q", body)
	}
	if !strings.Contains(body, "boom") {
		t.Fatalf("fallback error missing from response: %q", body)
	}
}

func TestRenderTemplateResponseBuffersBeforeWriting(t *testing.T) {
	original := templates
	t.Cleanup(func() { templates = original })
	templates = template.Must(template.New("page.html.tmpl").Funcs(template.FuncMap{
		"fail": func() (string, error) { return "", errors.New("template failed") },
	}).Parse(`prefix{{fail}}`))

	recorder := httptest.NewRecorder()
	err := renderTemplateResponse(recorder, http.StatusOK, "page.html.tmpl", struct{}{})
	if err == nil {
		t.Fatal("template failure unexpectedly ignored")
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("recorder status=%d before any response write", recorder.Code)
	}
	if recorder.Body.Len() != 0 {
		t.Fatalf("partial template leaked into response: %q", recorder.Body.String())
	}
}
