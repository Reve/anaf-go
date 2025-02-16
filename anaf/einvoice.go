package anaf

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type EinvoiceApi struct {
	URL          string
	AccessToken  string
	RefreshToken string
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Auth         *AnafAuth
	httpClient   *http.Client
	Testing      bool
}

func NewEinvoiceApi(accessToken, refreshToken, clientID, clientSecret, redirectURI string, testing bool) *EinvoiceApi {
	e := &EinvoiceApi{
		URL:          "https://api.anaf.ro/prod/FCTEL/rest",
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURI:  redirectURI,
		Auth:         NewAnafAuth(clientID, clientSecret, redirectURI),
		httpClient:   http.DefaultClient,
		Testing:      testing,
	}

	// If testing environment variable or constructor param is set
	if os.Getenv("PYANAF_TESTING") == "true" || testing {
		e.URL = "https://api.anaf.ro/test/FCTEL/rest"
	}

	return e
}

func (e *EinvoiceApi) isTokenExpired() bool {
	token, _, err := new(jwt.Parser).ParseUnverified(e.AccessToken, jwt.MapClaims{})

	if err != nil {
		return true
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if expVal, ok := claims["exp"].(float64); ok {
			expTime := time.Unix(int64(expVal), 0)
			return time.Now().After(expTime)
		}
	}

	return true
}

func (e *EinvoiceApi) refreshAccessToken(ctx context.Context) error {
	tokenData, err := e.Auth.RefreshAnafToken(ctx, e.RefreshToken)

	if err != nil {
		return err
	}

	if at, ok := tokenData["access_token"].(string); ok {
		e.AccessToken = at
	}

	if rt, ok := tokenData["refresh_token"].(string); ok {
		e.RefreshToken = rt
	}

	return nil
}

func (e *EinvoiceApi) ensureTokenValid(ctx context.Context) error {
	if e.isTokenExpired() {
		return e.refreshAccessToken(ctx)
	}
	return nil
}

func (e *EinvoiceApi) Hello(ctx context.Context) (string, error) {
	if err := e.ensureTokenValid(ctx); err != nil {
		return "", err
	}

	url := "https://api.anaf.ro/TestOauth/jaxrs/hello?name=valoare/hello"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+e.AccessToken)

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return "", &AnafResponseError{Msg: fmt.Sprintf("Error saying hello: %v", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return "", &AnafResponseError{Msg: "Unauthorized", Code: resp.StatusCode}
		}
		return "", &AnafResponseError{Msg: "Error saying hello", Code: resp.StatusCode}
	}
	return "OK", nil
}

func (e *EinvoiceApi) ListMessages(ctx context.Context, cif string, days int, filter string) (string, error) {
	if err := e.ensureTokenValid(ctx); err != nil {
		return "", err
	}

	u := fmt.Sprintf("%s/listaMesajeFactura?cif=%s&zile=%d", e.URL, cif, days)
	if filter != "" {
		u += "&filtru=" + filter
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+e.AccessToken)

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return "", &AnafResponseError{Msg: fmt.Sprintf("Error listing messages: %v", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return "", &AnafResponseError{Msg: "Unauthorized", Code: resp.StatusCode}
		}
		return "", &AnafResponseError{Msg: "Error listing messages", Code: resp.StatusCode}
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	// Python code did: json.dumps(response.read().decode()) -> basically a string
	return string(bodyBytes), nil
}

func (e *EinvoiceApi) ListMessagesPaginated(ctx context.Context, cif string, startTime, endTime string, page int, filter string) (string, error) {
	if err := e.ensureTokenValid(ctx); err != nil {
		return "", err
	}

	u := fmt.Sprintf(
		"%s/listaMesajePaginatieFactura?cif=%s&startTime=%s&endTime=%s&pagina=%d",
		e.URL, cif, startTime, endTime, page,
	)
	if filter != "" {
		u += "&filtru=" + filter
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+e.AccessToken)

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return "", &AnafResponseError{Msg: fmt.Sprintf("Error listing messages: %v", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return "", &AnafResponseError{Msg: "Unauthorized", Code: resp.StatusCode}
		}
		return "", &AnafResponseError{Msg: "Error listing messages", Code: resp.StatusCode}
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(bodyBytes), nil
}

func (e *EinvoiceApi) CheckUpload(ctx context.Context, uploadID string) (*xmlElement, error) {
	if err := e.ensureTokenValid(ctx); err != nil {
		return nil, err
	}

	u := fmt.Sprintf("%s/stareMesaj?id_incarcare=%s", e.URL, uploadID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+e.AccessToken)

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, &AnafResponseError{Msg: fmt.Sprintf("Error checking upload status: %v", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return nil, &AnafResponseError{Msg: "Unauthorized", Code: resp.StatusCode}
		}
		return nil, &AnafResponseError{Msg: "Error checking upload status", Code: resp.StatusCode}
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var root xmlElement
	if err := xml.Unmarshal(bodyBytes, &root); err != nil {
		return nil, err
	}

	return &root, nil
}

type xmlElement struct {
	XMLName  xml.Name
	Attrs    []xml.Attr   `xml:",any,attr"`
	Children []xmlElement `xml:",any"`
	Content  string       `xml:",chardata"`
}

func (e *EinvoiceApi) DownloadInvoice(ctx context.Context, uploadID string) ([]byte, string, error) {
	if err := e.ensureTokenValid(ctx); err != nil {
		return nil, "", err
	}

	u := fmt.Sprintf("%s/descarcare?id=%s", e.URL, uploadID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", "Bearer "+e.AccessToken)

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, "", &AnafResponseError{Msg: fmt.Sprintf("Error downloading eInvoice: %v", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return nil, "", &AnafResponseError{Msg: "Unauthorized", Code: resp.StatusCode}
		}
		return nil, "", &AnafResponseError{Msg: "Error downloading eInvoice", Code: resp.StatusCode}
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}

	// Python code checks Content-Disposition for a filename
	filename := ""
	cd := resp.Header.Get("Content-Disposition")
	if cd != "" {
		// cd might look like: attachment; filename="invoice.pdf"
		// naive parse:
		parts := strings.Split(cd, "filename=")
		if len(parts) > 1 {
			filename = strings.Trim(parts[1], `";`)
		}
	}
	return data, filename, nil
}

func (e *EinvoiceApi) DownloadInvoicePDF(ctx context.Context, xmlString string) ([]byte, error) {
	if err := e.ensureTokenValid(ctx); err != nil {
		return nil, err
	}

	// Example endpoint: https://api.anaf.ro/prod/FCTEL/rest/transformare/FACT1
	// Python: "url = f"{self.url}/transformare/FACT1"
	// But be sure you have "FACT1" or the correct transform param
	u := fmt.Sprintf("%s/transformare/FACT1", e.URL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewBufferString(xmlString))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+e.AccessToken)
	req.Header.Set("Content-Type", "text/plain")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, &AnafResponseError{Msg: fmt.Sprintf("Error downloading eInvoice PDF: %v", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return nil, &AnafResponseError{Msg: "Unauthorized", Code: resp.StatusCode}
		}
		var errObj map[string]interface{}

		if json.NewDecoder(resp.Body).Decode(&errObj) == nil {
			return nil, fmt.Errorf("error downloading PDF: %v", errObj)
		}

		return nil, &AnafResponseError{Msg: "Error downloading PDF", Code: resp.StatusCode}
	}

	pdfData, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	return pdfData, nil
}

func (e *EinvoiceApi) UploadInvoice(ctx context.Context, xmlString, standard, cif string, external, selfInvoice bool) (string, error) {
	if err := e.ensureTokenValid(ctx); err != nil {
		return "", err
	}

	// Example endpoint: https://api.anaf.ro/prod/FCTEL/rest/upload
	u := fmt.Sprintf("%s/upload", e.URL)

	q := url.Values{}
	q.Set("standard", standard)
	q.Set("cif", cif)

	if external {
		q.Set("external", "DA")
	}

	if selfInvoice {
		q.Set("selfInvoice", "DA")
	}

	u += "?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewBufferString(xmlString))

	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+e.AccessToken)
	req.Header.Set("Content-Type", "text/plain")

	resp, err := e.httpClient.Do(req)

	if err != nil {
		return "", &AnafResponseError{Msg: fmt.Sprintf("Error uploading invoice: %v", err)}
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return "", &AnafResponseError{Msg: "Unauthorized", Code: resp.StatusCode}
		}
		return "", &AnafResponseError{Msg: "Error uploading invoice", Code: resp.StatusCode}
	}

	bodyBytes, err := io.ReadAll(resp.Body)

	if err != nil {
		return "", err
	}

	var root xmlElement

	if err := xml.Unmarshal(bodyBytes, &root); err != nil {
		return "", err
	}

	xmlMap := parseElement(root)
	jsonBytes, err := json.Marshal(xmlMap)

	if err != nil {
		return "", err
	}

	return string(jsonBytes), nil
}

func parseElement(el xmlElement) map[string]interface{} {
	out := make(map[string]interface{})

	for _, attr := range el.Attrs {
		out[attr.Name.Local] = attr.Value
	}

	if strings.TrimSpace(el.Content) != "" {
		out["content"] = el.Content
	}

	if len(el.Children) > 0 {
		childSlice := make([]interface{}, 0, len(el.Children))
		for _, c := range el.Children {
			childSlice = append(childSlice, parseElement(c))
		}
		out["children"] = childSlice
	}
	return out
}
