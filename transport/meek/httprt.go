package meek

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/http"
)

type httpTripperClient struct {
	url          string
	roundTripper http.RoundTripper
}

func (c *httpTripperClient) RoundTrip(ctx context.Context, req Request) (resp Response, err error) {
	connectionTagStr := base64.RawURLEncoding.EncodeToString(req.ConnectionTag)

	httpRequest, err := http.NewRequestWithContext(ctx, "POST", c.url, bytes.NewReader(req.Data))
	if err != nil {
		return
	}
	httpRequest.Header.Set("X-Session-ID", connectionTagStr)

	httpResp, err := c.roundTripper.RoundTrip(httpRequest)
	if err != nil {
		return
	}
	defer httpResp.Body.Close()

	result, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return
	}
	return Response{Data: result}, err
}
