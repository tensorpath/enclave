package proxy

import (
	"context"
	"net"
	"net/http"

	"connectrpc.com/connect"
	"github.com/mdlayher/vsock"

	agentv1 "enclave/api/v1"
	"enclave/api/v1/agentv1connect"
)

type ProxyClient struct {
	client agentv1connect.AgentServiceClient
}

func NewProxyClient(cid uint32, port uint32) (*ProxyClient, error) {
	dialer := func(ctx context.Context, _ string, _ string) (net.Conn, error) {
		return vsock.Dial(cid, port, nil)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: dialer,
		},
	}

	client := agentv1connect.NewAgentServiceClient(
		httpClient,
		"http://tensor-agent",
	)

	return &ProxyClient{client: client}, nil
}

func (p *ProxyClient) StartSession(ctx context.Context, id string) (*agentv1.SessionResponse, error) {
	req := connect.NewRequest(&agentv1.StartRequest{
		SessionId: id,
	})
	resp, err := p.client.StartSession(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func (p *ProxyClient) ExecuteTool(ctx context.Context, tool, input string) (*agentv1.ToolResponse, error) {
	req := connect.NewRequest(&agentv1.ToolRequest{
		ToolName: tool,
		Input:    input,
	})
	resp, err := p.client.ExecuteTool(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func (p *ProxyClient) StopSession(ctx context.Context, id string) error {
	req := connect.NewRequest(&agentv1.StopRequest{
		SessionId: id,
	})
	_, err := p.client.StopSession(ctx, req)
	return err
}
