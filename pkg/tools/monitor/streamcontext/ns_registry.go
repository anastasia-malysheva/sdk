// Copyright (c) 2020 Doc.ai and/or its affiliates.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package streamcontext

import (
	"context"

	"github.com/networkservicemesh/api/pkg/api/networkservice"

	"github.com/networkservicemesh/sdk/pkg/tools/extend"
)

type monitorConnection_MonitorConnectionsServer struct {
	networkservice.MonitorConnection_MonitorConnectionsServer
	ctx context.Context
}

func (s *monitorConnection_MonitorConnectionsServer) Context() context.Context {
	return s.ctx
}

// MonitorConnectionMonitorConnectionsServer extends context for MonitorConnection_MonitorConnectionsServer
func MonitorConnectionMonitorConnectionsServer(ctx context.Context, server networkservice.MonitorConnection_MonitorConnectionsServer) networkservice.MonitorConnection_MonitorConnectionsServer {
	if server != nil {
		ctx = extend.WithValuesFromContext(server.Context(), ctx)
	}

	return &monitorConnection_MonitorConnectionsServer{
		ctx: ctx,
		MonitorConnection_MonitorConnectionsServer: server,
	}
}

// todo add same for the client

type monitorConnection_MonitorConnectionsClient struct {
	networkservice.MonitorConnection_MonitorConnectionsClient
	ctx context.Context
}

func (s *monitorConnection_MonitorConnectionsClient) Context() context.Context {
	return s.ctx
}

// MonitorConnectionMonitorConnectionsClient extends context for MonitorConnection_MonitorConnectionsClient
func MonitorConnectionMonitorConnectionsClient(ctx context.Context, client networkservice.MonitorConnection_MonitorConnectionsClient) networkservice.MonitorConnection_MonitorConnectionsClient {
	if client != nil {
		ctx = extend.WithValuesFromContext(client.Context(), ctx)
	}

	return &monitorConnection_MonitorConnectionsClient{
		ctx: ctx,
		MonitorConnection_MonitorConnectionsClient: client,
	}
}