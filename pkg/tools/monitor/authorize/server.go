// Copyright (c) 2022 Doc.ai and/or its affiliates.
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

// Package authorize provides authz checks for incoming or returning connections.
package authorize

import (
	"crypto/x509"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"google.golang.org/grpc/peer"

	"github.com/networkservicemesh/sdk/pkg/tools/monitor/next"
	"github.com/networkservicemesh/sdk/pkg/tools/opa"
	"github.com/networkservicemesh/sdk/pkg/tools/spire"
)

type authorizeMonitorConnectionsServer struct {
	policies              policiesList
	spiffeIDConnectionMap *spire.NestedMap
}

// NewMonitorConnectionServer - returns a new authorization networkservicemesh.MonitorConnectionServer
func NewMonitorConnectionServer(opts ...Option) networkservice.MonitorConnectionServer {
	logrus.Info("Create New monitor connections auth server")
	o := &options{
		policies:              policiesList{opa.WithServiceOwnConnectionPolicy()},
		spiffeIDConnectionMap: &spire.NestedMap{},
	}
	for _, opt := range opts {
		opt(o)
	}
	var s = &authorizeMonitorConnectionsServer{
		policies:              o.policies,
		spiffeIDConnectionMap: o.spiffeIDConnectionMap,
	}
	return s
}

// MonitorOpaInput - used to pass complex structure to monitor policies
type MonitorOpaInput struct {
	SpiffeIDConnectionMap map[string][]string           `json:"spiffe_id_connection_map"`
	PathSegments          []*networkservice.PathSegment `json:"path_segments"`
	ServiceSpiffeID       string                        `json:"service_spiffe_id"`
}

func (a *authorizeMonitorConnectionsServer) MonitorConnections(in *networkservice.MonitorScopeSelector, srv networkservice.MonitorConnection_MonitorConnectionsServer) error {
	logrus.Info("auth MonitorConnections")
	ctx := srv.Context()
	p, ok := peer.FromContext(ctx)
	var cert *x509.Certificate
	if ok {
		cert = opa.ParseX509Cert(p.AuthInfo)
	}
	var input MonitorOpaInput
	var spiffeID spiffeid.ID
	if cert != nil {
		spiffeID, _ = x509svid.IDFromCert(cert)
	}
	logrus.Infof("auth MonitorConnections service spiffe id %v", spiffeID.String())
	simpleMap := make(map[string][]string)

	a.spiffeIDConnectionMap.Range(
		func(sid string, connIds spire.ConnectionMap) bool {
			connIds.Range(
				func(connId string, _ bool) bool {
					simpleMap[sid] = append(simpleMap[sid], connId)
					return true
				},
			)
			return true
		},
	)

	if len(simpleMap) == 0 {
		logrus.Info("auth MonitorConnections spiffe id map is empty")
	}
	
	input = MonitorOpaInput{
		ServiceSpiffeID:       spiffeID.String(),
		SpiffeIDConnectionMap: simpleMap,
		PathSegments:          in.PathSegments,
	}
	logrus.Infof("SpiffeID map %v", simpleMap)
	
	for k, v := range simpleMap {
		logrus.Infof("SpiffeID %v :: %v", k, v)
	}
	var seg []string
	for _, v := range in.PathSegments{
		seg = append(seg, v.GetId())
	}
	logrus.Infof("PathSegments %v", seg)
	if err := a.policies.check(ctx, input); err != nil {
		logrus.Infof("auth MonitorConnections service with spiffe id failed policy check %v", spiffeID.String())
		return err
	}
	logrus.Infof("auth MonitorConnections service with spiffe id pass policy check %v", spiffeID)
	return next.MonitorConnectionServer(ctx).MonitorConnections(in, srv)
}
