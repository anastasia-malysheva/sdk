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
)

type authorizeMonitorConnectionsServer struct {
	policies              policiesList
	spiffeIDConnectionMap SpiffeIDConnectionMap
}

// NewMonitorConnectionServer - returns a new authorization networkservicemesh.MonitorConnectionServer
func NewMonitorConnectionServer(spiffeIDConnectionMap *SpiffeIDConnectionMap, opts ...Option) networkservice.MonitorConnectionServer {
	logrus.Info("Auth MonitorConnectionSercer")

	var s = &authorizeMonitorConnectionsServer{
		policies: []Policy{
			opa.WithServiceOwnConnectionPolicy(),
		},
		spiffeIDConnectionMap: *spiffeIDConnectionMap,
	}
	for _, o := range opts {
		o.apply(&s.policies)
	}
	return s
}

type MonitorOpaInput struct {
	SpiffeIDConnectionMap map[string][]string         `json:"spiffe_id_connection_map"`
	PathSegments          []*networkservice.PathSegment `json:"path_segments"`
	ServiceSpiffeID       string                        `json:"service_spiffe_id"`
}

func (a *authorizeMonitorConnectionsServer) MonitorConnections(in *networkservice.MonitorScopeSelector, srv networkservice.MonitorConnection_MonitorConnectionsServer) error {
	logrus.Info("Auth MonitorConnections")
	ctx := srv.Context()
	p, ok := peer.FromContext(ctx)
	var cert *x509.Certificate
	if ok {
		cert = opa.ParseX509Cert(p.AuthInfo)
	}
	var input MonitorOpaInput
	var spiffeID spiffeid.ID
	var err error
	if cert != nil {
		spiffeID, err = x509svid.IDFromCert(cert)
		if err == nil {
			logrus.Infof("Auth spiffemap :%v", a.spiffeIDConnectionMap)
			logrus.Infof("Auth PathSegments :%v", in.PathSegments)
		}
	}
	simpleMap := make(map[string][]string)
	a.spiffeIDConnectionMap.Range(
		func( k string, v []string) bool {
			simpleMap[k] = v
			return true
		},
	)

	input = MonitorOpaInput{
		ServiceSpiffeID:       spiffeID.String(),
		SpiffeIDConnectionMap: simpleMap,
		PathSegments:          in.PathSegments,
	}

	if err := a.policies.check(ctx, input); err != nil {
		return err
	}

	return next.MonitorConnectionServer(ctx).MonitorConnections(in, srv)
}
