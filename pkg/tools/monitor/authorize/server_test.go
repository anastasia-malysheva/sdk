// Copyright (c) 2020-2021 Doc.ai and/or its affiliates.
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

package authorize_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"go.uber.org/goleak"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/networkservicemesh/sdk/pkg/tools/monitor/authorize"
	"github.com/networkservicemesh/sdk/pkg/tools/opa"

	"github.com/networkservicemesh/api/pkg/api/networkservice"

	"github.com/stretchr/testify/require"
)

const (
	// certPem is a X.509 certificate with spiffeId = "spiffe://test.com/workload"
	certPem = `-----BEGIN CERTIFICATE-----
MIIBvjCCAWWgAwIBAgIQbnFakUhzr52nHoLGltZDyDAKBggqhkjOPQQDAjAdMQsw
CQYDVQQGEwJVUzEOMAwGA1UEChMFU1BJUkUwHhcNMjAwMTAxMDEwMTAxWhcNMzAw
MTAxMDEwMTAxWjAdMQswCQYDVQQGEwJVUzEOMAwGA1UEChMFU1BJUkUwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAASlFpbASv+NIyVdFwTp22JR5gx7D6LJ01Z8Wz0S
ZiBneWRAcYUBBQY6zKwr/RQtCDxUcFfFyq4zEfUD29a5Phnoo4GGMIGDMA4GA1Ud
DwEB/wQEAwIDqDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0T
AQH/BAIwADAdBgNVHQ4EFgQUJJpYlJa1eNEcks+zJcwKClopSAowJQYDVR0RBB4w
HIYac3BpZmZlOi8vdGVzdC5jb20vd29ya2xvYWQwCgYIKoZIzj0EAwIDRwAwRAIg
Dk6tlURSF8ULhNbnyUxFQ33rDic2dX8jOIstV2dWErwCIDRH2yw0swTcUMQWYgHy
aMp+T747AZGjOEfwHb9/w+7m
-----END CERTIFICATE-----
`
	spiffeID1 = "spiffe://test.com/workload"
	spiffeID2 = "spiffe://test.com/anotherWorkload"
)

func getContextWithTLSCert() (context.Context, error) {
	block, _ := pem.Decode([]byte(certPem))
	x509cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	authInfo := &credentials.TLSInfo{
		State: tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{x509cert},
		},
	}

	return peer.NewContext(context.Background(), &peer.Peer{AuthInfo: authInfo}), nil
}

func testPolicy() authorize.Policy {
	return opa.WithPolicyFromSource(`
		package test
	
		default allow = false
	
		allow {
			conn_ids := {y | y = input.spiffe_id_connection_map[input.service_spiffe_id][_]}
			path_conn_ids := {x | x = input.path_segments[_].id}
			conn_ids == path_conn_ids
		}
`, "allow", opa.True)
}

type testEmptyMCMCServer struct {
	networkservice.MonitorConnection_MonitorConnectionsServer
	context context.Context
}

func (t *testEmptyMCMCServer) Send(event *networkservice.ConnectionEvent) error {
	return nil
}

func (t *testEmptyMCMCServer) Context() context.Context {
	return t.context
}
func TestAuthzEndpoint(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })
	suits := []struct {
		name              string
		baseCtx           bool
		pathSegments      []*networkservice.PathSegment
		spiffeIDConnMap         map[string][]string
		denied            bool
	}{
		{
			name:        	 	"simple positive test without peer context",
			baseCtx:     	 	false,
			pathSegments: 	 	make([]*networkservice.PathSegment, 0),
			denied:      	 	false,
		},
		{
			name:        		"simple positive test with peer context",
			baseCtx:     		false,
			pathSegments: 		make([]*networkservice.PathSegment, 0),
		 	denied:      		false,
		 },
		 {
		 	name:        		"positive test with nonempty objects",
		 	baseCtx:     		true,
		 	pathSegments: 		[]*networkservice.PathSegment{{Id: "conn1"}},
			spiffeIDConnMap:    map[string][]string{spiffeID1: {"conn1"}},
		 	denied:      		false,
		 },
		 {
		 	name:        		"positive test with several spiffeIds objects",
		 	baseCtx:     		true,
		 	pathSegments: 		[]*networkservice.PathSegment{{Id: "conn1"}},
		 	spiffeIDConnMap:    map[string][]string{spiffeID1: {"conn1"}, spiffeID2: {"conn2"}},
			denied:      		false,
		 },
		{
			name:        		"negative test without peer context",
			baseCtx:     		false,
			pathSegments: 		[]*networkservice.PathSegment{{Id: "conn1"}},
			spiffeIDConnMap:    map[string][]string{spiffeID1: {"conn1"}},
			denied:      		true,
		},
		{
			name:         		"negative test with empty path",
			baseCtx:      		true,
			pathSegments: 		make([]*networkservice.PathSegment, 0),
			spiffeIDConnMap:    map[string][]string{spiffeID1: {"conn1"}},
			denied:       		true,
		},
		{
			name:        		"negative test without peer context",
			baseCtx:     		false,
			pathSegments: 		[]*networkservice.PathSegment{{Id: "conn1"}},
			spiffeIDConnMap: 	make(map[string][]string),
			denied:      		true,
		},
		{
			name:        		"negative test with wrong spiffeID in the map",
			baseCtx:     		true,
			pathSegments: 		[]*networkservice.PathSegment{{Id: "conn1"}},
			spiffeIDConnMap: 	map[string][]string{spiffeID2: {"conn1"}},
			denied:      		true,
		},

	}

	for i := range suits {
		s := suits[i]
		t.Run(s.name, func(t *testing.T) {
			var baseCtx context.Context
			var err error
			baseCtx = context.Background()
			if s.baseCtx {
				baseCtx, err = getContextWithTLSCert()
				require.NoError(t, err)
			}
			spiffeIDConnectionMap := authorize.SpiffeIDConnectionMap{}
			for k, v := range s.spiffeIDConnMap{
				spiffeIDConnectionMap.Store(k, v)
			}
			ctx, cancel := context.WithTimeout(baseCtx, time.Second)
			defer cancel()
			srv := authorize.NewMonitorConnectionServer(
				&spiffeIDConnectionMap, authorize.WithPolicies(testPolicy()))
			checkResult := func(err error) {
				if !s.denied {
					require.Nil(t, err, "monitorConnections expected to be not denied: ")
					return
				}
				require.NotNil(t, err, "monitorConnections expected to be denied")
				s, ok := status.FromError(err)
				require.True(t, ok, "error without error status code"+err.Error())
				require.Equal(t, s.Code(), codes.PermissionDenied, "wrong error status code")
			}

			err = srv.MonitorConnections(
				&networkservice.MonitorScopeSelector{PathSegments: s.pathSegments}, &testEmptyMCMCServer{context: ctx})
			checkResult(err)
		})
	}
}

func TestAuthorize_ShouldCorrectlyWorkWithHeal(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })
	peerCtx, err := getContextWithTLSCert()
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(peerCtx, time.Second)
	defer cancel()

	spiffeIDConnectionMap := authorize.SpiffeIDConnectionMap{}
	spiffeIDConnectionMap.Store(spiffeID1, []string{"conn1"})

	selector := &networkservice.MonitorScopeSelector{
		PathSegments: []*networkservice.PathSegment{{Id: "conn1"}},
	}
	// simulate heal request
	err = authorize.NewMonitorConnectionServer(
		&spiffeIDConnectionMap).MonitorConnections(
		selector, &testEmptyMCMCServer{context: ctx})
	require.NoError(t, err)
}
