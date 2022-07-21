// Copyright (c) 2020-2022 Doc.ai and/or its affiliates.
//
// Copyright (c) 2020-2022 Cisco Systems, Inc.
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
	"context"
	"crypto/x509"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"google.golang.org/grpc/peer"

	"github.com/networkservicemesh/api/pkg/api/networkservice"

	"github.com/networkservicemesh/sdk/pkg/networkservice/core/next"
	"github.com/networkservicemesh/sdk/pkg/tools/opa"
	"github.com/networkservicemesh/sdk/pkg/tools/spire"
)

type authorizeServer struct {
	policies              policiesList
	spiffeIDConnectionMap *spire.NestedMap
}

// NewServer - returns a new authorization networkservicemesh.NetworkServiceServers
// Authorize server checks left side of Path.
func NewServer(opts ...Option) networkservice.NetworkServiceServer {
	o := &options{
		policies: policiesList{
			opa.WithTokensValidPolicy(),
			opa.WithPrevTokenSignedPolicy(),
			opa.WithTokensExpiredPolicy(),
			opa.WithTokenChainPolicy(),
		},
		spiffeIDConnectionMap: &spire.NestedMap{},
	}
	for _, opt := range opts {
		opt(o)
	}
	var s = &authorizeServer{
		policies:              o.policies,
		spiffeIDConnectionMap: o.spiffeIDConnectionMap,
	}
	return s
}


func (a *authorizeServer) Request(ctx context.Context, request *networkservice.NetworkServiceRequest) (*networkservice.Connection, error) {
	conn := request.GetConnection()
	var index = conn.GetPath().GetIndex()
	var leftSide = &networkservice.Path{
		Index:        index,
		PathSegments: conn.GetPath().GetPathSegments()[:index+1],
	}
	if _, ok := peer.FromContext(ctx); ok {
		if err := a.policies.check(ctx, leftSide); err != nil {
			logrus.Info("auth NS  failed policy check ")
			return nil, err
		}
	}
	logrus.Infof("Connection index %v", index)
	var connIds []string
	for _, v := range conn.GetPath().GetPathSegments(){
		connIds = append(connIds, v.GetId())
	}
	logrus.Infof("Ids from path segments: %v", connIds)
	if spiffeID, err := getSpiffeID(ctx); err == nil {
		connID := conn.GetPath().GetPathSegments()[index-1].GetId()
		logrus.Infof("Put Spiffe id %v and conn id %v of the service in auth request", spiffeID, connID)
		logrus.Infof("Before Spiffe Id map %v", a.spiffeIDConnectionMap)
		ids, ok := a.spiffeIDConnectionMap.Load(spiffeID)
		logrus.Infof("Before conn Ids %v", ids)
		if !ok {
			logrus.Info("Conn Ids is empty")
			ids = spire.ConnectionMap{}
			ids.Store(connID, true)
		}else {
			logrus.Info("Conn Ids is not empty")
			present, ok := ids.Load(connID)
			if !present && !ok {
				logrus.Info("Add new Conn Id")
				ids.Store(connID, true)
			}
		}
		logrus.Infof("After conn Ids %v", ids)
		a.spiffeIDConnectionMap.Store(spiffeID, ids)
		logrus.Infof("After Spiffe Id map %v", a.spiffeIDConnectionMap)
	}
	a.spiffeIDConnectionMap.Range(
		func(sid string , connMap spire.ConnectionMap) bool {
			logrus.Infof("spiffeId %v", sid)
			connMap.Range(
				func(id string, ok bool) bool {
					logrus.Infof("ConnId %v", id)
					return true
				},
			)
			return true
		},
	)
	logrus.Info("auth NS  pass policy check ")
	return next.Server(ctx).Request(ctx, request)
}

func (a *authorizeServer) Close(ctx context.Context, conn *networkservice.Connection) (*empty.Empty, error) {
	var index = conn.GetPath().GetIndex()
	var leftSide = &networkservice.Path{
		Index:        index,
		PathSegments: conn.GetPath().GetPathSegments()[:index+1],
	}

	if _, ok := peer.FromContext(ctx); ok {
		if err := a.policies.check(ctx, leftSide); err != nil {
			logrus.Info("auth NS  failed policy check ")

			return nil, err
		}
	}
	// if spiffeID, err := getSpiffeID(ctx); err == nil {
	// 	logrus.Infof("Get Spiffe id of the service in auth close %v", spiffeID)
	// 	ids, _ := a.spiffeIDConnectionMap.Load(spiffeID)
	// 	a.spiffeIDConnectionMap.LoadOrStore(spiffeID, append(ids, conn.GetId()))
	// }
	logrus.Info("auth NS  pass policy check ")
	return next.Server(ctx).Close(ctx, conn)
}

func getSpiffeID(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	var cert *x509.Certificate
	if !ok {
		return "", errors.New("fail to get peer from context")
	}
	cert = opa.ParseX509Cert(p.AuthInfo)
	if cert != nil {
		spiffeID, err := x509svid.IDFromCert(cert)
		if err == nil {
			return spiffeID.String(), nil
		}
		return "", errors.New("fail to get Spiffe ID from certificate")
	}
	return "", errors.New("fail to get certificate from peer")
}
