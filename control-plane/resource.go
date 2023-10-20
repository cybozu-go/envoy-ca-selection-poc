// Copyright 2020 Envoyproxy Authors
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

package example

import (
	"time"

	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	router "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	tls_inspectorv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/tls_inspector/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
)

const (
	ClusterName  = "example_proxy_cluster"
	RouteName    = "local_route"
	ListenerName = "listener_0"
	ListenerPort = 10000
	UpstreamHost = "localhost"
	UpstreamPort = 8080
)

func makeCluster(clusterName string) *cluster.Cluster {
	return &cluster.Cluster{
		Name:                 clusterName,
		ConnectTimeout:       durationpb.New(5 * time.Second),
		ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_LOGICAL_DNS},
		LbPolicy:             cluster.Cluster_ROUND_ROBIN,
		LoadAssignment:       makeEndpoint(clusterName),
		DnsLookupFamily:      cluster.Cluster_V4_ONLY,
	}
}

func makeEndpoint(clusterName string) *endpoint.ClusterLoadAssignment {
	return &endpoint.ClusterLoadAssignment{
		ClusterName: clusterName,
		Endpoints: []*endpoint.LocalityLbEndpoints{{
			LbEndpoints: []*endpoint.LbEndpoint{{
				HostIdentifier: &endpoint.LbEndpoint_Endpoint{
					Endpoint: &endpoint.Endpoint{
						Address: &core.Address{
							Address: &core.Address_SocketAddress{
								SocketAddress: &core.SocketAddress{
									Protocol: core.SocketAddress_TCP,
									Address:  UpstreamHost,
									PortSpecifier: &core.SocketAddress_PortValue{
										PortValue: UpstreamPort,
									},
								},
							},
						},
					},
				},
			}},
		}},
	}
}

func makeRoute(routeName string, clusterName string) *route.RouteConfiguration {
	return &route.RouteConfiguration{
		Name: routeName,
		VirtualHosts: []*route.VirtualHost{{
			Name:    "local_service",
			Domains: []string{"*"},
			Routes: []*route.Route{{
				Match: &route.RouteMatch{
					PathSpecifier: &route.RouteMatch_Prefix{
						Prefix: "/",
					},
				},
				Action: &route.Route_Route{
					Route: &route.RouteAction{
						ClusterSpecifier: &route.RouteAction_Cluster{
							Cluster: clusterName,
						},
						HostRewriteSpecifier: &route.RouteAction_HostRewriteLiteral{
							HostRewriteLiteral: UpstreamHost,
						},
						AppendXForwardedHost: true, // Append for routing by SNI
					},
				},
			}},
		}},
	}
}

func makeDownstreamTLSContext(
	serverKeyPair *ServerKeyPair,
	clientValContext *ClientCertValidationContext,
) *anypb.Any {
	// TLS configuration
	context := &tlsv3.DownstreamTlsContext{
		RequireClientCertificate: wrapperspb.Bool(true), // Require Client Certificate for mTLS
		CommonTlsContext: &tlsv3.CommonTlsContext{
			TlsCertificates: []*tlsv3.TlsCertificate{
				{
					CertificateChain: &corev3.DataSource{
						Specifier: &corev3.DataSource_InlineBytes{
							InlineBytes: serverKeyPair.Cert,
						},
					},
					PrivateKey: &corev3.DataSource{
						Specifier: &corev3.DataSource_InlineBytes{
							InlineBytes: serverKeyPair.Key,
						},
					},
				},
			},
			ValidationContextType: &tlsv3.CommonTlsContext_ValidationContext{
				ValidationContext: &tlsv3.CertificateValidationContext{
					TrustedCa: &corev3.DataSource{
						Specifier: &corev3.DataSource_InlineBytes{
							InlineBytes: clientValContext.CACert,
						},
					},
				},
			},
		},
	}
	pbst, err := anypb.New(context)
	if err != nil {
		panic(err)
	}
	return pbst
}

func makeFilterChain(
	route string,
	serverKeyPair *ServerKeyPair,
	clientValContext *ClientCertValidationContext,
) *listener.FilterChain {
	routerConfig, _ := anypb.New(&router.Router{})
	// HTTP filter configuration
	manager := &hcm.HttpConnectionManager{
		CodecType:                hcm.HttpConnectionManager_AUTO,
		StatPrefix:               "http",
		ForwardClientCertDetails: hcm.HttpConnectionManager_ForwardClientCertDetails(2),
		SetCurrentClientCertDetails: &hcm.HttpConnectionManager_SetCurrentClientCertDetails{
			Uri: true,
		},
		RouteSpecifier: &hcm.HttpConnectionManager_Rds{
			Rds: &hcm.Rds{
				ConfigSource:    makeConfigSource(),
				RouteConfigName: route,
			},
		},
		HttpFilters: []*hcm.HttpFilter{{
			Name:       wellknown.Router,
			ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: routerConfig},
		}},
	}
	pbst, err := anypb.New(manager)
	if err != nil {
		panic(err)
	}

	return &listener.FilterChain{
		FilterChainMatch: &listener.FilterChainMatch{
			ServerNames: []string{clientValContext.ServerName},
		},
		Filters: []*listener.Filter{
			{
				Name: wellknown.HTTPConnectionManager,
				ConfigType: &listener.Filter_TypedConfig{
					TypedConfig: pbst,
				},
			},
		},
		TransportSocket: &corev3.TransportSocket{
			Name: wellknown.TransportSocketTLS,
			ConfigType: &core.TransportSocket_TypedConfig{
				TypedConfig: makeDownstreamTLSContext(serverKeyPair, clientValContext),
			},
		},
	}
}

func makeFilterChainArray(
	route string,
	serverKeyPair *ServerKeyPair,
	clientValContexts []*ClientCertValidationContext,
) []*listener.FilterChain {
	var chainArray []*listener.FilterChain
	for _, certGroup := range clientValContexts {
		chainArray = append(
			chainArray,
			makeFilterChain(route, serverKeyPair, certGroup),
		)
	}
	return chainArray
}

func makeHTTPListener(
	listenerName string,
	route string,
	serverKeyPair *ServerKeyPair,
	clientValContexts []*ClientCertValidationContext,
) *listener.Listener {
	inspector := &tls_inspectorv3.TlsInspector{
		EnableJa3Fingerprinting: wrapperspb.Bool(false),
	}
	pbst3, err := anypb.New(inspector)
	if err != nil {
		panic(err)
	}

	return &listener.Listener{
		Name: listenerName,
		Address: &core.Address{
			Address: &core.Address_SocketAddress{
				SocketAddress: &core.SocketAddress{
					Protocol: core.SocketAddress_TCP,
					Address:  "0.0.0.0",
					PortSpecifier: &core.SocketAddress_PortValue{
						PortValue: ListenerPort,
					},
				},
			},
		},
		ListenerFilters: []*listener.ListenerFilter{
			{
				Name: wellknown.TLSInspector,
				ConfigType: &listener.ListenerFilter_TypedConfig{
					TypedConfig: pbst3,
				},
			},
		},
		FilterChains: makeFilterChainArray(route, serverKeyPair, clientValContexts),
	}
}

func makeConfigSource() *core.ConfigSource {
	source := &core.ConfigSource{}
	source.ResourceApiVersion = resource.DefaultAPIVersion
	source.ConfigSourceSpecifier = &core.ConfigSource_ApiConfigSource{
		ApiConfigSource: &core.ApiConfigSource{
			TransportApiVersion:       resource.DefaultAPIVersion,
			ApiType:                   core.ApiConfigSource_GRPC,
			SetNodeOnFirstMessageOnly: true,
			GrpcServices: []*core.GrpcService{{
				TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
					EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: "xds_cluster"},
				},
			}},
		},
	}
	return source
}

func GenerateSnapshot() *cache.Snapshot {
	snap, _ := cache.NewSnapshot("1",
		map[resource.Type][]types.Resource{
			resource.ClusterType: {makeCluster(ClusterName)},
			resource.RouteType:   {makeRoute(RouteName, ClusterName)},
			resource.ListenerType: {makeHTTPListener(
				ListenerName,
				RouteName,
				GetServerKeyPair(),
				GetClientCertValidationContexts(),
			)},
		},
	)
	return snap
}
