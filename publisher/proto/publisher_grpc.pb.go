// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.1.0
// - protoc             v3.18.1
// source: publisher.proto

package proto

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// PublisherClient is the client API for Publisher service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type PublisherClient interface {
	SubmitToSingleCTWithResult(ctx context.Context, in *Request, opts ...grpc.CallOption) (*Result, error)
}

type publisherClient struct {
	cc grpc.ClientConnInterface
}

func NewPublisherClient(cc grpc.ClientConnInterface) PublisherClient {
	return &publisherClient{cc}
}

func (c *publisherClient) SubmitToSingleCTWithResult(ctx context.Context, in *Request, opts ...grpc.CallOption) (*Result, error) {
	out := new(Result)
	err := c.cc.Invoke(ctx, "/Publisher/SubmitToSingleCTWithResult", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PublisherServer is the server API for Publisher service.
// All implementations must embed UnimplementedPublisherServer
// for forward compatibility
type PublisherServer interface {
	SubmitToSingleCTWithResult(context.Context, *Request) (*Result, error)
	mustEmbedUnimplementedPublisherServer()
}

// UnimplementedPublisherServer must be embedded to have forward compatible implementations.
type UnimplementedPublisherServer struct {
}

func (UnimplementedPublisherServer) SubmitToSingleCTWithResult(context.Context, *Request) (*Result, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SubmitToSingleCTWithResult not implemented")
}
func (UnimplementedPublisherServer) mustEmbedUnimplementedPublisherServer() {}

// UnsafePublisherServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to PublisherServer will
// result in compilation errors.
type UnsafePublisherServer interface {
	mustEmbedUnimplementedPublisherServer()
}

func RegisterPublisherServer(s grpc.ServiceRegistrar, srv PublisherServer) {
	s.RegisterService(&Publisher_ServiceDesc, srv)
}

func _Publisher_SubmitToSingleCTWithResult_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Request)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PublisherServer).SubmitToSingleCTWithResult(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Publisher/SubmitToSingleCTWithResult",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PublisherServer).SubmitToSingleCTWithResult(ctx, req.(*Request))
	}
	return interceptor(ctx, in, info, handler)
}

// Publisher_ServiceDesc is the grpc.ServiceDesc for Publisher service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Publisher_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "Publisher",
	HandlerType: (*PublisherServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "SubmitToSingleCTWithResult",
			Handler:    _Publisher_SubmitToSingleCTWithResult_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "publisher.proto",
}
