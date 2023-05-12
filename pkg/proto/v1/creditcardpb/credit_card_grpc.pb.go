// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v4.22.2
// source: credit_card.proto

package creditcardpb

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	CreditCardsVault_AddCreditCard_FullMethodName    = "/creditcard.v1.CreditCardsVault/AddCreditCard"
	CreditCardsVault_GetCreditCard_FullMethodName    = "/creditcard.v1.CreditCardsVault/GetCreditCard"
	CreditCardsVault_UpdateCreditCard_FullMethodName = "/creditcard.v1.CreditCardsVault/UpdateCreditCard"
	CreditCardsVault_ListCreditCards_FullMethodName  = "/creditcard.v1.CreditCardsVault/ListCreditCards"
	CreditCardsVault_DeleteCreditCard_FullMethodName = "/creditcard.v1.CreditCardsVault/DeleteCreditCard"
)

// CreditCardsVaultClient is the client API for CreditCardsVault service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type CreditCardsVaultClient interface {
	AddCreditCard(ctx context.Context, in *AddCreditCardRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	GetCreditCard(ctx context.Context, in *GetCreditCardRequest, opts ...grpc.CallOption) (*CreditCard, error)
	UpdateCreditCard(ctx context.Context, in *UpdateCreditCardRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	ListCreditCards(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*ListCreditCardsResponse, error)
	DeleteCreditCard(ctx context.Context, in *DeleteCreditCardRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
}

type creditCardsVaultClient struct {
	cc grpc.ClientConnInterface
}

func NewCreditCardsVaultClient(cc grpc.ClientConnInterface) CreditCardsVaultClient {
	return &creditCardsVaultClient{cc}
}

func (c *creditCardsVaultClient) AddCreditCard(ctx context.Context, in *AddCreditCardRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, CreditCardsVault_AddCreditCard_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *creditCardsVaultClient) GetCreditCard(ctx context.Context, in *GetCreditCardRequest, opts ...grpc.CallOption) (*CreditCard, error) {
	out := new(CreditCard)
	err := c.cc.Invoke(ctx, CreditCardsVault_GetCreditCard_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *creditCardsVaultClient) UpdateCreditCard(ctx context.Context, in *UpdateCreditCardRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, CreditCardsVault_UpdateCreditCard_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *creditCardsVaultClient) ListCreditCards(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*ListCreditCardsResponse, error) {
	out := new(ListCreditCardsResponse)
	err := c.cc.Invoke(ctx, CreditCardsVault_ListCreditCards_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *creditCardsVaultClient) DeleteCreditCard(ctx context.Context, in *DeleteCreditCardRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, CreditCardsVault_DeleteCreditCard_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CreditCardsVaultServer is the server API for CreditCardsVault service.
// All implementations must embed UnimplementedCreditCardsVaultServer
// for forward compatibility
type CreditCardsVaultServer interface {
	AddCreditCard(context.Context, *AddCreditCardRequest) (*emptypb.Empty, error)
	GetCreditCard(context.Context, *GetCreditCardRequest) (*CreditCard, error)
	UpdateCreditCard(context.Context, *UpdateCreditCardRequest) (*emptypb.Empty, error)
	ListCreditCards(context.Context, *emptypb.Empty) (*ListCreditCardsResponse, error)
	DeleteCreditCard(context.Context, *DeleteCreditCardRequest) (*emptypb.Empty, error)
	mustEmbedUnimplementedCreditCardsVaultServer()
}

// UnimplementedCreditCardsVaultServer must be embedded to have forward compatible implementations.
type UnimplementedCreditCardsVaultServer struct {
}

func (UnimplementedCreditCardsVaultServer) AddCreditCard(context.Context, *AddCreditCardRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AddCreditCard not implemented")
}
func (UnimplementedCreditCardsVaultServer) GetCreditCard(context.Context, *GetCreditCardRequest) (*CreditCard, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetCreditCard not implemented")
}
func (UnimplementedCreditCardsVaultServer) UpdateCreditCard(context.Context, *UpdateCreditCardRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateCreditCard not implemented")
}
func (UnimplementedCreditCardsVaultServer) ListCreditCards(context.Context, *emptypb.Empty) (*ListCreditCardsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListCreditCards not implemented")
}
func (UnimplementedCreditCardsVaultServer) DeleteCreditCard(context.Context, *DeleteCreditCardRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteCreditCard not implemented")
}
func (UnimplementedCreditCardsVaultServer) mustEmbedUnimplementedCreditCardsVaultServer() {}

// UnsafeCreditCardsVaultServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to CreditCardsVaultServer will
// result in compilation errors.
type UnsafeCreditCardsVaultServer interface {
	mustEmbedUnimplementedCreditCardsVaultServer()
}

func RegisterCreditCardsVaultServer(s grpc.ServiceRegistrar, srv CreditCardsVaultServer) {
	s.RegisterService(&CreditCardsVault_ServiceDesc, srv)
}

func _CreditCardsVault_AddCreditCard_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AddCreditCardRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CreditCardsVaultServer).AddCreditCard(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CreditCardsVault_AddCreditCard_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CreditCardsVaultServer).AddCreditCard(ctx, req.(*AddCreditCardRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CreditCardsVault_GetCreditCard_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetCreditCardRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CreditCardsVaultServer).GetCreditCard(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CreditCardsVault_GetCreditCard_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CreditCardsVaultServer).GetCreditCard(ctx, req.(*GetCreditCardRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CreditCardsVault_UpdateCreditCard_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateCreditCardRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CreditCardsVaultServer).UpdateCreditCard(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CreditCardsVault_UpdateCreditCard_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CreditCardsVaultServer).UpdateCreditCard(ctx, req.(*UpdateCreditCardRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CreditCardsVault_ListCreditCards_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(emptypb.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CreditCardsVaultServer).ListCreditCards(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CreditCardsVault_ListCreditCards_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CreditCardsVaultServer).ListCreditCards(ctx, req.(*emptypb.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _CreditCardsVault_DeleteCreditCard_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteCreditCardRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CreditCardsVaultServer).DeleteCreditCard(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CreditCardsVault_DeleteCreditCard_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CreditCardsVaultServer).DeleteCreditCard(ctx, req.(*DeleteCreditCardRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// CreditCardsVault_ServiceDesc is the grpc.ServiceDesc for CreditCardsVault service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var CreditCardsVault_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "creditcard.v1.CreditCardsVault",
	HandlerType: (*CreditCardsVaultServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "AddCreditCard",
			Handler:    _CreditCardsVault_AddCreditCard_Handler,
		},
		{
			MethodName: "GetCreditCard",
			Handler:    _CreditCardsVault_GetCreditCard_Handler,
		},
		{
			MethodName: "UpdateCreditCard",
			Handler:    _CreditCardsVault_UpdateCreditCard_Handler,
		},
		{
			MethodName: "ListCreditCards",
			Handler:    _CreditCardsVault_ListCreditCards_Handler,
		},
		{
			MethodName: "DeleteCreditCard",
			Handler:    _CreditCardsVault_DeleteCreditCard_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "credit_card.proto",
}
