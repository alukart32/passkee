// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v4.22.2
// source: passwords.proto

package passwordspb

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	fieldmaskpb "google.golang.org/protobuf/types/known/fieldmaskpb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Password struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// The field will contain password details in the format login:password.
	Data  string  `protobuf:"bytes,2,opt,name=data,proto3" json:"data,omitempty"`
	Notes *string `protobuf:"bytes,3,opt,name=notes,proto3,oneof" json:"notes,omitempty"`
}

func (x *Password) Reset() {
	*x = Password{}
	if protoimpl.UnsafeEnabled {
		mi := &file_passwords_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Password) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Password) ProtoMessage() {}

func (x *Password) ProtoReflect() protoreflect.Message {
	mi := &file_passwords_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Password.ProtoReflect.Descriptor instead.
func (*Password) Descriptor() ([]byte, []int) {
	return file_passwords_proto_rawDescGZIP(), []int{0}
}

func (x *Password) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Password) GetData() string {
	if x != nil {
		return x.Data
	}
	return ""
}

func (x *Password) GetNotes() string {
	if x != nil && x.Notes != nil {
		return *x.Notes
	}
	return ""
}

type AddPasswordRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Password *Password `protobuf:"bytes,1,opt,name=password,proto3" json:"password,omitempty"`
}

func (x *AddPasswordRequest) Reset() {
	*x = AddPasswordRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_passwords_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AddPasswordRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AddPasswordRequest) ProtoMessage() {}

func (x *AddPasswordRequest) ProtoReflect() protoreflect.Message {
	mi := &file_passwords_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AddPasswordRequest.ProtoReflect.Descriptor instead.
func (*AddPasswordRequest) Descriptor() ([]byte, []int) {
	return file_passwords_proto_rawDescGZIP(), []int{1}
}

func (x *AddPasswordRequest) GetPassword() *Password {
	if x != nil {
		return x.Password
	}
	return nil
}

type GetPasswordRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *GetPasswordRequest) Reset() {
	*x = GetPasswordRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_passwords_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetPasswordRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetPasswordRequest) ProtoMessage() {}

func (x *GetPasswordRequest) ProtoReflect() protoreflect.Message {
	mi := &file_passwords_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetPasswordRequest.ProtoReflect.Descriptor instead.
func (*GetPasswordRequest) Descriptor() ([]byte, []int) {
	return file_passwords_proto_rawDescGZIP(), []int{2}
}

func (x *GetPasswordRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

type UpdatePasswordRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name       string                          `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Password   *UpdatePasswordRequest_Password `protobuf:"bytes,2,opt,name=password,proto3" json:"password,omitempty"`
	UpdateMask *fieldmaskpb.FieldMask          `protobuf:"bytes,3,opt,name=update_mask,json=updateMask,proto3" json:"update_mask,omitempty"`
}

func (x *UpdatePasswordRequest) Reset() {
	*x = UpdatePasswordRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_passwords_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpdatePasswordRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdatePasswordRequest) ProtoMessage() {}

func (x *UpdatePasswordRequest) ProtoReflect() protoreflect.Message {
	mi := &file_passwords_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdatePasswordRequest.ProtoReflect.Descriptor instead.
func (*UpdatePasswordRequest) Descriptor() ([]byte, []int) {
	return file_passwords_proto_rawDescGZIP(), []int{3}
}

func (x *UpdatePasswordRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *UpdatePasswordRequest) GetPassword() *UpdatePasswordRequest_Password {
	if x != nil {
		return x.Password
	}
	return nil
}

func (x *UpdatePasswordRequest) GetUpdateMask() *fieldmaskpb.FieldMask {
	if x != nil {
		return x.UpdateMask
	}
	return nil
}

type IndexPasswordsResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name []string `protobuf:"bytes,1,rep,name=name,proto3" json:"name,omitempty"`
}

func (x *IndexPasswordsResponse) Reset() {
	*x = IndexPasswordsResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_passwords_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IndexPasswordsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IndexPasswordsResponse) ProtoMessage() {}

func (x *IndexPasswordsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_passwords_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IndexPasswordsResponse.ProtoReflect.Descriptor instead.
func (*IndexPasswordsResponse) Descriptor() ([]byte, []int) {
	return file_passwords_proto_rawDescGZIP(), []int{4}
}

func (x *IndexPasswordsResponse) GetName() []string {
	if x != nil {
		return x.Name
	}
	return nil
}

type DeletePasswordRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name  string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Login string `protobuf:"bytes,2,opt,name=login,proto3" json:"login,omitempty"`
}

func (x *DeletePasswordRequest) Reset() {
	*x = DeletePasswordRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_passwords_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeletePasswordRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeletePasswordRequest) ProtoMessage() {}

func (x *DeletePasswordRequest) ProtoReflect() protoreflect.Message {
	mi := &file_passwords_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeletePasswordRequest.ProtoReflect.Descriptor instead.
func (*DeletePasswordRequest) Descriptor() ([]byte, []int) {
	return file_passwords_proto_rawDescGZIP(), []int{5}
}

func (x *DeletePasswordRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *DeletePasswordRequest) GetLogin() string {
	if x != nil {
		return x.Login
	}
	return ""
}

// The Password resource which replaces the resource on the server.
type UpdatePasswordRequest_Password struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name     *string `protobuf:"bytes,1,opt,name=name,proto3,oneof" json:"name,omitempty"`
	Login    *string `protobuf:"bytes,2,opt,name=login,proto3,oneof" json:"login,omitempty"`
	Password *string `protobuf:"bytes,3,opt,name=password,proto3,oneof" json:"password,omitempty"`
	Notes    []byte  `protobuf:"bytes,4,opt,name=notes,proto3,oneof" json:"notes,omitempty"`
}

func (x *UpdatePasswordRequest_Password) Reset() {
	*x = UpdatePasswordRequest_Password{}
	if protoimpl.UnsafeEnabled {
		mi := &file_passwords_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpdatePasswordRequest_Password) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdatePasswordRequest_Password) ProtoMessage() {}

func (x *UpdatePasswordRequest_Password) ProtoReflect() protoreflect.Message {
	mi := &file_passwords_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdatePasswordRequest_Password.ProtoReflect.Descriptor instead.
func (*UpdatePasswordRequest_Password) Descriptor() ([]byte, []int) {
	return file_passwords_proto_rawDescGZIP(), []int{3, 0}
}

func (x *UpdatePasswordRequest_Password) GetName() string {
	if x != nil && x.Name != nil {
		return *x.Name
	}
	return ""
}

func (x *UpdatePasswordRequest_Password) GetLogin() string {
	if x != nil && x.Login != nil {
		return *x.Login
	}
	return ""
}

func (x *UpdatePasswordRequest_Password) GetPassword() string {
	if x != nil && x.Password != nil {
		return *x.Password
	}
	return ""
}

func (x *UpdatePasswordRequest_Password) GetNotes() []byte {
	if x != nil {
		return x.Notes
	}
	return nil
}

var File_passwords_proto protoreflect.FileDescriptor

var file_passwords_proto_rawDesc = []byte{
	0x0a, 0x0f, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x0c, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x73, 0x2e, 0x76, 0x31, 0x1a,
	0x1b, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2f, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x20, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x66, 0x69,
	0x65, 0x6c, 0x64, 0x5f, 0x6d, 0x61, 0x73, 0x6b, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x57,
	0x0a, 0x08, 0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61,
	0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x12,
	0x0a, 0x04, 0x64, 0x61, 0x74, 0x61, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x64, 0x61,
	0x74, 0x61, 0x12, 0x19, 0x0a, 0x05, 0x6e, 0x6f, 0x74, 0x65, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x09, 0x48, 0x00, 0x52, 0x05, 0x6e, 0x6f, 0x74, 0x65, 0x73, 0x88, 0x01, 0x01, 0x42, 0x08, 0x0a,
	0x06, 0x5f, 0x6e, 0x6f, 0x74, 0x65, 0x73, 0x22, 0x48, 0x0a, 0x12, 0x41, 0x64, 0x64, 0x50, 0x61,
	0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x32, 0x0a,
	0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x16, 0x2e, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x50,
	0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x52, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72,
	0x64, 0x22, 0x28, 0x0a, 0x12, 0x47, 0x65, 0x74, 0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x22, 0xd9, 0x02, 0x0a, 0x15,
	0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x48, 0x0a, 0x08, 0x70, 0x61, 0x73,
	0x73, 0x77, 0x6f, 0x72, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2c, 0x2e, 0x70, 0x61,
	0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x70, 0x64, 0x61, 0x74,
	0x65, 0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x2e, 0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x52, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77,
	0x6f, 0x72, 0x64, 0x12, 0x3b, 0x0a, 0x0b, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x5f, 0x6d, 0x61,
	0x73, 0x6b, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x46, 0x69, 0x65, 0x6c, 0x64,
	0x4d, 0x61, 0x73, 0x6b, 0x52, 0x0a, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x4d, 0x61, 0x73, 0x6b,
	0x1a, 0xa4, 0x01, 0x0a, 0x08, 0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x12, 0x17, 0x0a,
	0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52, 0x04, 0x6e,
	0x61, 0x6d, 0x65, 0x88, 0x01, 0x01, 0x12, 0x19, 0x0a, 0x05, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x48, 0x01, 0x52, 0x05, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x88, 0x01,
	0x01, 0x12, 0x1f, 0x0a, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x09, 0x48, 0x02, 0x52, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x88,
	0x01, 0x01, 0x12, 0x19, 0x0a, 0x05, 0x6e, 0x6f, 0x74, 0x65, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x0c, 0x48, 0x03, 0x52, 0x05, 0x6e, 0x6f, 0x74, 0x65, 0x73, 0x88, 0x01, 0x01, 0x42, 0x07, 0x0a,
	0x05, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x42, 0x08, 0x0a, 0x06, 0x5f, 0x6c, 0x6f, 0x67, 0x69, 0x6e,
	0x42, 0x0b, 0x0a, 0x09, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x42, 0x08, 0x0a,
	0x06, 0x5f, 0x6e, 0x6f, 0x74, 0x65, 0x73, 0x22, 0x2c, 0x0a, 0x16, 0x49, 0x6e, 0x64, 0x65, 0x78,
	0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x03, 0x28, 0x09, 0x52,
	0x04, 0x6e, 0x61, 0x6d, 0x65, 0x22, 0x41, 0x0a, 0x15, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x50,
	0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x12,
	0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61,
	0x6d, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x05, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x32, 0x90, 0x03, 0x0a, 0x0e, 0x50, 0x61, 0x73,
	0x73, 0x77, 0x6f, 0x72, 0x64, 0x73, 0x56, 0x61, 0x75, 0x6c, 0x74, 0x12, 0x47, 0x0a, 0x0b, 0x41,
	0x64, 0x64, 0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x12, 0x20, 0x2e, 0x70, 0x61, 0x73,
	0x73, 0x77, 0x6f, 0x72, 0x64, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x64, 0x64, 0x50, 0x61, 0x73,
	0x73, 0x77, 0x6f, 0x72, 0x64, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x16, 0x2e, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45,
	0x6d, 0x70, 0x74, 0x79, 0x12, 0x47, 0x0a, 0x0b, 0x47, 0x65, 0x74, 0x50, 0x61, 0x73, 0x73, 0x77,
	0x6f, 0x72, 0x64, 0x12, 0x20, 0x2e, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x73, 0x2e,
	0x76, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x16, 0x2e, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64,
	0x73, 0x2e, 0x76, 0x31, 0x2e, 0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x12, 0x4d, 0x0a,
	0x0e, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x12,
	0x23, 0x2e, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x55,
	0x70, 0x64, 0x61, 0x74, 0x65, 0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x1a, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x12, 0x4e, 0x0a, 0x0e,
	0x49, 0x6e, 0x64, 0x65, 0x78, 0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x73, 0x12, 0x16,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x24, 0x2e, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72,
	0x64, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x50, 0x61, 0x73, 0x73, 0x77,
	0x6f, 0x72, 0x64, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x4d, 0x0a, 0x0e,
	0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x12, 0x23,
	0x2e, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x44, 0x65,
	0x6c, 0x65, 0x74, 0x65, 0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x1a, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x42, 0x1a, 0x5a, 0x18, 0x70,
	0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x76, 0x31, 0x2f, 0x70, 0x61, 0x73, 0x73,
	0x77, 0x6f, 0x72, 0x64, 0x73, 0x70, 0x62, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_passwords_proto_rawDescOnce sync.Once
	file_passwords_proto_rawDescData = file_passwords_proto_rawDesc
)

func file_passwords_proto_rawDescGZIP() []byte {
	file_passwords_proto_rawDescOnce.Do(func() {
		file_passwords_proto_rawDescData = protoimpl.X.CompressGZIP(file_passwords_proto_rawDescData)
	})
	return file_passwords_proto_rawDescData
}

var file_passwords_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
var file_passwords_proto_goTypes = []interface{}{
	(*Password)(nil),                       // 0: passwords.v1.Password
	(*AddPasswordRequest)(nil),             // 1: passwords.v1.AddPasswordRequest
	(*GetPasswordRequest)(nil),             // 2: passwords.v1.GetPasswordRequest
	(*UpdatePasswordRequest)(nil),          // 3: passwords.v1.UpdatePasswordRequest
	(*IndexPasswordsResponse)(nil),         // 4: passwords.v1.IndexPasswordsResponse
	(*DeletePasswordRequest)(nil),          // 5: passwords.v1.DeletePasswordRequest
	(*UpdatePasswordRequest_Password)(nil), // 6: passwords.v1.UpdatePasswordRequest.Password
	(*fieldmaskpb.FieldMask)(nil),          // 7: google.protobuf.FieldMask
	(*emptypb.Empty)(nil),                  // 8: google.protobuf.Empty
}
var file_passwords_proto_depIdxs = []int32{
	0, // 0: passwords.v1.AddPasswordRequest.password:type_name -> passwords.v1.Password
	6, // 1: passwords.v1.UpdatePasswordRequest.password:type_name -> passwords.v1.UpdatePasswordRequest.Password
	7, // 2: passwords.v1.UpdatePasswordRequest.update_mask:type_name -> google.protobuf.FieldMask
	1, // 3: passwords.v1.PasswordsVault.AddPassword:input_type -> passwords.v1.AddPasswordRequest
	2, // 4: passwords.v1.PasswordsVault.GetPassword:input_type -> passwords.v1.GetPasswordRequest
	3, // 5: passwords.v1.PasswordsVault.UpdatePassword:input_type -> passwords.v1.UpdatePasswordRequest
	8, // 6: passwords.v1.PasswordsVault.IndexPasswords:input_type -> google.protobuf.Empty
	5, // 7: passwords.v1.PasswordsVault.DeletePassword:input_type -> passwords.v1.DeletePasswordRequest
	8, // 8: passwords.v1.PasswordsVault.AddPassword:output_type -> google.protobuf.Empty
	0, // 9: passwords.v1.PasswordsVault.GetPassword:output_type -> passwords.v1.Password
	8, // 10: passwords.v1.PasswordsVault.UpdatePassword:output_type -> google.protobuf.Empty
	4, // 11: passwords.v1.PasswordsVault.IndexPasswords:output_type -> passwords.v1.IndexPasswordsResponse
	8, // 12: passwords.v1.PasswordsVault.DeletePassword:output_type -> google.protobuf.Empty
	8, // [8:13] is the sub-list for method output_type
	3, // [3:8] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_passwords_proto_init() }
func file_passwords_proto_init() {
	if File_passwords_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_passwords_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Password); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_passwords_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AddPasswordRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_passwords_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetPasswordRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_passwords_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpdatePasswordRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_passwords_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IndexPasswordsResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_passwords_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeletePasswordRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_passwords_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpdatePasswordRequest_Password); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_passwords_proto_msgTypes[0].OneofWrappers = []interface{}{}
	file_passwords_proto_msgTypes[6].OneofWrappers = []interface{}{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_passwords_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   7,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_passwords_proto_goTypes,
		DependencyIndexes: file_passwords_proto_depIdxs,
		MessageInfos:      file_passwords_proto_msgTypes,
	}.Build()
	File_passwords_proto = out.File
	file_passwords_proto_rawDesc = nil
	file_passwords_proto_goTypes = nil
	file_passwords_proto_depIdxs = nil
}
