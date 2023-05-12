// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v4.22.2
// source: text.proto

package textpb

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

type CreateObjectRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name  string  `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Notes *string `protobuf:"bytes,2,opt,name=notes,proto3,oneof" json:"notes,omitempty"`
}

func (x *CreateObjectRequest) Reset() {
	*x = CreateObjectRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_text_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateObjectRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateObjectRequest) ProtoMessage() {}

func (x *CreateObjectRequest) ProtoReflect() protoreflect.Message {
	mi := &file_text_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateObjectRequest.ProtoReflect.Descriptor instead.
func (*CreateObjectRequest) Descriptor() ([]byte, []int) {
	return file_text_proto_rawDescGZIP(), []int{0}
}

func (x *CreateObjectRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *CreateObjectRequest) GetNotes() string {
	if x != nil && x.Notes != nil {
		return *x.Notes
	}
	return ""
}

type CreateObjectResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// text object id.
	ObjectId string `protobuf:"bytes,1,opt,name=object_id,json=objectId,proto3" json:"object_id,omitempty"`
}

func (x *CreateObjectResponse) Reset() {
	*x = CreateObjectResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_text_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateObjectResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateObjectResponse) ProtoMessage() {}

func (x *CreateObjectResponse) ProtoReflect() protoreflect.Message {
	mi := &file_text_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateObjectResponse.ProtoReflect.Descriptor instead.
func (*CreateObjectResponse) Descriptor() ([]byte, []int) {
	return file_text_proto_rawDescGZIP(), []int{1}
}

func (x *CreateObjectResponse) GetObjectId() string {
	if x != nil {
		return x.ObjectId
	}
	return ""
}

type Chunk struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// block number.
	No uint64 `protobuf:"varint,1,opt,name=no,proto3" json:"no,omitempty"`
	// A 4096 bytes chunk.
	Data []byte `protobuf:"bytes,2,opt,name=data,proto3" json:"data,omitempty"`
}

func (x *Chunk) Reset() {
	*x = Chunk{}
	if protoimpl.UnsafeEnabled {
		mi := &file_text_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Chunk) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Chunk) ProtoMessage() {}

func (x *Chunk) ProtoReflect() protoreflect.Message {
	mi := &file_text_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Chunk.ProtoReflect.Descriptor instead.
func (*Chunk) Descriptor() ([]byte, []int) {
	return file_text_proto_rawDescGZIP(), []int{2}
}

func (x *Chunk) GetNo() uint64 {
	if x != nil {
		return x.No
	}
	return 0
}

func (x *Chunk) GetData() []byte {
	if x != nil {
		return x.Data
	}
	return nil
}

type GetObjectRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *GetObjectRequest) Reset() {
	*x = GetObjectRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_text_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetObjectRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetObjectRequest) ProtoMessage() {}

func (x *GetObjectRequest) ProtoReflect() protoreflect.Message {
	mi := &file_text_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetObjectRequest.ProtoReflect.Descriptor instead.
func (*GetObjectRequest) Descriptor() ([]byte, []int) {
	return file_text_proto_rawDescGZIP(), []int{3}
}

func (x *GetObjectRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

type GetObjectResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ObjectId string  `protobuf:"bytes,1,opt,name=object_id,json=objectId,proto3" json:"object_id,omitempty"`
	Notes    *string `protobuf:"bytes,2,opt,name=notes,proto3,oneof" json:"notes,omitempty"`
}

func (x *GetObjectResponse) Reset() {
	*x = GetObjectResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_text_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetObjectResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetObjectResponse) ProtoMessage() {}

func (x *GetObjectResponse) ProtoReflect() protoreflect.Message {
	mi := &file_text_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetObjectResponse.ProtoReflect.Descriptor instead.
func (*GetObjectResponse) Descriptor() ([]byte, []int) {
	return file_text_proto_rawDescGZIP(), []int{4}
}

func (x *GetObjectResponse) GetObjectId() string {
	if x != nil {
		return x.ObjectId
	}
	return ""
}

func (x *GetObjectResponse) GetNotes() string {
	if x != nil && x.Notes != nil {
		return *x.Notes
	}
	return ""
}

type GetDataRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ObjectId string `protobuf:"bytes,1,opt,name=object_id,json=objectId,proto3" json:"object_id,omitempty"`
}

func (x *GetDataRequest) Reset() {
	*x = GetDataRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_text_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetDataRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetDataRequest) ProtoMessage() {}

func (x *GetDataRequest) ProtoReflect() protoreflect.Message {
	mi := &file_text_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetDataRequest.ProtoReflect.Descriptor instead.
func (*GetDataRequest) Descriptor() ([]byte, []int) {
	return file_text_proto_rawDescGZIP(), []int{5}
}

func (x *GetDataRequest) GetObjectId() string {
	if x != nil {
		return x.ObjectId
	}
	return ""
}

type UpdateObjectRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name       string                      `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Object     *UpdateObjectRequest_Object `protobuf:"bytes,3,opt,name=object,proto3" json:"object,omitempty"`
	UpdateMask *fieldmaskpb.FieldMask      `protobuf:"bytes,4,opt,name=update_mask,json=updateMask,proto3" json:"update_mask,omitempty"`
}

func (x *UpdateObjectRequest) Reset() {
	*x = UpdateObjectRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_text_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpdateObjectRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdateObjectRequest) ProtoMessage() {}

func (x *UpdateObjectRequest) ProtoReflect() protoreflect.Message {
	mi := &file_text_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdateObjectRequest.ProtoReflect.Descriptor instead.
func (*UpdateObjectRequest) Descriptor() ([]byte, []int) {
	return file_text_proto_rawDescGZIP(), []int{6}
}

func (x *UpdateObjectRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *UpdateObjectRequest) GetObject() *UpdateObjectRequest_Object {
	if x != nil {
		return x.Object
	}
	return nil
}

func (x *UpdateObjectRequest) GetUpdateMask() *fieldmaskpb.FieldMask {
	if x != nil {
		return x.UpdateMask
	}
	return nil
}

type UpdateObjectResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ObjectId string `protobuf:"bytes,1,opt,name=object_id,json=objectId,proto3" json:"object_id,omitempty"`
}

func (x *UpdateObjectResponse) Reset() {
	*x = UpdateObjectResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_text_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpdateObjectResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdateObjectResponse) ProtoMessage() {}

func (x *UpdateObjectResponse) ProtoReflect() protoreflect.Message {
	mi := &file_text_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdateObjectResponse.ProtoReflect.Descriptor instead.
func (*UpdateObjectResponse) Descriptor() ([]byte, []int) {
	return file_text_proto_rawDescGZIP(), []int{7}
}

func (x *UpdateObjectResponse) GetObjectId() string {
	if x != nil {
		return x.ObjectId
	}
	return ""
}

type ListObjectsResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name []string `protobuf:"bytes,1,rep,name=name,proto3" json:"name,omitempty"`
}

func (x *ListObjectsResponse) Reset() {
	*x = ListObjectsResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_text_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListObjectsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListObjectsResponse) ProtoMessage() {}

func (x *ListObjectsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_text_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListObjectsResponse.ProtoReflect.Descriptor instead.
func (*ListObjectsResponse) Descriptor() ([]byte, []int) {
	return file_text_proto_rawDescGZIP(), []int{8}
}

func (x *ListObjectsResponse) GetName() []string {
	if x != nil {
		return x.Name
	}
	return nil
}

type DeleteDataRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *DeleteDataRequest) Reset() {
	*x = DeleteDataRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_text_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteDataRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteDataRequest) ProtoMessage() {}

func (x *DeleteDataRequest) ProtoReflect() protoreflect.Message {
	mi := &file_text_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteDataRequest.ProtoReflect.Descriptor instead.
func (*DeleteDataRequest) Descriptor() ([]byte, []int) {
	return file_text_proto_rawDescGZIP(), []int{9}
}

func (x *DeleteDataRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

// The text object resource which replaces the resource on the server.
type UpdateObjectRequest_Object struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name  *string `protobuf:"bytes,1,opt,name=name,proto3,oneof" json:"name,omitempty"`
	Notes *string `protobuf:"bytes,2,opt,name=notes,proto3,oneof" json:"notes,omitempty"`
}

func (x *UpdateObjectRequest_Object) Reset() {
	*x = UpdateObjectRequest_Object{}
	if protoimpl.UnsafeEnabled {
		mi := &file_text_proto_msgTypes[10]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpdateObjectRequest_Object) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdateObjectRequest_Object) ProtoMessage() {}

func (x *UpdateObjectRequest_Object) ProtoReflect() protoreflect.Message {
	mi := &file_text_proto_msgTypes[10]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdateObjectRequest_Object.ProtoReflect.Descriptor instead.
func (*UpdateObjectRequest_Object) Descriptor() ([]byte, []int) {
	return file_text_proto_rawDescGZIP(), []int{6, 0}
}

func (x *UpdateObjectRequest_Object) GetName() string {
	if x != nil && x.Name != nil {
		return *x.Name
	}
	return ""
}

func (x *UpdateObjectRequest_Object) GetNotes() string {
	if x != nil && x.Notes != nil {
		return *x.Notes
	}
	return ""
}

var File_text_proto protoreflect.FileDescriptor

var file_text_proto_rawDesc = []byte{
	0x0a, 0x0a, 0x74, 0x65, 0x78, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x07, 0x74, 0x65,
	0x78, 0x74, 0x2e, 0x76, 0x31, 0x1a, 0x1b, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x20, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2f, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x5f, 0x6d, 0x61, 0x73, 0x6b, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0x4e, 0x0a, 0x13, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x4f, 0x62,
	0x6a, 0x65, 0x63, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x6e,
	0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12,
	0x19, 0x0a, 0x05, 0x6e, 0x6f, 0x74, 0x65, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00,
	0x52, 0x05, 0x6e, 0x6f, 0x74, 0x65, 0x73, 0x88, 0x01, 0x01, 0x42, 0x08, 0x0a, 0x06, 0x5f, 0x6e,
	0x6f, 0x74, 0x65, 0x73, 0x22, 0x33, 0x0a, 0x14, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x4f, 0x62,
	0x6a, 0x65, 0x63, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x1b, 0x0a, 0x09,
	0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x08, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x49, 0x64, 0x22, 0x2b, 0x0a, 0x05, 0x43, 0x68, 0x75,
	0x6e, 0x6b, 0x12, 0x0e, 0x0a, 0x02, 0x6e, 0x6f, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x02,
	0x6e, 0x6f, 0x12, 0x12, 0x0a, 0x04, 0x64, 0x61, 0x74, 0x61, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x04, 0x64, 0x61, 0x74, 0x61, 0x22, 0x26, 0x0a, 0x10, 0x47, 0x65, 0x74, 0x4f, 0x62, 0x6a,
	0x65, 0x63, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61,
	0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x22, 0x55,
	0x0a, 0x11, 0x47, 0x65, 0x74, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x12, 0x1b, 0x0a, 0x09, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x69, 0x64,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x49, 0x64,
	0x12, 0x19, 0x0a, 0x05, 0x6e, 0x6f, 0x74, 0x65, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x48,
	0x00, 0x52, 0x05, 0x6e, 0x6f, 0x74, 0x65, 0x73, 0x88, 0x01, 0x01, 0x42, 0x08, 0x0a, 0x06, 0x5f,
	0x6e, 0x6f, 0x74, 0x65, 0x73, 0x22, 0x2d, 0x0a, 0x0e, 0x47, 0x65, 0x74, 0x44, 0x61, 0x74, 0x61,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1b, 0x0a, 0x09, 0x6f, 0x62, 0x6a, 0x65, 0x63,
	0x74, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x6f, 0x62, 0x6a, 0x65,
	0x63, 0x74, 0x49, 0x64, 0x22, 0xf4, 0x01, 0x0a, 0x13, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x4f,
	0x62, 0x6a, 0x65, 0x63, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04,
	0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65,
	0x12, 0x3b, 0x0a, 0x06, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x23, 0x2e, 0x74, 0x65, 0x78, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x70, 0x64, 0x61, 0x74,
	0x65, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x2e, 0x4f,
	0x62, 0x6a, 0x65, 0x63, 0x74, 0x52, 0x06, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x12, 0x3b, 0x0a,
	0x0b, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x5f, 0x6d, 0x61, 0x73, 0x6b, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2e, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x4d, 0x61, 0x73, 0x6b, 0x52, 0x0a,
	0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x4d, 0x61, 0x73, 0x6b, 0x1a, 0x4f, 0x0a, 0x06, 0x4f, 0x62,
	0x6a, 0x65, 0x63, 0x74, 0x12, 0x17, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x48, 0x00, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x88, 0x01, 0x01, 0x12, 0x19, 0x0a,
	0x05, 0x6e, 0x6f, 0x74, 0x65, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x48, 0x01, 0x52, 0x05,
	0x6e, 0x6f, 0x74, 0x65, 0x73, 0x88, 0x01, 0x01, 0x42, 0x07, 0x0a, 0x05, 0x5f, 0x6e, 0x61, 0x6d,
	0x65, 0x42, 0x08, 0x0a, 0x06, 0x5f, 0x6e, 0x6f, 0x74, 0x65, 0x73, 0x22, 0x33, 0x0a, 0x14, 0x55,
	0x70, 0x64, 0x61, 0x74, 0x65, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x12, 0x1b, 0x0a, 0x09, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x69, 0x64,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x49, 0x64,
	0x22, 0x29, 0x0a, 0x13, 0x4c, 0x69, 0x73, 0x74, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x73, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18,
	0x01, 0x20, 0x03, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x22, 0x27, 0x0a, 0x11, 0x44,
	0x65, 0x6c, 0x65, 0x74, 0x65, 0x44, 0x61, 0x74, 0x61, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04,
	0x6e, 0x61, 0x6d, 0x65, 0x32, 0xdd, 0x03, 0x0a, 0x09, 0x54, 0x65, 0x78, 0x74, 0x56, 0x61, 0x75,
	0x6c, 0x74, 0x12, 0x4b, 0x0a, 0x0c, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x4f, 0x62, 0x6a, 0x65,
	0x63, 0x74, 0x12, 0x1c, 0x2e, 0x74, 0x65, 0x78, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x72, 0x65,
	0x61, 0x74, 0x65, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x1a, 0x1d, 0x2e, 0x74, 0x65, 0x78, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x72, 0x65, 0x61, 0x74,
	0x65, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12,
	0x33, 0x0a, 0x07, 0x50, 0x75, 0x74, 0x44, 0x61, 0x74, 0x61, 0x12, 0x0e, 0x2e, 0x74, 0x65, 0x78,
	0x74, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x68, 0x75, 0x6e, 0x6b, 0x1a, 0x16, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70,
	0x74, 0x79, 0x28, 0x01, 0x12, 0x42, 0x0a, 0x09, 0x47, 0x65, 0x74, 0x4f, 0x62, 0x6a, 0x65, 0x63,
	0x74, 0x12, 0x19, 0x2e, 0x74, 0x65, 0x78, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x4f,
	0x62, 0x6a, 0x65, 0x63, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1a, 0x2e, 0x74,
	0x65, 0x78, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x34, 0x0a, 0x07, 0x47, 0x65, 0x74, 0x44,
	0x61, 0x74, 0x61, 0x12, 0x17, 0x2e, 0x74, 0x65, 0x78, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65,
	0x74, 0x44, 0x61, 0x74, 0x61, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x0e, 0x2e, 0x74,
	0x65, 0x78, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x68, 0x75, 0x6e, 0x6b, 0x30, 0x01, 0x12, 0x4b,
	0x0a, 0x0c, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x12, 0x1c,
	0x2e, 0x74, 0x65, 0x78, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x4f,
	0x62, 0x6a, 0x65, 0x63, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1d, 0x2e, 0x74,
	0x65, 0x78, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x4f, 0x62, 0x6a,
	0x65, 0x63, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x43, 0x0a, 0x0b, 0x4c,
	0x69, 0x73, 0x74, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x73, 0x12, 0x16, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70,
	0x74, 0x79, 0x1a, 0x1c, 0x2e, 0x74, 0x65, 0x78, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x69, 0x73,
	0x74, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x42, 0x0a, 0x0c, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74,
	0x12, 0x1a, 0x2e, 0x74, 0x65, 0x78, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x44, 0x65, 0x6c, 0x65, 0x74,
	0x65, 0x44, 0x61, 0x74, 0x61, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x16, 0x2e, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45,
	0x6d, 0x70, 0x74, 0x79, 0x42, 0x15, 0x5a, 0x13, 0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x2f, 0x76, 0x31, 0x2f, 0x74, 0x65, 0x78, 0x74, 0x70, 0x62, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_text_proto_rawDescOnce sync.Once
	file_text_proto_rawDescData = file_text_proto_rawDesc
)

func file_text_proto_rawDescGZIP() []byte {
	file_text_proto_rawDescOnce.Do(func() {
		file_text_proto_rawDescData = protoimpl.X.CompressGZIP(file_text_proto_rawDescData)
	})
	return file_text_proto_rawDescData
}

var file_text_proto_msgTypes = make([]protoimpl.MessageInfo, 11)
var file_text_proto_goTypes = []interface{}{
	(*CreateObjectRequest)(nil),        // 0: text.v1.CreateObjectRequest
	(*CreateObjectResponse)(nil),       // 1: text.v1.CreateObjectResponse
	(*Chunk)(nil),                      // 2: text.v1.Chunk
	(*GetObjectRequest)(nil),           // 3: text.v1.GetObjectRequest
	(*GetObjectResponse)(nil),          // 4: text.v1.GetObjectResponse
	(*GetDataRequest)(nil),             // 5: text.v1.GetDataRequest
	(*UpdateObjectRequest)(nil),        // 6: text.v1.UpdateObjectRequest
	(*UpdateObjectResponse)(nil),       // 7: text.v1.UpdateObjectResponse
	(*ListObjectsResponse)(nil),        // 8: text.v1.ListObjectsResponse
	(*DeleteDataRequest)(nil),          // 9: text.v1.DeleteDataRequest
	(*UpdateObjectRequest_Object)(nil), // 10: text.v1.UpdateObjectRequest.Object
	(*fieldmaskpb.FieldMask)(nil),      // 11: google.protobuf.FieldMask
	(*emptypb.Empty)(nil),              // 12: google.protobuf.Empty
}
var file_text_proto_depIdxs = []int32{
	10, // 0: text.v1.UpdateObjectRequest.object:type_name -> text.v1.UpdateObjectRequest.Object
	11, // 1: text.v1.UpdateObjectRequest.update_mask:type_name -> google.protobuf.FieldMask
	0,  // 2: text.v1.TextVault.CreateObject:input_type -> text.v1.CreateObjectRequest
	2,  // 3: text.v1.TextVault.PutData:input_type -> text.v1.Chunk
	3,  // 4: text.v1.TextVault.GetObject:input_type -> text.v1.GetObjectRequest
	5,  // 5: text.v1.TextVault.GetData:input_type -> text.v1.GetDataRequest
	6,  // 6: text.v1.TextVault.UpdateObject:input_type -> text.v1.UpdateObjectRequest
	12, // 7: text.v1.TextVault.ListObjects:input_type -> google.protobuf.Empty
	9,  // 8: text.v1.TextVault.DeleteObject:input_type -> text.v1.DeleteDataRequest
	1,  // 9: text.v1.TextVault.CreateObject:output_type -> text.v1.CreateObjectResponse
	12, // 10: text.v1.TextVault.PutData:output_type -> google.protobuf.Empty
	4,  // 11: text.v1.TextVault.GetObject:output_type -> text.v1.GetObjectResponse
	2,  // 12: text.v1.TextVault.GetData:output_type -> text.v1.Chunk
	7,  // 13: text.v1.TextVault.UpdateObject:output_type -> text.v1.UpdateObjectResponse
	8,  // 14: text.v1.TextVault.ListObjects:output_type -> text.v1.ListObjectsResponse
	12, // 15: text.v1.TextVault.DeleteObject:output_type -> google.protobuf.Empty
	9,  // [9:16] is the sub-list for method output_type
	2,  // [2:9] is the sub-list for method input_type
	2,  // [2:2] is the sub-list for extension type_name
	2,  // [2:2] is the sub-list for extension extendee
	0,  // [0:2] is the sub-list for field type_name
}

func init() { file_text_proto_init() }
func file_text_proto_init() {
	if File_text_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_text_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateObjectRequest); i {
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
		file_text_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateObjectResponse); i {
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
		file_text_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Chunk); i {
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
		file_text_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetObjectRequest); i {
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
		file_text_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetObjectResponse); i {
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
		file_text_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetDataRequest); i {
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
		file_text_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpdateObjectRequest); i {
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
		file_text_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpdateObjectResponse); i {
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
		file_text_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListObjectsResponse); i {
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
		file_text_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeleteDataRequest); i {
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
		file_text_proto_msgTypes[10].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpdateObjectRequest_Object); i {
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
	file_text_proto_msgTypes[0].OneofWrappers = []interface{}{}
	file_text_proto_msgTypes[4].OneofWrappers = []interface{}{}
	file_text_proto_msgTypes[10].OneofWrappers = []interface{}{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_text_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   11,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_text_proto_goTypes,
		DependencyIndexes: file_text_proto_depIdxs,
		MessageInfos:      file_text_proto_msgTypes,
	}.Build()
	File_text_proto = out.File
	file_text_proto_rawDesc = nil
	file_text_proto_goTypes = nil
	file_text_proto_depIdxs = nil
}
