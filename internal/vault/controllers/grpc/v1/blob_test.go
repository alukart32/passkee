package v1

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"testing"

	"github.com/alukart32/yandex/practicum/passkee/internal/pkg/conn"
	"github.com/alukart32/yandex/practicum/passkee/internal/vault/models"
	"github.com/alukart32/yandex/practicum/passkee/pkg/proto/v1/blobpb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type blobVaultMock struct {
	SaveFn   func(context.Context, models.Blob) error
	GetFn    func(context.Context, models.BlobMeta) (models.Blob, error)
	IndexFn  func(ctx context.Context, userID string, typ models.BlobType) ([]models.Blob, error)
	UpdateFn func(ctx context.Context, meta models.BlobMeta, data models.Blob) error
	DeleteFn func(ctx context.Context, meta models.BlobMeta) error
}

func (m *blobVaultMock) Save(ctx context.Context, b models.Blob) error {
	if m != nil && m.SaveFn != nil {
		return m.SaveFn(ctx, b)
	}
	return fmt.Errorf("can't save a new blob object")
}

func (m *blobVaultMock) Get(ctx context.Context, meta models.BlobMeta) (models.Blob, error) {
	if m != nil && m.GetFn != nil {
		return m.GetFn(ctx, meta)
	}
	return models.Blob{}, fmt.Errorf("can't get blob object")
}

func (m *blobVaultMock) Index(ctx context.Context, userID string, typ models.BlobType) ([]models.Blob, error) {
	if m != nil && m.IndexFn != nil {
		return m.IndexFn(ctx, userID, typ)
	}
	return []models.Blob{}, fmt.Errorf("can't index blob objects")
}

func (m *blobVaultMock) Update(ctx context.Context, meta models.BlobMeta, data models.Blob) error {
	if m != nil && m.UpdateFn != nil {
		return m.UpdateFn(ctx, meta, data)
	}
	return fmt.Errorf("can't update blob object")
}

func (m *blobVaultMock) Delete(ctx context.Context, meta models.BlobMeta) error {
	if m != nil && m.DeleteFn != nil {
		return m.DeleteFn(ctx, meta)
	}
	return fmt.Errorf("can't delete blob object")
}

func TestBlobService_UploadObject(t *testing.T) {
	// Prepare encrypter.
	key := "bo7zun3tio268aafqzw801vxnl267c0g"
	enc, err := testDataEncrypter(key)
	require.NoError(t, err)

	type blob struct {
		data  bytes.Buffer
		name  string
		notes string
		typ   blobpb.ObjectType
	}
	type services struct {
		sessProvider sessionProvider
		vault        blobVault
	}
	type want struct {
		code codes.Code
	}
	tests := []struct {
		want       want
		serv       services
		req        blob
		name       string
		errSession bool
		err        bool
	}{
		{
			name:       "Session not found, status code: Internal",
			errSession: true,
			req: blob{
				name:  "blob",
				typ:   blobpb.ObjectType_OBJECT_BIN,
				notes: "notes",
			},
			want: want{
				code: codes.Internal,
			},
			serv: services{
				sessProvider: &sessionProviderMock{},
				vault:        &blobVaultMock{},
			},
		},
		{
			name:       "Corrupted session encrypter, status code: Internal",
			errSession: true,
			req: blob{
				name:  "blob",
				typ:   blobpb.ObjectType_OBJECT_BIN,
				notes: "notes",
			},
			want: want{
				code: codes.Internal,
			},
			serv: services{
				sessProvider: &sessionProviderMock{
					SessionByIdFn: func(s string) (conn.Session, error) {
						session, err := conn.SessionFrom("1", []byte(""))
						if err != nil {
							return conn.Session{}, err
						}
						return session, nil
					},
				},
				vault: &blobVaultMock{},
			},
		},
		{
			name: "Valid blob, status code: OK",
			req: blob{
				name:  "blob",
				typ:   blobpb.ObjectType_OBJECT_BIN,
				notes: "notes",
				data: *bytes.NewBuffer([]byte(`Hoped amounted house son very.
Both otherwise are kept provision situation discourse sing. Summer concluded cause upon
unreserved off by shall mirth hearted spring trees contrasted dine. Account my what considered
great cousins sending death continuing miles regular too form winding should. Resolution
carried two did the.Pleasant blessing seven reserved particular doubt matter. Provided indeed
excellent learn removing sweetness overcame any whole son. Husband bachelor led could stronger
fine hunted picture resolving manor found seven prudent comparison order especially resembled.
Possible played projecting get explained future relied celebrated direction rendered sweetness
concluded proceed fulfilled. Tent thing their point hold enough peculiar discretion marked under
simplicity first knew done respect.
				`)),
			},
			want: want{
				code: codes.OK,
			},
			serv: services{
				sessProvider: &sessionProviderMock{
					SessionByIdFn: func(s string) (conn.Session, error) {
						session, err := conn.SessionFrom("1", []byte(key))
						if err != nil {
							return conn.Session{}, err
						}
						return session, nil
					},
				},
				vault: &blobVaultMock{
					SaveFn: func(_ context.Context, _ models.Blob) error {
						return nil
					},
				},
			},
		},
		{
			name: "Can't save valid blob, status code: Internal",
			err:  true,
			req: blob{
				name:  "blob",
				typ:   blobpb.ObjectType_OBJECT_BIN,
				notes: "notes",
				data: *bytes.NewBuffer([]byte(`Hoped amounted house son very.
Both otherwise are kept provision situation discourse sing. Summer concluded cause upon
unreserved off by shall mirth hearted spring trees contrasted dine. Account my what considered
great cousins sending death continuing miles regular too form winding should. Resolution
carried two did the.Pleasant blessing seven reserved particular doubt matter. Provided indeed
excellent learn removing sweetness overcame any whole son. Husband bachelor led could stronger
fine hunted picture resolving manor found seven prudent comparison order especially resembled.
Possible played projecting get explained future relied celebrated direction rendered sweetness
concluded proceed fulfilled. Tent thing their point hold enough peculiar discretion marked under
simplicity first knew done respect.
				`)),
			},
			want: want{
				code: codes.Internal,
			},
			serv: services{
				sessProvider: &sessionProviderMock{
					SessionByIdFn: func(s string) (conn.Session, error) {
						session, err := conn.SessionFrom("1", []byte(key))
						if err != nil {
							return conn.Session{}, err
						}
						return session, nil
					},
				},
				vault: &blobVaultMock{
					SaveFn: func(_ context.Context, _ models.Blob) error {
						return fmt.Errorf("can't save")
					},
				},
			},
		},
		{
			name: "Ivalid object type, status code: InvalidArgument",
			err:  true,
			req: blob{
				name:  "blob",
				typ:   blobpb.ObjectType_UNDEFINED,
				notes: "notes",
				data: *bytes.NewBuffer([]byte(`Hoped amounted house son very.
Both otherwise are kept provision situation discourse sing. Summer concluded cause upon
unreserved off by shall mirth hearted spring trees contrasted dine. Account my what considered
great cousins sending death continuing miles regular too form winding should. Resolution
carried two did the.Pleasant blessing seven reserved particular doubt matter. Provided indeed
excellent learn removing sweetness overcame any whole son. Husband bachelor led could stronger
fine hunted picture resolving manor found seven prudent comparison order especially resembled.
Possible played projecting get explained future relied celebrated direction rendered sweetness
concluded proceed fulfilled. Tent thing their point hold enough peculiar discretion marked under
simplicity first knew done respect.
				`)),
			},
			want: want{
				code: codes.InvalidArgument,
			},
			serv: services{
				sessProvider: &sessionProviderMock{
					SessionByIdFn: func(s string) (conn.Session, error) {
						session, err := conn.SessionFrom("1", []byte(key))
						if err != nil {
							return conn.Session{}, err
						}
						return session, nil
					},
				},
				vault: &blobVaultMock{},
			},
		},
		// TODO: add over max object size test.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, closer :=
				blobServiceClient(context.Background(), tt.serv.sessProvider, tt.serv.vault)
			defer closer()

			data, err := encTestData(enc, tt.req.data)
			require.NoError(t, err)

			encName, err := enc.Encrypt([]byte(tt.req.name))
			require.NoError(t, err)

			encNotes, err := enc.Encrypt([]byte(tt.req.notes))
			require.NoError(t, err)

			stream, err := client.UploadObject(context.Background())
			require.NoError(t, err)

			// Send the object info.
			err = stream.SendMsg(&blobpb.UploadObjectRequest{
				Data: &blobpb.UploadObjectRequest_Info{
					Info: &blobpb.UploadObjectRequest_ObjectInfo{
						Name:  encName,
						Typ:   blobpb.ObjectType(tt.req.typ),
						Notes: encNotes,
					},
				},
			})
			if err != nil && tt.errSession {
				if e, ok := status.FromError(err); ok {
					assert.EqualValues(t, tt.want.code, e.Code(),
						"Expected status code: %d, got %d", tt.want.code, e.Code())
					return
				} else {
					// TODO: EOF only run all tests.
					require.EqualValues(t, io.EOF, err)
				}
			}

			// Send chunks.
			for _, b := range data {
				err := stream.Send(&blobpb.UploadObjectRequest{
					Data: &blobpb.UploadObjectRequest_Chunk{
						Chunk: &blobpb.Chunk{
							Data: b,
						},
					},
				})
				if err == io.EOF {
					break
				}
				require.NoError(t, err)
			}
			_, err = stream.CloseAndRecv()

			if err != nil && tt.err {
				if e, ok := status.FromError(err); ok {
					assert.EqualValues(t, tt.want.code, e.Code(),
						"Expected status code: %d, got %d", tt.want.code, e.Code())
				} else {
					t.Fatalf("failed to parse: %v", err)
				}
			}
		})
	}
}

func TestBlobService_UpdateObjectInfo(t *testing.T) {
	// Prepare encrypter.
	key := "bo7zun3tio268aafqzw801vxnl267c0g"
	enc, err := testDataEncrypter(key)
	require.NoError(t, err)

	type blob struct {
		name     string
		newName  string
		newNotes string
		typ      blobpb.ObjectType
	}
	type services struct {
		sessProvider sessionProvider
		vault        blobVault
	}
	type want struct {
		code codes.Code
	}
	tests := []struct {
		want want
		serv services
		req  blob
		name string
	}{
		{
			name: "Session not found, status code: Internal",
			req: blob{
				name:     "blob",
				typ:      blobpb.ObjectType_OBJECT_BIN,
				newNotes: "notes",
			},
			want: want{
				code: codes.Internal,
			},
			serv: services{
				sessProvider: &sessionProviderMock{},
				vault:        &blobVaultMock{},
			},
		},
		{
			name: "Corrupted session encrypter, status code: Internal",
			req: blob{
				name:     "blob",
				typ:      blobpb.ObjectType_OBJECT_BIN,
				newNotes: "notes",
			},
			want: want{
				code: codes.Internal,
			},
			serv: services{
				sessProvider: &sessionProviderMock{
					SessionByIdFn: func(s string) (conn.Session, error) {
						session, err := conn.SessionFrom("1", []byte(""))
						if err != nil {
							return conn.Session{}, err
						}
						return session, nil
					},
				},
				vault: &blobVaultMock{},
			},
		},
		{
			name: "Valid blob update, status code: OK",
			req: blob{
				name:     "blob",
				newName:  "blob2",
				typ:      blobpb.ObjectType_OBJECT_BIN,
				newNotes: "notes",
			},
			want: want{
				code: codes.OK,
			},
			serv: services{
				sessProvider: &sessionProviderMock{
					SessionByIdFn: func(s string) (conn.Session, error) {
						session, err := conn.SessionFrom("1", []byte(key))
						if err != nil {
							return conn.Session{}, err
						}
						return session, nil
					},
				},
				vault: &blobVaultMock{
					UpdateFn: func(_ context.Context, _ models.BlobMeta, _ models.Blob) error {
						return nil
					},
				},
			},
		},
		{
			name: "Can't update blob, status code: Internal",
			req: blob{
				name:     "blob",
				typ:      blobpb.ObjectType_OBJECT_BIN,
				newNotes: "notes",
			},
			want: want{
				code: codes.Internal,
			},
			serv: services{
				sessProvider: &sessionProviderMock{
					SessionByIdFn: func(s string) (conn.Session, error) {
						session, err := conn.SessionFrom("1", []byte(key))
						if err != nil {
							return conn.Session{}, err
						}
						return session, nil
					},
				},
				vault: &blobVaultMock{
					UpdateFn: func(_ context.Context, _ models.BlobMeta, _ models.Blob) error {
						return fmt.Errorf("can't update")
					},
				},
			},
		},
		{
			name: "Ivalid object type, status code: InvalidArgument",
			req: blob{
				name:     "blob",
				typ:      blobpb.ObjectType_UNDEFINED,
				newNotes: "notes",
			},
			want: want{
				code: codes.InvalidArgument,
			},
			serv: services{
				sessProvider: &sessionProviderMock{
					SessionByIdFn: func(s string) (conn.Session, error) {
						session, err := conn.SessionFrom("1", []byte(key))
						if err != nil {
							return conn.Session{}, err
						}
						return session, nil
					},
				},
				vault: &blobVaultMock{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, closer :=
				blobServiceClient(context.Background(), tt.serv.sessProvider, tt.serv.vault)
			defer closer()

			name, err := enc.Encrypt([]byte(tt.req.name))
			require.NoError(t, err)

			var newName []byte
			if len(tt.req.newName) != 0 {
				newName, err = enc.Encrypt([]byte(tt.req.newName))
				require.NoError(t, err)
			}
			var newNotes []byte
			if len(tt.req.newNotes) != 0 {
				newNotes, err = enc.Encrypt([]byte(tt.req.newNotes))
				require.NoError(t, err)
			}
			_, err = client.UpdateObjectInfo(
				context.Background(),
				&blobpb.UpdateObjectInfoRequest{
					Name: name,
					Typ:  tt.req.typ,
					Info: &blobpb.UpdateObjectInfoRequest_ObjectInfo{
						Name:  newName,
						Notes: newNotes,
					},
				})
			if err != nil {
				if e, ok := status.FromError(err); ok {
					assert.EqualValues(t, tt.want.code, e.Code(),
						"Expected status code: %d, got %d", tt.want.code, e.Code())
				} else {
					t.Fatalf("failed to parse: %v", err)
				}
			}
		})
	}
}

func TestBlobService_DownloadObject(t *testing.T) {
	// Prepare encrypter.
	key := "bo7zun3tio268aafqzw801vxnl267c0g"
	enc, err := testDataEncrypter(key)
	require.NoError(t, err)

	type blob struct {
		data  bytes.Buffer
		name  string
		notes string
		typ   blobpb.ObjectType
	}
	type services struct {
		sessProvider sessionProvider
		vault        blobVault
	}
	type want struct {
		blob blob
		code codes.Code
	}
	tests := []struct {
		want       want
		serv       services
		req        blob
		name       string
		errSession bool
		err        bool
	}{
		{
			name:       "Session not found, status code: Internal",
			errSession: true,
			req: blob{
				name: "blob",
				typ:  blobpb.ObjectType_OBJECT_BIN,
			},
			want: want{
				code: codes.Internal,
			},
			serv: services{
				sessProvider: &sessionProviderMock{},
				vault:        &blobVaultMock{},
			},
		},
		{
			name:       "Corrupted session encrypter, status code: Internal",
			errSession: true,
			req: blob{
				name: "blob",
				typ:  blobpb.ObjectType_OBJECT_BIN,
			},
			want: want{
				code: codes.Internal,
			},
			serv: services{
				sessProvider: &sessionProviderMock{
					SessionByIdFn: func(s string) (conn.Session, error) {
						session, err := conn.SessionFrom("1", []byte(""))
						if err != nil {
							return conn.Session{}, err
						}
						return session, nil
					},
				},
				vault: &blobVaultMock{},
			},
		},
		{
			name: "Get blob, status code: OK",
			req: blob{
				name: "blob",
				typ:  blobpb.ObjectType_OBJECT_BIN,
			},
			want: want{
				blob: blob{
					name:  "blob",
					typ:   blobpb.ObjectType_OBJECT_BIN,
					notes: "notes",
					data: *bytes.NewBuffer([]byte(`Hoped amounted house son very.
	Both otherwise are kept provision situation discourse sing. Summer concluded cause upon
	unreserved off by shall mirth hearted spring trees contrasted dine. Account my what considered
	great cousins sending death continuing miles regular too form winding should. Resolution
	carried two did the.Pleasant blessing seven reserved particular doubt matter. Provided indeed
	excellent learn removing sweetness overcame any whole son. Husband bachelor led could stronger
	fine hunted picture resolving manor found seven prudent comparison order especially resembled.
	Possible played projecting get explained future relied celebrated direction rendered sweetness
	concluded proceed fulfilled. Tent thing their point hold enough peculiar discretion marked under
	simplicity first knew done respect.`)),
				},
				code: codes.OK,
			},
			serv: services{
				sessProvider: &sessionProviderMock{
					SessionByIdFn: func(s string) (conn.Session, error) {
						session, err := conn.SessionFrom("1", []byte(key))
						if err != nil {
							return conn.Session{}, err
						}
						return session, nil
					},
				},
				vault: &blobVaultMock{
					GetFn: func(ctx context.Context, bm models.BlobMeta) (models.Blob, error) {
						blob := models.Blob{
							Meta: models.BlobMeta{
								Obj: models.ObjectMeta{
									Name: []byte("blob"),
								},
								Typ: models.BinObjectType,
							},
							Data: []byte(`Hoped amounted house son very.
Both otherwise are kept provision situation discourse sing. Summer concluded cause upon
unreserved off by shall mirth hearted spring trees contrasted dine. Account my what considered
great cousins sending death continuing miles regular too form winding should. Resolution
carried two did the.Pleasant blessing seven reserved particular doubt matter. Provided indeed
excellent learn removing sweetness overcame any whole son. Husband bachelor led could stronger
fine hunted picture resolving manor found seven prudent comparison order especially resembled.
Possible played projecting get explained future relied celebrated direction rendered sweetness
concluded proceed fulfilled. Tent thing their point hold enough peculiar discretion marked under
simplicity first knew done respect.`),
							Notes: []byte("notes"),
						}
						return blob, nil
					},
				},
			},
		},
		{
			name: "Can't get blob, status code: Unknown",
			err:  true,
			req: blob{
				name: "blob",
				typ:  blobpb.ObjectType_OBJECT_BIN,
			},
			want: want{
				code: codes.Unknown,
			},
			serv: services{
				sessProvider: &sessionProviderMock{
					SessionByIdFn: func(s string) (conn.Session, error) {
						session, err := conn.SessionFrom("1", []byte(key))
						if err != nil {
							return conn.Session{}, err
						}
						return session, nil
					},
				},
				vault: &blobVaultMock{
					GetFn: func(_ context.Context, _ models.BlobMeta) (models.Blob, error) {
						return models.Blob{}, fmt.Errorf("can't get")
					},
				},
			},
		},
		{
			name: "Ivalid object type, status code: InvalidArgument",
			err:  true,
			req: blob{
				name: "blob",
				typ:  blobpb.ObjectType_UNDEFINED,
			},
			want: want{
				code: codes.InvalidArgument,
			},
			serv: services{
				sessProvider: &sessionProviderMock{
					SessionByIdFn: func(s string) (conn.Session, error) {
						session, err := conn.SessionFrom("1", []byte(key))
						if err != nil {
							return conn.Session{}, err
						}
						return session, nil
					},
				},
				vault: &blobVaultMock{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, closer :=
				blobServiceClient(context.Background(), tt.serv.sessProvider, tt.serv.vault)
			defer closer()

			name, err := enc.Encrypt([]byte(tt.req.name))
			require.NoError(t, err)

			stream, err := client.DownloadObject(
				context.Background(),
				&blobpb.DownloadObjectRequest{
					Name: name,
					Typ:  tt.req.typ,
				},
			)
			require.NoError(t, err)
			// Read first message.
			resp, err := stream.Recv()

			if err != nil && tt.errSession || tt.err {
				if e, ok := status.FromError(err); ok {
					assert.EqualValues(t, tt.want.code, e.Code(),
						"Expected status code: %d, got %d", tt.want.code, e.Code())
					return
				}
			}

			notes, err := enc.Decrypt(resp.GetInfo().Notes)
			require.NoError(t, err)

			assert.EqualValues(t, tt.want.blob.notes, notes)

			// Recieve object data.
			buf := new(bytes.Buffer)
			for i := uint64(0); ; i++ {
				msg, err := stream.Recv()
				if err != nil {
					if err == io.EOF {
						break
					}
					t.Fatal(err)
				}
				data, err := enc.DecryptBlock(msg.GetChunk().Data, i)
				require.NoError(t, err)

				if _, err = buf.Write(data); err != nil {
					require.NoError(t, err)
				}
			}
			err = stream.CloseSend()
			require.NoError(t, err)

			if err != nil {
				if e, ok := status.FromError(err); ok {
					assert.EqualValues(t, tt.want.code, e.Code(),
						"Expected status code: %d, got %d", tt.want.code, e.Code())
				} else {
					t.Fatalf("failed to parse: %v", err)
				}
			}
		})
	}
}

func TestBlobService_DeleteObject(t *testing.T) {
	// Prepare encrypter.
	key := "bo7zun3tio268aafqzw801vxnl267c0g"
	enc, err := testDataEncrypter(key)
	require.NoError(t, err)

	type blob struct {
		name string
		typ  blobpb.ObjectType
	}
	type services struct {
		sessProvider sessionProvider
		vault        blobVault
	}
	type want struct {
		code codes.Code
	}
	tests := []struct {
		want want
		serv services
		req  blob
		name string
	}{
		{
			name: "Session not found, status code: Internal",
			req: blob{
				name: "blob",
				typ:  blobpb.ObjectType_OBJECT_BIN,
			},
			want: want{
				code: codes.Internal,
			},
			serv: services{
				sessProvider: &sessionProviderMock{},
				vault:        &blobVaultMock{},
			},
		},
		{
			name: "Corrupted session encrypter, status code: Internal",
			req: blob{
				name: "blob",
				typ:  blobpb.ObjectType_OBJECT_BIN,
			},
			want: want{
				code: codes.Internal,
			},
			serv: services{
				sessProvider: &sessionProviderMock{
					SessionByIdFn: func(s string) (conn.Session, error) {
						session, err := conn.SessionFrom("1", []byte(""))
						if err != nil {
							return conn.Session{}, err
						}
						return session, nil
					},
				},
				vault: &blobVaultMock{},
			},
		},
		{
			name: "Blob deleted, status code: OK",
			req: blob{
				name: "blob",
				typ:  blobpb.ObjectType_OBJECT_BIN,
			},
			want: want{
				code: codes.OK,
			},
			serv: services{
				sessProvider: &sessionProviderMock{
					SessionByIdFn: func(s string) (conn.Session, error) {
						session, err := conn.SessionFrom("1", []byte(key))
						if err != nil {
							return conn.Session{}, err
						}
						return session, nil
					},
				},
				vault: &blobVaultMock{
					DeleteFn: func(_ context.Context, _ models.BlobMeta) error {
						return nil
					},
				},
			},
		},
		{
			name: "Can't delete blob, status code: Internal",
			req: blob{
				name: "blob",
				typ:  blobpb.ObjectType_OBJECT_BIN,
			},
			want: want{
				code: codes.Internal,
			},
			serv: services{
				sessProvider: &sessionProviderMock{
					SessionByIdFn: func(s string) (conn.Session, error) {
						session, err := conn.SessionFrom("1", []byte(key))
						if err != nil {
							return conn.Session{}, err
						}
						return session, nil
					},
				},
				vault: &blobVaultMock{
					DeleteFn: func(_ context.Context, _ models.BlobMeta) error {
						return fmt.Errorf("can't delete")
					},
				},
			},
		},
		{
			name: "Ivalid object type, status code: InvalidArgument",
			req: blob{
				name: "blob",
				typ:  blobpb.ObjectType_UNDEFINED,
			},
			want: want{
				code: codes.InvalidArgument,
			},
			serv: services{
				sessProvider: &sessionProviderMock{
					SessionByIdFn: func(s string) (conn.Session, error) {
						session, err := conn.SessionFrom("1", []byte(key))
						if err != nil {
							return conn.Session{}, err
						}
						return session, nil
					},
				},
				vault: &blobVaultMock{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, closer :=
				blobServiceClient(context.Background(), tt.serv.sessProvider, tt.serv.vault)
			defer closer()

			name, err := enc.Encrypt([]byte(tt.req.name))
			require.NoError(t, err)

			_, err = client.DeleteObject(
				context.Background(),
				&blobpb.DeleteObjectRequest{
					Name: name,
					Typ:  tt.req.typ,
				})
			if err != nil {
				if e, ok := status.FromError(err); ok {
					assert.EqualValues(t, tt.want.code, e.Code(),
						"Expected status code: %d, got %d", tt.want.code, e.Code())
				} else {
					t.Fatalf("failed to parse: %v", err)
				}
			}
		})
	}
}

func blobServiceClient(
	ctx context.Context,
	sessProvider sessionProvider,
	vault blobVault,
) (blobpb.BlobVaultClient, func()) {
	buffer := 1024 * 1024
	lis := bufconn.Listen(buffer)

	baseServer := grpc.NewServer()
	RegisterBlobVaultService(
		baseServer,
		sessProvider,
		vault,
	)
	go func() {
		if err := baseServer.Serve(lis); err != nil {
			log.Printf("error serving server: %v", err)
		}
	}()

	conn, err := grpc.DialContext(ctx, "",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Printf("error connecting to server: %v", err)
	}

	closer := func() {
		err := lis.Close()
		if err != nil {
			log.Printf("error closing listener: %v", err)
		}
		baseServer.Stop()
	}

	client := blobpb.NewBlobVaultClient(conn)
	return client, closer
}

func encTestData(enc conn.DataEncrypter, buf bytes.Buffer) ([][]byte, error) {
	blocks := make([][]byte, 1+(buf.Len()-1)/4096)
	for i := uint64(0); ; i++ {
		tmp := make([]byte, 4096)
		_, err := buf.Read(tmp)
		if err != nil {
			if err == io.EOF {
				break
			} else {
				return nil, err
			}
		}

		b, err := enc.EncryptBlock(tmp, i)
		if err != nil {
			return nil, fmt.Errorf("can't encrypt object data: %v", err)
		}

		blocks[i] = b
	}

	return blocks, nil
}
