package v1

import (
	"github.com/alukart32/yandex/practicum/passkee/pkg/proto/v1/creditcardpb"
	"google.golang.org/grpc"
)

func RegisterCreditCardsVaultService(srv *grpc.Server) {
	// TODO:
}

type creditCardVaultService struct {
	creditcardpb.UnimplementedCreditCardsVaultServer
}
