// Package vault defines the passkee vault server.
package vault

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/alukart32/yandex/practicum/passkee/internal/pkg/aesgcm"
	"github.com/alukart32/yandex/practicum/passkee/internal/pkg/migrate"
	"github.com/alukart32/yandex/practicum/passkee/internal/pkg/ports/grpcauth"
	"github.com/alukart32/yandex/practicum/passkee/internal/pkg/ports/grpcsrv"
	"github.com/alukart32/yandex/practicum/passkee/internal/pkg/postgres"
	"github.com/alukart32/yandex/practicum/passkee/internal/pkg/zerologx"
	v1 "github.com/alukart32/yandex/practicum/passkee/internal/vault/controllers/grpc/v1"
	"github.com/alukart32/yandex/practicum/passkee/internal/vault/controllers/session"
	"github.com/alukart32/yandex/practicum/passkee/internal/vault/storage/users"
	"github.com/alukart32/yandex/practicum/passkee/internal/vault/storage/vaultblob"
	"github.com/alukart32/yandex/practicum/passkee/internal/vault/storage/vaultcard"
	"github.com/alukart32/yandex/practicum/passkee/internal/vault/storage/vaultpass"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Run prepares and starts the passkee server.
func Run() {
	logger := zerologx.Get()

	conf, err := scanConf()
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to read app config")
	}

	// Prepare postgres pool.
	var pgxPool *pgxpool.Pool
	if len(conf.PostgresDSN) != 0 {
		logger.Info().Msg("prepare: postgres pool")
		pgxPool, err = postgres.Get(conf.PostgresDSN)
		if err != nil {
			logger.Fatal().Err(err).Msg("failed to prepare: postgres pool")
		}
		defer func() {
			logger.Info().Msg("shutdown: postgres pool")
			pgxPool.Close()
		}()

		logger.Info().Msg("start db migration")
		if err = migrate.Up(conf.PostgresDSN, ""); err != nil {
			logger.Fatal().Err(err).Send()
		}
	} else {
		logger.Fatal().Msg("postgres DSN not provided")
	}

	// Prepare grpc server.
	usersStorage, err := users.NewStorage(pgxPool)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to prepare users storage")
	}

	logger.Info().Msg("prepare: grpc server")
	grpcServer, err := grpcsrv.NewServer(
		grpcsrv.Config{
			ADDR: conf.GrpcAddr,
		}, *grpcauth.NewAuthOpts(
			usersStorage,
			v1.MethodsForAuthSkip(),
		),
	)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to prepare: grpc server")
	}

	// Prepare grpc services.
	sessionManager := session.Manager()

	// Auth service.
	err = v1.RegisterAuthService(grpcServer.Srv, sessionManager, usersStorage)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to prepare grpc v1 auth service")
	}

	// Session service.
	err = v1.RegisterSessionService(grpcServer.Srv, sessionManager)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to prepare grpc v1 session service")
	}

	vaultEncrypter, err := aesgcm.Encrypter([]byte(conf.VaultKey))
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to prepare vault encrypter")
	}

	// Password service.
	passwordVault, err := vaultpass.Vault(pgxPool, vaultEncrypter)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to prepare password vault")
	}
	err = v1.RegisterPasswordsVaultService(grpcServer.Srv, sessionManager, passwordVault)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to prepare grpc v1 password service")
	}

	// Credit card service.
	creditCardVault, err := vaultcard.Vault(pgxPool, vaultEncrypter)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to prepare credit card vault")
	}
	err = v1.RegisterCreditCardsVaultService(grpcServer.Srv, sessionManager, creditCardVault)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to prepare grpc v1 credit card service")
	}

	// Blob service.
	blobVault, err := vaultblob.Vault(pgxPool, vaultEncrypter)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to prepare blob vault")
	}
	err = v1.RegisterBlobVaultService(grpcServer.Srv, sessionManager, blobVault)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to prepare grpc v1 blob service")
	}

	// Run grpc server.
	logger.Info().Msg("run: grpc server")
	grpcServer.Run()
	defer func() {
		logger.Info().Msg("shutdown: grpc server")
		grpcServer.Shutdown()
	}()

	// Waiting signals.
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	select {
	case s := <-interrupt:
		logger.Info().Msg(s.String())
	case err = <-grpcServer.Notify():
		logger.Fatal().Err(err).Send()
	}
}

// config is a representation of app settings.
type config struct {
	GrpcAddr    string `json:"grpc_server_address"`
	PostgresDSN string `json:"postgres_dsn"`
	VaultKey    string `json:"vault_key"`
}

// scanConf reads and prepares app config.
func scanConf() (config, error) {
	var (
		confFile string
		conf     config
	)

	flag.StringVar(&conf.GrpcAddr, "a", "", "grpc server address")
	flag.StringVar(&conf.PostgresDSN, "d", "", "postgres DSN")
	flag.StringVar(&conf.VaultKey, "v", "", "vault encryption key")
	flag.StringVar(&confFile, "c", "", "configuration filepath")
	flag.StringVar(&confFile, "config", "", "configuration filepath")
	flag.Parse()

	envConfigFile := os.Getenv("CONFIG")
	if len(confFile) == 0 && len(envConfigFile) == 0 {
		return conf, nil
	}

	if len(confFile) == 0 && len(envConfigFile) != 0 {
		confFile = envConfigFile
	}

	b, err := os.ReadFile(confFile)
	if err != nil {
		return config{}, fmt.Errorf("failed to read config file")
	}

	if err = json.Unmarshal(b, &conf); err != nil {
		return config{}, fmt.Errorf("failed to unmarshal config file")
	}

	return conf, nil
}
