package cmd

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"

	"github.com/alukart32/yandex/practicum/passkee/internal/cli/cmd/bincmd"
	"github.com/alukart32/yandex/practicum/passkee/internal/cli/cmd/cardcmd"
	"github.com/alukart32/yandex/practicum/passkee/internal/cli/cmd/infocmd"
	"github.com/alukart32/yandex/practicum/passkee/internal/cli/cmd/logoncmd"
	"github.com/alukart32/yandex/practicum/passkee/internal/cli/cmd/passcmd"
	"github.com/alukart32/yandex/practicum/passkee/internal/cli/cmd/textcmd"
	"github.com/alukart32/yandex/practicum/passkee/internal/pkg/conn"
	"github.com/spf13/cobra"
)

var Root = &cobra.Command{
	Use:   "passkee [object] subcommands",
	Short: "Store confidential data",
	Long:  `passkee CLI is a client for passkee vault server`,
}

func Execute() {
	err := Root.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	Root.AddCommand(
		infocmd.Cmd,
		logoncmd.Cmd(),
		bincmd.Cmd(scanConnInfo),
		textcmd.Cmd(scanConnInfo),
		passcmd.Cmd(scanConnInfo),
		cardcmd.Cmd(scanConnInfo),
	)
}

func scanConnInfo() (conn.Info, error) {
	var (
		remoteAddr = "http://localhost:8080"
		username   string
		password   []byte
	)

	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("Vault server [%v]: ", remoteAddr)

	addrStr, err := reader.ReadString('\n')
	if err != nil {
		log.Fatalf("Error: %v\n", err)
	}
	addrStr = strings.TrimSpace(addrStr)
	if len(addrStr) != 0 {
		_, err = url.Parse(addrStr)
		if err != nil {
			log.Fatalln("Corrupted URL")
		}
		remoteAddr = addrStr
	}

	fmt.Printf("\nUsername: ")
	usernameStr, err := reader.ReadString('\n')
	if err != nil {
		log.Fatalf("Error: %v\n", err)
	}
	username = strings.TrimSpace(usernameStr)
	if len(username) == 0 {
		log.Fatalln("Empty username")
	}

	fmt.Printf("Authentication required for %v\nPassword: ", remoteAddr)
	rawPassword, err := reader.ReadString('\n')
	if err != nil {
		log.Fatalf("Error: %v\n", err)
	}
	rawPassword = strings.TrimSpace(rawPassword)
	if len(rawPassword) == 0 {
		log.Fatalln("Empty password")
	}
	hash := sha256.New()
	hash.Write([]byte(rawPassword))
	password = hash.Sum(nil)

	creds := fmt.Sprintf("%s:%v", username, password)
	creds = base64.StdEncoding.EncodeToString([]byte(creds))

	return conn.Info{
		RemoteAddr: remoteAddr,
		Creds:      creds,
	}, nil
}
