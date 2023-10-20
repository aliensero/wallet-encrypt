package wallet

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func NowTimeString() string {
	return time.Now().UTC().Format("2006-01-02T15-04-05.000") + "Z"
}

func WalletFile() string {
	return filepath.Join("wallet_" + NowTimeString() + ".json")
}

func TestWallet(t *testing.T) {

	// fmt.Print("Enter a secure password used to encrypt the wallet file (optional but strongly recommended): ")
	// password, err := password.Read(os.Stdin)
	// fmt.Println()
	// cobra.CheckErr(err)
	wk := NewKey(WithRandomSalt(), WithPbkdf2Password([]byte("password")))
	// cobra.CheckErr(err)

	// Make sure we're not overwriting an existing wallet (this should not happen)
	walletFn := WalletFile()
	_, err := os.Stat(walletFn)
	switch {
	case errors.Is(err, os.ErrNotExist):
		// all fine
	case err == nil:
		log.Fatalln("Wallet file already exists")
	default:
		log.Fatalf("Error opening %s: %v\n", walletFn, err)
	}

	// Now open for writing
	f2, err := os.OpenFile(walletFn, os.O_WRONLY|os.O_CREATE, 0o600)
	cobra.CheckErr(err)
	defer f2.Close()
	w, err := NewEhereumWallet()
	if err != nil {
		log.Fatal(err)
	}
	cobra.CheckErr(wk.Export(f2, w))

	fmt.Printf("Wallet saved to %s. BACK UP THIS FILE NOW!\n", walletFn)

	f, err := os.Open(walletFn)
	cobra.CheckErr(err)
	defer f.Close()

	// get the password
	// fmt.Print("Enter wallet password: ")
	// password, err := password.Read(os.Stdin)
	// fmt.Println()
	// cobra.CheckErr(err)

	// attempt to read it
	wkr := NewKey(WithPasswordOnly([]byte("password")))
	wr, err := wkr.Open(f, false)
	cobra.CheckErr(err)
	a, err := wr.Info(GetEthereumAddressByPrivateKeyHex)
	cobra.CheckErr(err)
	fmt.Println(a)
	fmt.Println(w.PrivateKey())
}
