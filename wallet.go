package wallet

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

func NewEhereumWallet() (*Wallet, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}
	privateKeyBytes := crypto.FromECDSA(privateKey)
	w := &Wallet{
		Meta: walletMetadata{
			DisplayName: "Main Wallet",
			Created:     time.Now().Local().Format("20060102 15:04:05"),
			// TODO: set correctly
			GenesisID: "",
		},
		Secrets: walletSecrets{
			PrivateKey: hex.EncodeToString(privateKeyBytes),
		},
	}
	return w, nil
}

// Wallet is the basic data structure.
type Wallet struct {
	// keystore string
	// password string
	// unlocked bool
	Meta    walletMetadata `json:"meta"`
	Secrets walletSecrets  `json:"crypto"`
}

// EncryptedWalletFile is the encrypted representation of the wallet on the filesystem.
type EncryptedWalletFile struct {
	Meta    walletMetadata         `json:"meta"`
	Secrets walletSecretsEncrypted `json:"crypto"`
}

type walletMetadata struct {
	DisplayName string `json:"displayName"`
	Created     string `json:"created"`
	GenesisID   string `json:"genesisID"`
}

type hexEncodedCiphertext []byte

func (c *hexEncodedCiphertext) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(*c))
}

func (c *hexEncodedCiphertext) UnmarshalJSON(data []byte) (err error) {
	var hexString string
	if err = json.Unmarshal(data, &hexString); err != nil {
		return
	}
	*c, err = hex.DecodeString(hexString)
	return
}

type walletSecretsEncrypted struct {
	Cipher       string               `json:"cipher"`
	CipherText   hexEncodedCiphertext `json:"cipherText"`
	CipherParams struct {
		IV hexEncodedCiphertext `json:"iv"`
	} `json:"cipherParams"`
	KDF       string `json:"kdf"`
	KDFParams struct {
		DKLen      int                  `json:"dklen"`
		Hash       string               `json:"hash"`
		Salt       hexEncodedCiphertext `json:"salt"`
		Iterations int                  `json:"iterations"`
	} `json:"kdfparams"`
}

type walletSecrets struct {
	PrivateKey string `json:"privatekey"`
}

func (w *Wallet) PrivateKey() string {
	return w.Secrets.PrivateKey
}

type InfoCallBack func(string) (string, error)

var GetEthereumAddressByPrivateKeyHex = func(privateHex string) (string, error) {
	privateKey, err := crypto.HexToECDSA(privateHex)
	if err != nil {
		return "", err
	}
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}
	return crypto.PubkeyToAddress(*publicKeyECDSA).Hex(), nil
}

func (w *Wallet) Info(cb InfoCallBack) (string, error) {
	return cb(w.PrivateKey())
}
