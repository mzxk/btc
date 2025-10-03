package btc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// AddressType 地址类型枚举
type AddressType string

const (
	P2PKH  AddressType = "p2pkh"  // 1开头地址
	P2WPKH AddressType = "p2wpkh" // bc1q开头地址
	P2SH   AddressType = "p2sh"   // 3开头地址
	P2TR   AddressType = "p2tr"   // bc1p开头地址
)

// Network 网络类型
type Network string

const (
	MainNet Network = "mainnet"
	TestNet Network = "testnet"
)

// UTXO 未花费的交易输出
type UTXO struct {
	TxID  string `json:"txid"`
	Vout  uint32 `json:"vout"`
	Value int64  `json:"value"`
}

// BitcoinWallet 比特币钱包实现
type BitcoinWallet struct {
	privateKey *btcec.PrivateKey
	publicKey  *btcec.PublicKey
	network    *chaincfg.Params
	apiURL     string
	feeRate    int64 // satoshi per byte
	httpClient *http.Client
}

// NewWallet 创建新钱包
func NewWallet(wif string, network Network) (*BitcoinWallet, error) {
	var netParams *chaincfg.Params
	var apiURL string

	switch network {
	case MainNet:
		netParams = &chaincfg.MainNetParams
		apiURL = "https://blockstream.info/api"
	case TestNet:
		netParams = &chaincfg.TestNet3Params
		apiURL = "https://blockstream.info/testnet/api"
	default:
		return nil, fmt.Errorf("不支持的网络类型: %s", network)
	}

	key, err := btcutil.DecodeWIF(wif)
	if err != nil {
		return nil, fmt.Errorf("解码WIF失败: %w", err)
	}

	if !key.IsForNet(netParams) {
		return nil, fmt.Errorf("私钥网络不匹配")
	}

	return &BitcoinWallet{
		privateKey: key.PrivKey,
		publicKey:  key.PrivKey.PubKey(),
		network:    netParams,
		apiURL:     apiURL,
		feeRate:    1, // 默认费率 1 sat/byte
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}, nil
}

// SetFeeRate 设置费率
func (w *BitcoinWallet) SetFeeRate(feeRate int64) {
	w.feeRate = feeRate
}

// GetFeeRate 获取费率
func (w *BitcoinWallet) GetFeeRate() int64 {
	return w.feeRate
}

// GetAddress 获取指定类型的地址
func (w *BitcoinWallet) GetAddress(addrType AddressType) (string, error) {
	switch addrType {
	case P2PKH:
		return w.getP2PKHAddress()
	case P2WPKH:
		return w.getP2WPKHAddress()
	case P2SH:
		return w.getP2SHAddress()
	case P2TR:
		return w.getP2TRAddress()
	default:
		return "", fmt.Errorf("不支持的地址类型: %s", addrType)
	}
}

// getP2PKHAddress 获取P2PKH地址
func (w *BitcoinWallet) getP2PKHAddress() (string, error) {
	pubKeyHash := btcutil.Hash160(w.publicKey.SerializeCompressed())
	addr, err := btcutil.NewAddressPubKeyHash(pubKeyHash, w.network)
	if err != nil {
		return "", err
	}
	return addr.EncodeAddress(), nil
}

// getP2WPKHAddress 获取P2WPKH地址
func (w *BitcoinWallet) getP2WPKHAddress() (string, error) {
	pubKeyHash := btcutil.Hash160(w.publicKey.SerializeCompressed())
	addr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, w.network)
	if err != nil {
		return "", err
	}
	return addr.EncodeAddress(), nil
}

// getP2SHAddress 获取P2SH地址 (嵌套SegWit)
func (w *BitcoinWallet) getP2SHAddress() (string, error) {
	pubKeyHash := btcutil.Hash160(w.publicKey.SerializeCompressed())

	// 创建P2WPKH赎回脚本
	witnessScript, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_0).
		AddData(pubKeyHash).
		Script()
	if err != nil {
		return "", err
	}

	scriptHash := btcutil.Hash160(witnessScript)
	addr, err := btcutil.NewAddressScriptHashFromHash(scriptHash, w.network)
	if err != nil {
		return "", err
	}

	return addr.EncodeAddress(), nil
}

// getP2TRAddress 获取P2TR地址
func (w *BitcoinWallet) getP2TRAddress() (string, error) {
	tapKey := txscript.ComputeTaprootKeyNoScript(w.publicKey)
	addr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(tapKey), w.network)
	if err != nil {
		return "", err
	}
	return addr.String(), nil
}

// GetBalance 获取地址余额
func (w *BitcoinWallet) GetBalance(address string) (int64, error) {
	url := fmt.Sprintf("%s/address/%s", w.apiURL, address)

	resp, err := w.httpClient.Get(url)
	if err != nil {
		return 0, fmt.Errorf("请求余额失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = resp.Status
		}
		return 0, fmt.Errorf("请求余额失败: %s", msg)
	}

	var result struct {
		ChainStats struct {
			FundedTxoSum int64 `json:"funded_txo_sum"`
			SpentTxoSum  int64 `json:"spent_txo_sum"`
		} `json:"chain_stats"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("解析余额失败: %w", err)
	}

	return result.ChainStats.FundedTxoSum - result.ChainStats.SpentTxoSum, nil
}

// GetUTXOs 获取地址的UTXO
func (w *BitcoinWallet) GetUTXOs(address string) ([]UTXO, error) {
	url := fmt.Sprintf("%s/address/%s/utxo", w.apiURL, address)

	resp, err := w.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("请求UTXO失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = resp.Status
		}
		return nil, fmt.Errorf("请求UTXO失败: %s", msg)
	}

	var utxos []UTXO
	if err := json.NewDecoder(resp.Body).Decode(&utxos); err != nil {
		return nil, fmt.Errorf("解析UTXO失败: %w", err)
	}

	return utxos, nil
}

// GetTxHex 获取交易的原始十六进制数据
func (w *BitcoinWallet) GetTxHex(txID string) (string, error) {
	url := fmt.Sprintf("%s/tx/%s/hex", w.apiURL, txID)

	resp, err := w.httpClient.Get(url)
	if err != nil {
		return "", fmt.Errorf("请求交易数据失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = resp.Status
		}
		return "", fmt.Errorf("请求交易数据失败: %s", msg)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取响应失败: %w", err)
	}

	return string(body), nil
}

// BroadcastTransaction 广播交易
func (w *BitcoinWallet) BroadcastTransaction(txHex string) (string, error) {
	url := fmt.Sprintf("%s/tx", w.apiURL)

	resp, err := w.httpClient.Post(url, "text/plain", bytes.NewBufferString(txHex))
	if err != nil {
		return "", fmt.Errorf("广播交易失败: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取响应失败: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = resp.Status
		}
		return "", fmt.Errorf("广播失败: %s", msg)
	}

	return string(body), nil
}

// SelectUTXOs 选择足够的UTXO来支付
func (w *BitcoinWallet) SelectUTXOs(utxos []UTXO, amount int64) ([]UTXO, int64, error) {
	if len(utxos) == 0 {
		return nil, 0, fmt.Errorf("没有可用的UTXO")
	}

	sorted := append([]UTXO(nil), utxos...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Value < sorted[j].Value
	})

	var selected []UTXO
	var total int64

	for _, utxo := range sorted {
		selected = append(selected, utxo)
		total += utxo.Value

		if total >= amount {
			return selected, total, nil
		}
	}

	return nil, 0, fmt.Errorf("余额不足: 需要 %d, 可用 %d", amount, total)
}

// EstimateTxSize 估算交易大小
func (w *BitcoinWallet) EstimateTxSize(inputs, outputs int, addrType AddressType) int {
	switch addrType {
	case P2PKH:
		// 传统地址
		baseSize := 10 + inputs*148 + outputs*34
		return baseSize
	case P2WPKH:
		// 原生SegWit
		baseSize := 10 + inputs*64 + outputs*31
		witnessSize := inputs*107 + 2
		vSize := (baseSize*3 + baseSize + witnessSize) / 4
		return vSize
	case P2SH:
		// 嵌套SegWit
		baseSize := 10 + inputs*148 + outputs*34
		witnessSize := inputs*107 + 2
		vSize := (baseSize*3 + baseSize + witnessSize) / 4
		return vSize
	case P2TR:
		// Taproot
		baseSize := 10 + inputs*64 + outputs*31
		witnessSize := inputs*64 + 2
		vSize := (baseSize*3 + baseSize + witnessSize) / 4
		return vSize
	default:
		return 250 // 默认值
	}
}

// SignP2PKHTransaction 签名P2PKH交易
func (w *BitcoinWallet) SignP2PKHTransaction(tx *wire.MsgTx, idx int, pkScript []byte) error {
	sigHash, err := txscript.CalcSignatureHash(pkScript, txscript.SigHashAll, tx, idx)
	if err != nil {
		return fmt.Errorf("计算签名哈希失败: %w", err)
	}

	signature := ecdsa.Sign(w.privateKey, sigHash)
	sigWithHashType := append(signature.Serialize(), byte(txscript.SigHashAll))

	tx.TxIn[idx].SignatureScript, err = txscript.NewScriptBuilder().
		AddData(sigWithHashType).
		AddData(w.publicKey.SerializeCompressed()).
		Script()
	if err != nil {
		return fmt.Errorf("构建签名脚本失败: %w", err)
	}

	return nil
}

// SignP2WPKHTransaction 签名P2WPKH交易
func (w *BitcoinWallet) SignP2WPKHTransaction(tx *wire.MsgTx, idx int, value int64, pkScript []byte) error {
	prevFetcher := txscript.NewCannedPrevOutputFetcher(pkScript, value)
	sigHash, err := txscript.CalcWitnessSigHash(
		pkScript, txscript.NewTxSigHashes(tx, prevFetcher), txscript.SigHashAll, tx, idx, value,
	)
	if err != nil {
		return fmt.Errorf("计算witness签名哈希失败: %w", err)
	}

	signature := ecdsa.Sign(w.privateKey, sigHash)
	sigWithHashType := append(signature.Serialize(), byte(txscript.SigHashAll))

	tx.TxIn[idx].Witness = wire.TxWitness{
		sigWithHashType,
		w.publicKey.SerializeCompressed(),
	}

	return nil
}

// SignP2SHTransaction 签名P2SH交易
func (w *BitcoinWallet) SignP2SHTransaction(tx *wire.MsgTx, idx int, value int64, pkScript []byte) error {
	// 获取发送方地址的公钥哈希
	pubKeyHash := btcutil.Hash160(w.publicKey.SerializeCompressed())

	// 创建P2WPKH赎回脚本
	witnessScript, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_0).
		AddData(pubKeyHash).
		Script()
	if err != nil {
		return fmt.Errorf("创建赎回脚本失败: %w", err)
	}

	// 计算签名哈希（使用P2WPKH脚本，因为这是嵌套SegWit）
	prevFetcher := txscript.NewCannedPrevOutputFetcher(pkScript, value)
	sigHashes := txscript.NewTxSigHashes(tx, prevFetcher)

	sigHash, err := txscript.CalcWitnessSigHash(
		witnessScript, sigHashes, txscript.SigHashAll, tx, idx, value,
	)
	if err != nil {
		return fmt.Errorf("计算witness签名哈希失败: %w", err)
	}

	// 生成签名
	signature := ecdsa.Sign(w.privateKey, sigHash)
	sigWithHashType := append(signature.Serialize(), byte(txscript.SigHashAll))

	// 设置witness数据（签名 + 公钥）
	tx.TxIn[idx].Witness = wire.TxWitness{
		sigWithHashType,
		w.publicKey.SerializeCompressed(),
	}

	// 设置SignatureScript为完整的赎回脚本（这是P2SH-Nested SegWit的正确方式）
	tx.TxIn[idx].SignatureScript, err = txscript.NewScriptBuilder().
		AddData(witnessScript).
		Script()
	if err != nil {
		return fmt.Errorf("构建签名脚本失败: %w", err)
	}

	return nil
}

// SignP2TRTransaction 签名P2TR交易
func (w *BitcoinWallet) SignP2TRTransaction(tx *wire.MsgTx, idx int, value int64, pkScript []byte) error {
	// 对于P2TR，需要重新生成正确的prevOutputScript
	// 因为传入的pkScript可能是通过PayToAddrScript生成的，但P2TR需要特殊的处理

	// 生成P2TR地址
	p2trAddr, err := w.getP2TRAddress()
	if err != nil {
		return fmt.Errorf("获取P2TR地址失败: %w", err)
	}

	// 解析P2TR地址
	addrObj, err := btcutil.DecodeAddress(p2trAddr, w.network)
	if err != nil {
		return fmt.Errorf("解析P2TR地址失败: %w", err)
	}

	// 生成正确的P2TR输出脚本
	prevScript, err := txscript.PayToAddrScript(addrObj)
	if err != nil {
		return fmt.Errorf("生成P2TR脚本失败: %w", err)
	}

	// 创建PrevOutputFetcher
	prevFetcher := txscript.NewCannedPrevOutputFetcher(prevScript, value)
	sighashes := txscript.NewTxSigHashes(tx, prevFetcher)

	// 使用RawTxInTaprootSignature生成Taproot签名
	sig, err := txscript.RawTxInTaprootSignature(
		tx, sighashes, idx, value, prevScript, nil, txscript.SigHashDefault, w.privateKey,
	)
	if err != nil {
		return fmt.Errorf("生成Taproot签名失败: %w", err)
	}

	// 设置witness数据（只有签名，Taproot key-path不需要公钥）
	tx.TxIn[idx].Witness = wire.TxWitness{sig}
	return nil
}
