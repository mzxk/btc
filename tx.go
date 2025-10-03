package btc

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// CreateTransaction 创建交易
func (w *BitcoinWallet) CreateTransaction(
	fromAddrType AddressType,
	toAddress string,
	amount int64,
	utxos []UTXO,
	totalValue int64,
) (*wire.MsgTx, error) {
	// 创建新交易
	tx := wire.NewMsgTx(wire.TxVersion)

	// 添加输入
	for _, utxo := range utxos {
		txHash, err := chainhash.NewHashFromStr(utxo.TxID)
		if err != nil {
			return nil, fmt.Errorf("解析交易哈希失败: %w", err)
		}

		txIn := wire.NewTxIn(wire.NewOutPoint(txHash, utxo.Vout), nil, nil)
		tx.AddTxIn(txIn)
	}

	// 解析目标地址
	targetAddr, err := btcutil.DecodeAddress(toAddress, w.network)
	if err != nil {
		return nil, fmt.Errorf("解析目标地址失败: %w", err)
	}

	// 创建接收方输出脚本
	receiverScript, err := txscript.PayToAddrScript(targetAddr)
	if err != nil {
		return nil, fmt.Errorf("创建接收方脚本失败: %w", err)
	}

	// 添加接收方输出
	tx.AddTxOut(wire.NewTxOut(amount, receiverScript))

	// 计算找零金额
	estimatedSize := w.EstimateTxSize(len(utxos), 2, fromAddrType)
	estimatedFee := int64(estimatedSize) * w.feeRate
	changeAmount := totalValue - amount - estimatedFee

	// 如果找零金额大于防尘阈值，则创建找零输出
	dustThreshold := int64(546)
	if changeAmount > dustThreshold {
		// 获取找零地址（使用相同的地址类型）
		changeAddr, err := w.GetAddress(fromAddrType)
		if err != nil {
			return nil, fmt.Errorf("创建找零地址失败: %w", err)
		}

		changeAddrObj, err := btcutil.DecodeAddress(changeAddr, w.network)
		if err != nil {
			return nil, fmt.Errorf("解析找零地址失败: %w", err)
		}

		changeScript, err := txscript.PayToAddrScript(changeAddrObj)
		if err != nil {
			return nil, fmt.Errorf("创建找零脚本失败: %w", err)
		}

		// 添加找零输出
		tx.AddTxOut(wire.NewTxOut(changeAmount, changeScript))
	}

	return tx, nil
}

// SignTransaction 签名交易
func (w *BitcoinWallet) SignTransaction(tx *wire.MsgTx, fromAddrType AddressType, utxos []UTXO) error {
	// 获取发送方地址
	fromAddr, err := w.GetAddress(fromAddrType)
	if err != nil {
		return fmt.Errorf("获取发送方地址失败: %w", err)
	}

	fromAddrObj, err := btcutil.DecodeAddress(fromAddr, w.network)
	if err != nil {
		return fmt.Errorf("解析发送方地址失败: %w", err)
	}

	// 获取发送方脚本
	fromScript, err := txscript.PayToAddrScript(fromAddrObj)
	if err != nil {
		return fmt.Errorf("创建发送方脚本失败: %w", err)
	}

	// 根据地址类型选择签名方法
	for i, utxo := range utxos {
		switch fromAddrType {
		case P2PKH:
			err = w.SignP2PKHTransaction(tx, i, fromScript)
		case P2WPKH:
			err = w.SignP2WPKHTransaction(tx, i, utxo.Value, fromScript)
		case P2SH:
			err = w.SignP2SHTransaction(tx, i, utxo.Value, fromScript)
		case P2TR:
			err = w.SignP2TRTransaction(tx, i, utxo.Value, fromScript)
		default:
			return fmt.Errorf("不支持的地址类型: %s", fromAddrType)
		}

		if err != nil {
			return fmt.Errorf("签名输入%d失败: %w", i, err)
		}
	}

	return nil
}

// SendTransaction 发送交易
func (w *BitcoinWallet) SendTransaction(fromAddrType AddressType, toAddress string, amount int64) (string, error) {
	// 获取发送方地址
	fromAddr, err := w.GetAddress(fromAddrType)
	if err != nil {
		return "", fmt.Errorf("获取发送方地址失败: %w", err)
	}

	// 获取UTXO
	utxos, err := w.GetUTXOs(fromAddr)
	if err != nil {
		return "", fmt.Errorf("获取UTXO失败: %w", err)
	}

	if len(utxos) == 0 {
		return "", fmt.Errorf("没有可用的UTXO")
	}

	// 计算所需金额（包含手续费）
	estimatedSize := w.EstimateTxSize(len(utxos), 2, fromAddrType)
	estimatedFee := int64(estimatedSize) * w.feeRate
	requiredAmount := amount + estimatedFee

	// 选择UTXO
	selectedUTXOs, totalValue, err := w.SelectUTXOs(utxos, requiredAmount)
	if err != nil {
		return "", fmt.Errorf("选择UTXO失败: %w", err)
	}

	// 创建交易
	tx, err := w.CreateTransaction(fromAddrType, toAddress, amount, selectedUTXOs, totalValue)
	if err != nil {
		return "", fmt.Errorf("创建交易失败: %w", err)
	}

	// 签名交易
	err = w.SignTransaction(tx, fromAddrType, selectedUTXOs)
	if err != nil {
		return "", fmt.Errorf("签名交易失败: %w", err)
	}

	// 序列化交易
	var buf bytes.Buffer
	err = tx.Serialize(&buf)
	if err != nil {
		return "", fmt.Errorf("序列化交易失败: %w", err)
	}

	txHex := hex.EncodeToString(buf.Bytes())

	// 广播交易
	return w.BroadcastTransaction(txHex)
}

// SendAll 发送全部余额
func (w *BitcoinWallet) SendAll(fromAddrType AddressType, toAddress string) (string, error) {
	// 获取发送方地址
	fromAddr, err := w.GetAddress(fromAddrType)
	if err != nil {
		return "", fmt.Errorf("获取发送方地址失败: %w", err)
	}

	// 获取UTXO
	utxos, err := w.GetUTXOs(fromAddr)
	if err != nil {
		return "", fmt.Errorf("获取UTXO失败: %w", err)
	}

	if len(utxos) == 0 {
		return "", fmt.Errorf("没有可用的UTXO")
	}

	// 计算总余额
	var totalBalance int64
	for _, utxo := range utxos {
		totalBalance += utxo.Value
	}

	// 估算手续费
	estimatedSize := w.EstimateTxSize(len(utxos), 1, fromAddrType) // 1个输出
	estimatedFee := int64(estimatedSize) * w.feeRate

	// 计算实际转账金额
	transferAmount := totalBalance - estimatedFee

	if transferAmount <= 0 {
		return "", fmt.Errorf("余额不足以支付手续费")
	}

	// 创建交易
	tx := wire.NewMsgTx(wire.TxVersion)

	// 添加所有输入
	for _, utxo := range utxos {
		txHash, err := chainhash.NewHashFromStr(utxo.TxID)
		if err != nil {
			return "", fmt.Errorf("解析交易哈希失败: %w", err)
		}

		txIn := wire.NewTxIn(wire.NewOutPoint(txHash, utxo.Vout), nil, nil)
		tx.AddTxIn(txIn)
	}

	// 解析目标地址
	targetAddr, err := btcutil.DecodeAddress(toAddress, w.network)
	if err != nil {
		return "", fmt.Errorf("解析目标地址失败: %w", err)
	}

	// 创建接收方输出脚本
	receiverScript, err := txscript.PayToAddrScript(targetAddr)
	if err != nil {
		return "", fmt.Errorf("创建接收方脚本失败: %w", err)
	}

	// 添加接收方输出（全部余额减去手续费）
	tx.AddTxOut(wire.NewTxOut(transferAmount, receiverScript))

	// 签名交易
	err = w.SignTransaction(tx, fromAddrType, utxos)
	if err != nil {
		return "", fmt.Errorf("签名交易失败: %w", err)
	}

	// 序列化交易
	var buf bytes.Buffer
	err = tx.Serialize(&buf)
	if err != nil {
		return "", fmt.Errorf("序列化交易失败: %w", err)
	}

	txHex := hex.EncodeToString(buf.Bytes())

	// 广播交易
	return w.BroadcastTransaction(txHex)
}

// CreateRawTransaction 创建原始交易（不签名）
func (w *BitcoinWallet) CreateRawTransaction(
	fromAddrType AddressType,
	toAddress string,
	amount int64,
	utxos []UTXO,
) (string, error) {
	// 计算总金额
	var totalValue int64
	for _, utxo := range utxos {
		totalValue += utxo.Value
	}

	// 创建交易
	tx, err := w.CreateTransaction(fromAddrType, toAddress, amount, utxos, totalValue)
	if err != nil {
		return "", fmt.Errorf("创建交易失败: %w", err)
	}

	// 序列化交易
	var buf bytes.Buffer
	err = tx.Serialize(&buf)
	if err != nil {
		return "", fmt.Errorf("序列化交易失败: %w", err)
	}

	return hex.EncodeToString(buf.Bytes()), nil
}

// SignRawTransaction 签名原始交易
func (w *BitcoinWallet) SignRawTransaction(txHex string, fromAddrType AddressType, utxos []UTXO) (string, error) {
	// 解码交易
	data, err := hex.DecodeString(txHex)
	if err != nil {
		return "", fmt.Errorf("解码十六进制失败: %w", err)
	}

	tx := wire.NewMsgTx(wire.TxVersion)
	err = tx.Deserialize(bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("反序列化交易失败: %w", err)
	}

	// 签名交易
	err = w.SignTransaction(tx, fromAddrType, utxos)
	if err != nil {
		return "", fmt.Errorf("签名交易失败: %w", err)
	}

	// 序列化已签名的交易
	var buf bytes.Buffer
	err = tx.Serialize(&buf)
	if err != nil {
		return "", fmt.Errorf("序列化交易失败: %w", err)
	}

	return hex.EncodeToString(buf.Bytes()), nil
}
