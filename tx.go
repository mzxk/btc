package btc

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const dustThreshold int64 = 546

type PaymentOutput struct {
	Address string
	Amount  int64
}

type resolvedOutput struct {
	address btcutil.Address
	script  []byte
	amount  int64
}

func (w *BitcoinWallet) estimateFee(inputCount, outputCount int, addrType AddressType) int64 {
	size := w.EstimateTxSize(inputCount, outputCount, addrType)
	if size <= 0 {
		return 0
	}

	feeRate := w.feeRate
	if feeRate <= 0 {
		feeRate = 1
	}

	return int64(size) * feeRate
}

func (w *BitcoinWallet) decodeAndValidateAddress(addr string) (btcutil.Address, error) {
	trimmed := strings.TrimSpace(addr)
	if trimmed == "" {
		return nil, fmt.Errorf("地址不能为空")
	}

	decoded, err := btcutil.DecodeAddress(trimmed, w.network)
	if err != nil {
		return nil, fmt.Errorf("解析地址失败: %w", err)
	}

	if !decoded.IsForNet(w.network) {
		return nil, fmt.Errorf("地址与当前网络不匹配")
	}

	return decoded, nil
}

func (w *BitcoinWallet) resolvePaymentOutputs(outputs []PaymentOutput) ([]resolvedOutput, int64, error) {
	if len(outputs) == 0 {
		return nil, 0, fmt.Errorf("至少需要一个转账输出")
	}

	resolved := make([]resolvedOutput, 0, len(outputs))
	var totalAmount int64

	for idx, output := range outputs {
		if output.Amount <= 0 {
			return nil, 0, fmt.Errorf("输出%d的金额必须大于0", idx)
		}

		addr, err := w.decodeAndValidateAddress(output.Address)
		if err != nil {
			return nil, 0, fmt.Errorf("输出%d的地址无效: %w", idx, err)
		}

		script, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return nil, 0, fmt.Errorf("创建输出%d脚本失败: %w", idx, err)
		}

		if output.Amount < dustThreshold {
			return nil, 0, fmt.Errorf("输出%d的金额低于dust阈值(%d)", idx, dustThreshold)
		}

		resolved = append(resolved, resolvedOutput{
			address: addr,
			script:  script,
			amount:  output.Amount,
		})

		totalAmount += output.Amount
		if totalAmount < 0 {
			return nil, 0, fmt.Errorf("转账金额总和溢出")
		}
	}

	return resolved, totalAmount, nil
}

func (w *BitcoinWallet) computeFeeAndChange(
	fromAddrType AddressType,
	totalAmount int64,
	outputCount int,
	utxos []UTXO,
	totalValue int64,
) (fee int64, changeAmount int64) {
	if len(utxos) == 0 {
		return 0, -totalAmount
	}

	feeNoChange := w.estimateFee(len(utxos), outputCount, fromAddrType)
	changeNoChange := totalValue - totalAmount - feeNoChange
	if changeNoChange < 0 {
		return feeNoChange, changeNoChange
	}

	feeWithChange := w.estimateFee(len(utxos), outputCount+1, fromAddrType)
	changeWithChange := totalValue - totalAmount - feeWithChange
	if changeWithChange > dustThreshold {
		return feeWithChange, changeWithChange
	}

	// 找零过小或不足以覆盖额外输出，直接作为手续费处理
	actualFee := totalValue - totalAmount
	if actualFee < 0 {
		return feeWithChange, changeWithChange
	}

	return actualFee, 0
}

// CreateTransaction 创建交易
func (w *BitcoinWallet) buildTransaction(
	fromAddrType AddressType,
	utxos []UTXO,
	outputs []resolvedOutput,
	changeAmount int64,
) (*wire.MsgTx, error) {
	if len(outputs) == 0 {
		return nil, fmt.Errorf("缺少交易输出")
	}

	if changeAmount < 0 {
		return nil, fmt.Errorf("找零金额无效: %d", changeAmount)
	}

	tx := wire.NewMsgTx(wire.TxVersion)

	for idx, utxo := range utxos {
		if utxo.TxID == "" {
			return nil, fmt.Errorf("输入%d缺少交易ID", idx)
		}

		txHash, err := chainhash.NewHashFromStr(utxo.TxID)
		if err != nil {
			return nil, fmt.Errorf("解析交易哈希失败: %w", err)
		}

		txIn := wire.NewTxIn(wire.NewOutPoint(txHash, utxo.Vout), nil, nil)
		tx.AddTxIn(txIn)
	}

	for _, output := range outputs {
		tx.AddTxOut(wire.NewTxOut(output.amount, output.script))
	}

	if changeAmount > dustThreshold {
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

		tx.AddTxOut(wire.NewTxOut(changeAmount, changeScript))
	}

	return tx, nil
}

func (w *BitcoinWallet) CreateTransaction(
	fromAddrType AddressType,
	toAddress string,
	amount int64,
	utxos []UTXO,
	changeAmount int64,
) (*wire.MsgTx, error) {
	resolved, _, err := w.resolvePaymentOutputs([]PaymentOutput{{Address: toAddress, Amount: amount}})
	if err != nil {
		return nil, err
	}

	return w.buildTransaction(fromAddrType, utxos, resolved, changeAmount)
}

func (w *BitcoinWallet) CreateTransactionWithOutputs(
	fromAddrType AddressType,
	utxos []UTXO,
	outputs []PaymentOutput,
	changeAmount int64,
) (*wire.MsgTx, error) {
	resolved, _, err := w.resolvePaymentOutputs(outputs)
	if err != nil {
		return nil, err
	}

	return w.buildTransaction(fromAddrType, utxos, resolved, changeAmount)
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
	return w.SendMany(fromAddrType, []PaymentOutput{{Address: toAddress, Amount: amount}})
}

func (w *BitcoinWallet) SendMany(fromAddrType AddressType, outputs []PaymentOutput) (string, error) {
	resolvedOutputs, totalAmount, err := w.resolvePaymentOutputs(outputs)
	if err != nil {
		return "", err
	}

	fromAddr, err := w.GetAddress(fromAddrType)
	if err != nil {
		return "", fmt.Errorf("获取发送方地址失败: %w", err)
	}

	utxos, err := w.GetUTXOs(fromAddr)
	if err != nil {
		return "", fmt.Errorf("获取UTXO失败: %w", err)
	}

	if len(utxos) == 0 {
		return "", fmt.Errorf("没有可用的UTXO")
	}

	requiredAmount := totalAmount
	var selectedUTXOs []UTXO
	var totalValue int64
	var estimatedFee int64
	var changeAmount int64

	for {
		selectedUTXOs, totalValue, err = w.SelectUTXOs(utxos, requiredAmount)
		if err != nil {
			return "", fmt.Errorf("选择UTXO失败: %w", err)
		}

		estimatedFee, changeAmount = w.computeFeeAndChange(fromAddrType, totalAmount, len(resolvedOutputs), selectedUTXOs, totalValue)
		if changeAmount >= 0 {
			break
		}

		requiredAmount = totalAmount + estimatedFee
	}

	tx, err := w.buildTransaction(fromAddrType, selectedUTXOs, resolvedOutputs, changeAmount)
	if err != nil {
		return "", fmt.Errorf("创建交易失败: %w", err)
	}

	if err = w.SignTransaction(tx, fromAddrType, selectedUTXOs); err != nil {
		return "", fmt.Errorf("签名交易失败: %w", err)
	}

	var buf bytes.Buffer
	if err = tx.Serialize(&buf); err != nil {
		return "", fmt.Errorf("序列化交易失败: %w", err)
	}

	txHex := hex.EncodeToString(buf.Bytes())
	return w.BroadcastTransaction(txHex)
}

// SendAll 发送全部余额
func (w *BitcoinWallet) SendAll(fromAddrType AddressType, toAddress string) (string, error) {
	targetAddr, err := w.decodeAndValidateAddress(toAddress)
	if err != nil {
		return "", err
	}

	fromAddr, err := w.GetAddress(fromAddrType)
	if err != nil {
		return "", fmt.Errorf("获取发送方地址失败: %w", err)
	}

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
	feeRate := w.feeRate
	if feeRate <= 0 {
		feeRate = 1
	}
	estimatedFee := int64(estimatedSize) * feeRate

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
	return w.CreateRawTransactionWithOutputs(fromAddrType, []PaymentOutput{{Address: toAddress, Amount: amount}}, utxos)
}

func (w *BitcoinWallet) CreateRawTransactionWithOutputs(
	fromAddrType AddressType,
	outputs []PaymentOutput,
	utxos []UTXO,
) (string, error) {
	resolvedOutputs, totalAmount, err := w.resolvePaymentOutputs(outputs)
	if err != nil {
		return "", err
	}

	if len(utxos) == 0 {
		return "", fmt.Errorf("没有可用的UTXO")
	}

	var totalValue int64
	for _, utxo := range utxos {
		totalValue += utxo.Value
		if totalValue < 0 {
			return "", fmt.Errorf("UTXO金额总和溢出")
		}
	}

	_, changeAmount := w.computeFeeAndChange(fromAddrType, totalAmount, len(resolvedOutputs), utxos, totalValue)
	if changeAmount < 0 {
		return "", fmt.Errorf("余额不足以支付金额和手续费")
	}

	tx, err := w.buildTransaction(fromAddrType, utxos, resolvedOutputs, changeAmount)
	if err != nil {
		return "", fmt.Errorf("创建交易失败: %w", err)
	}

	var buf bytes.Buffer
	if err = tx.Serialize(&buf); err != nil {
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
