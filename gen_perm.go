package main

import (
	"bufio"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

var cnt int
var start_time time.Time

// vim 修改这里
var words []string
var targetAddress string

var legal_cnt int

type Checkpoint struct {
	Cnt           int
	LegalCnt      int
	StartIdx      int
	Width         int
	TargetAddress string
	StartTime     time.Time
}

func saveCheckpoint(cp *Checkpoint) {
	file, err := os.Create("checkpoint.json")
	if err != nil {
		log.Fatalf("无法保存 checkpoint: %v", err)
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	_ = encoder.Encode(cp)
}

func verify(mnemonic string) bool {
	// 验证助记词是否合法并提取熵（含校验）
	_, err := bip39.MnemonicToByteArray(mnemonic)
	if err != nil {
		// log.Fatalf("助记词非法: %v", err)
		return false
	}
	// 生成种子 和 主密钥
	seed := bip39.NewSeed(mnemonic, "")
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		// log.Fatal(err)
		return false
	}
	legal_cnt++
	//派生路径: m/44'/60'/0'/0/0
	key, _ := masterKey.NewChildKey(bip32.FirstHardenedChild + uint32(44)) // 强化派生 对应 purpose'
	key, _ = key.NewChildKey(bip32.FirstHardenedChild + uint32(60))        // 强化派生 对应 coin_type'
	key, _ = key.NewChildKey(bip32.FirstHardenedChild + uint32(0))         // 强化派生 对应 account'
	key, _ = key.NewChildKey(uint32(0))                                    // 常规派生 对应 change
	key, _ = key.NewChildKey(uint32(0))                                    // 常规派生 对应 address_index

	privateKeyBytes := key.Key
	privateKeyECDSA, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return false
	}

	publicKey := privateKeyECDSA.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return false
	}

	address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()
	// fmt.Println("Ethereum address:", address)
	address = strings.ToLower(address)

	if address == targetAddress {
		return true
	}
	return false
}

// 全排列生成器
func permute(window []string, start int, before_window []string, after_window []string) {
	if start == len(window) {

		all := append([]string{}, before_window...)
		all = append(all, window...)
		all = append(all, after_window...)
		result := strings.Join(all, " ")
		// fmt.Println(result)
		cnt++
		if cnt%5000 == 0 {
			elapsed := time.Since(start_time)
			fmt.Printf("%d cost time: %s   legal cnt: %d\n", cnt, elapsed, legal_cnt)
		}
		if verify(result) {
			fmt.Println(result)
			outputFile, err := os.Create("matched_mnemonics.txt")
			if err != nil {
				log.Fatalf("无法创建文件: %v", err)
			}
			_, _ = io.WriteString(outputFile, result)
			outputFile.Close()
			os.Exit(0)
		}
		return
	}

	for i := start; i < len(window); i++ {
		// 交换元素
		window[start], window[i] = window[i], window[start]
		// 递归处理下一个位置
		permute(window, start+1, before_window, after_window)
		// 恢复交换
		window[start], window[i] = window[i], window[start]
	}
}

func readInput(filename string) ([]string, string) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if len(lines) < 2 {
		return nil, ""
	}

	wordList := strings.Fields(lines[0])
	address := strings.ToLower(strings.TrimSpace(lines[1]))

	return wordList, address
}

func main() {
	// cp, err := loadCheckpoint()

	words, targetAddress = readInput("input.txt")

	cnt = 0
	legal_cnt = 0
	start_time = time.Now()

	cp := &Checkpoint{
		Cnt:           0,
		LegalCnt:      0,
		StartIdx:      0,
		Width:         3,
		TargetAddress: targetAddress,
		StartTime:     start_time,
	}

	for width := 3; width <= len(words); width++ {
		for i := 0; i <= len(words)-width; i++ {
			before_window := words[0:i]
			window := words[i : i+width]
			after_windows := words[i+width:]
			permute(window, 0, before_window, after_windows)
			cp.Cnt = cnt
			cp.LegalCnt = legal_cnt
			cp.StartIdx = i + 1
			cp.Width = width
			saveCheckpoint(cp)
		}
	}

}

//deposit suspect ginger borrow month enjoy rather sweet diesel broken ritual later
