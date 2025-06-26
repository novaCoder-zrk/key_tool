package main

import (
	"fmt"
	"log"
	"os"
    "io"
	"strings"
    "encoding/json"
    "bufio"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
    "time"
    "github.com/ethereum/go-ethereum/crypto"
    "crypto/ecdsa"
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
	Index         int
	TargetAddress string
    Target        []string
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

func verify(mnemonic string) bool{
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
	//派生路径: m/44'/0'/0'/0/0
	key, _ := masterKey.NewChildKey(bip32.FirstHardenedChild + uint32(44)) // 强化派生 对应 purpose'
	key, _ = key.NewChildKey(bip32.FirstHardenedChild + uint32(60))         // 强化派生 对应 coin_type'
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
        Index:      0,
        TargetAddress: targetAddress,
        StartTime:     start_time,
    }

    for i := 0; i < len(words); i++ {
        before := words[0:i]
        after := words[i+1:]

        wordList := bip39.GetWordList()
        for _, word := range wordList {    
            cnt++    
            if cnt % 100000 == 0 {
                elapsed := time.Since(start_time)
                fmt.Printf("已尝试 %d 个组合，合法组合 %d，耗时 %s\n, index %d", cnt, legal_cnt, elapsed, i)
            }      
            all := append([]string{}, before...)
            all = append(all, word)
            all = append(all, after...)

            result := strings.Join(all, " ")
            if verify(result) {
                fmt.Println(result)
                outputFile, err := os.Create("matched_mnemonics.txt")
                if err != nil {
                    log.Fatalf("无法创建文件: %v", err)
                }
                 _, _ = io.WriteString(outputFile, result)
                outputFile.Close()

                cp.Target = all
                cp.Cnt = cnt
                cp.LegalCnt = legal_cnt
                cp.Index = i
                saveCheckpoint(cp)
                os.Exit(0)
            }
        }
        cp.Cnt = cnt
        cp.LegalCnt = legal_cnt
        cp.Index = i
        saveCheckpoint(cp)
    }
    fmt.Println("没有找到匹配的助记词组合")

}
//deposit suspect ginger borrow month enjoy rather sweet diesel broken ritual later
