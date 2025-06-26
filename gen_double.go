package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/robfig/cron/v3"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

var start_time time.Time

var words []string
var targetAddress string

var total_cnt int
var total_legal_cnt int
var receiver string
var success_flag bool

type Checkpoint struct {
	Cnt           int
	LegalCnt      int
	Index1        int
	Index2        int
	Word1         string
	Word2         string
	TargetAddress string
	// Target        []string
	StartTime time.Time
}

func sendEmail(receiver string, content string) {
	smtpHost := "zhenxiao.mail.pairserver.com"
	smtpPort := "465"
	sender := "support@metaphantasy.com"
	password := "chatbot230704"

	subject := "Subject:replace_double!\r\n"
	body := content
	if body == "" {
		filename := "checkpoint_0_0_.json"
		data, err := ioutil.ReadFile(filename)
		if err != nil {
			log.Fatal("无法读取 JSON 文件：", err)
			return
		}
		var prettyJSON map[string]interface{}
		if err := json.Unmarshal(data, &prettyJSON); err != nil {
			log.Fatal("JSON 解码失败：", err)
			return
		}
		formattedBody, err := json.MarshalIndent(prettyJSON, "", "  ")
		if err != nil {
			log.Fatal("JSON 格式化失败：", err)
			return
		}
		body = string(formattedBody)
	}

	msg := strings.Join([]string{
		"From: " + sender,
		"To: " + receiver,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=\"UTF-8\"",
		"", // 空行分隔头部和正文
		body,
	}, "\r\n")

	// 连接配置
	serverAddr := smtpHost + ":" + smtpPort
	tlsconfig := &tls.Config{
		ServerName: smtpHost,
		// 必须为 false，Gmail 要求验证证书
		InsecureSkipVerify: false,
	}

	// 建立 TLS 连接
	conn, err := tls.Dial("tcp", serverAddr, tlsconfig)
	if err != nil {
		log.Fatalf("无法连接 SMTP 服务器: %v", err)
	}
	defer conn.Close()

	// 创建客户端
	client, err := smtp.NewClient(conn, smtpHost)
	if err != nil {
		log.Fatalf("SMTP 客户端创建失败: %v", err)
	}

	// 登录认证
	auth := smtp.PlainAuth("", sender, password, smtpHost)
	if err = client.Auth(auth); err != nil {
		log.Fatalf("SMTP 认证失败: %v", err)
	}

	// 设置发件人和收件人
	if err = client.Mail(sender); err != nil {
		log.Fatalf("设置发件人失败: %v", err)
	}
	if err = client.Rcpt(receiver); err != nil {
		log.Fatalf("设置收件人失败: %v", err)
	}

	// 写入邮件内容
	w, err := client.Data()
	if err != nil {
		log.Fatalf("开启邮件写入失败: %v", err)
	}
	_, err = w.Write([]byte(msg))
	if err != nil {
		log.Fatalf("写入邮件内容失败: %v", err)
	}
	w.Close()
	client.Quit()

	fmt.Println("邮件发送成功！")
}

func timer_due(receiver string) {
	if receiver == "" {
		fmt.Println("no receiver...")
		return
	}
	c := cron.New(cron.WithSeconds())

	// 每天早上 8 点整触发：秒 分 时 日 月 星期
	_, err := c.AddFunc("0 0 8 * * *", func() {
		sendEmail(receiver, "")
	})
	if err != nil {
		log.Fatal("定时任务添加失败:", err)
	}

	fmt.Println("邮件定时器启动，等待每天 8 点发送...")
	c.Start()

	select {} // 阻塞主线程，持续运行
}

func saveCheckpoint(cp *Checkpoint, i, j int) {
	filename := "checkpoint_" + strconv.Itoa(i) + "_" + strconv.Itoa(j) + "_.json"
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("无法保存 checkpoint: %v", err)
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	_ = encoder.Encode(cp)
}

func verify(mnemonic string, legal_cnt *int) bool {
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
	*legal_cnt = *legal_cnt + 1
	total_legal_cnt++
	//派生路径: m/44'/0'/0'/0/0
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
		fmt.Println("Ethereum address:", address)
		return true
	}
	return false
}

func readInput(filename string) ([]string, string, string) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, "", ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if len(lines) < 2 {
		return nil, "", ""
	}

	wordList := strings.Fields(lines[0])
	address := strings.ToLower(strings.TrimSpace(lines[1]))
	receiver := strings.TrimSpace(lines[2])

	return wordList, address, receiver
}

func traverse(i, j int, words []string) {
	// if (i > 1) || (j > 1) { return }
	cp := &Checkpoint{
		Cnt:           0,
		LegalCnt:      0,
		Index1:        0,
		Index2:        0,
		TargetAddress: targetAddress,
		StartTime:     start_time,
	}

	wordList := bip39.GetWordList()
	cnt := 0
	legal_cnt := 0
	for _, word1 := range wordList {
		for _, word2 := range wordList {
			cnt++
			total_cnt++

			if cnt%10000 == 0 {
				elapsed := time.Since(start_time)
				fmt.Printf("已尝试 %d 个组合，合法组合 %d，耗时 %s, index1 %d, index2 %d,  word1 %s,  word2 %s \n", cnt, legal_cnt, elapsed, i, j, word1, word2)
				cp.Cnt = cnt
				cp.LegalCnt = legal_cnt
				cp.Index1 = i
				cp.Index2 = j
				cp.Word1 = word1
				cp.Word2 = word2
				saveCheckpoint(cp, i, j)

				total_cp := &Checkpoint{
					Cnt:           total_cnt,
					LegalCnt:      total_legal_cnt,
					TargetAddress: targetAddress,
					StartTime:     start_time,
				}
				saveCheckpoint(total_cp, 0, 0)
			}
			tmp := words[:]
			tmp[i] = word1
			tmp[j] = word2
			result := strings.Join(tmp, " ")
			// print(result)

			if verify(result, &legal_cnt) {
				success_flag = true
				fmt.Println("找到了！")
				fmt.Println(result)
				outputFile, err := os.Create("matched_mnemonics.txt")
				if err != nil {
					log.Fatalf("无法创建文件: %v", err)
				}
				_, _ = io.WriteString(outputFile, result)
				outputFile.Close()
				sendEmail(receiver, "find the mnemonics successfully, see the matched_mnemonics.txt!")
				// cp.Target = tmp
				cp.Cnt = cnt
				cp.LegalCnt = legal_cnt
				cp.Index1 = i
				cp.Index2 = j
				cp.Word1 = word1
				cp.Word2 = word2
				saveCheckpoint(cp, i, j)
				return
			}
			if success_flag {
				return
			}
		}
	}
}

func main() {
	// cp, err := loadCheckpoint()
	total_cnt = 0
	total_legal_cnt = 0
	success_flag = false

	words, targetAddress, receiver = readInput("input.txt")
	start_time = time.Now()
	go timer_due(receiver)
	var wg sync.WaitGroup
	for i := 0; i < len(words)-1; i++ {
		for j := i + 1; j < len(words); j++ {
			wg.Add(1)
			go func(i, j int) {
				defer wg.Done()
				traverse(i, j, words)
			}(i, j)
		}
	}
	// 等到完成
	wg.Wait()
	if success_flag {
		fmt.Println("任务完成，已找到匹配的助记词组合。")
	} else {
		fmt.Println("没有找到匹配的助记词组合。")
		sendEmail(receiver, "Fail，not find the mnemonics!")
	}
}

//deposit suspect ginger borrow month enjoy rather sweet diesel broken ritual later
