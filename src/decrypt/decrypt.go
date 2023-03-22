package decrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"os"
)

type Content struct {
	contentID    []byte
	contentIndex []byte
	contentType  uint16
	contentSize  uint64
	contentHash  []byte
}

var wiiuCommonKey = "d7b00402659ba2abd2cb0db27fa2b656"

func Equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func Decrypt() {
	// Hash the common key and check if it matches the expected value
	wiiuCommonKeyHash := sha1.Sum([]byte(wiiuCommonKey))
	if hex.EncodeToString(wiiuCommonKeyHash[:]) != "abc0a5faf6181a137a7f8cc9950e451250878e8f" {
		fmt.Println("Wrong Wii U Common Key. Place the correct one in the script.")
		os.Exit(1)
	}

	ckey, err := hex.DecodeString(wiiuCommonKey)
	if err != nil {
		fmt.Println("Invalid common key")
		os.Exit(1)
	}

	readSize := 8 * 1024 * 1024

	if _, err := os.Stat("title.tmd"); os.IsNotExist(err) {
		fmt.Println("No TMD (title.tmd) was found.")
		os.Exit(1)
	}

	// find title id and content id
	var titleID []byte
	var contentCount uint16
	tmd, err := os.Open("title.tmd")
	if err != nil {
		fmt.Println("Failed to open TMD:", err)
		os.Exit(1)
	}
	defer tmd.Close()

	tmd.Seek(0x18C, io.SeekStart)
	titleID = make([]byte, 8)
	if _, err := io.ReadFull(tmd, titleID); err != nil {
		fmt.Println("Failed to read title ID:", err)
		os.Exit(1)
	}

	tmd.Seek(0x1DE, io.SeekStart)
	if err := binary.Read(tmd, binary.BigEndian, &contentCount); err != nil {
		fmt.Println("Failed to read content count:", err)
		os.Exit(1)
	}

	tmd.Seek(0x204, io.SeekStart)
	tmdIndex := make([]byte, 2)
	if _, err := io.ReadFull(tmd, tmdIndex); err != nil {
		fmt.Println("Failed to read TMD index:", err)
		os.Exit(1)
	}

	contents := make([]Content, contentCount)

	for c := uint16(0); c < contentCount; c++ {
		tmd.Seek(0xB04+(0x30*int64(c)), io.SeekStart)
		contents[c].contentID = make([]byte, 4)
		if _, err := io.ReadFull(tmd, contents[c].contentID); err != nil {
			fmt.Println("Failed to read content ID:", err)
			os.Exit(1)
		}

		tmd.Seek(0xB08+(0x30*int64(c)), io.SeekStart)
		contents[c].contentIndex = make([]byte, 2)
		if _, err := io.ReadFull(tmd, contents[c].contentIndex); err != nil {
			fmt.Println("Failed to read content index:", err)
			os.Exit(1)
		}

		tmd.Seek(0xB0A+(0x30*int64(c)), io.SeekStart)
		if err := binary.Read(tmd, binary.BigEndian, &contents[c].contentType); err != nil {
			fmt.Println("Failed to read content type:", err)
		}

		tmd.Seek(0xB0C+(0x30*int64(c)), io.SeekStart)
		if err := binary.Read(tmd, binary.BigEndian, &contents[c].contentSize); err != nil {
			fmt.Println("Failed to read content size:", err)
		}

		tmd.Seek(0xB14+(0x30*int64(c)), io.SeekStart)
		contents[c].contentHash = make([]byte, 0x14)
		if _, err := io.ReadFull(tmd, contents[c].contentHash); err != nil {
			fmt.Println("Failed to read content hash:", err)
			os.Exit(1)
		}
	}
	fmt.Printf("Title ID: %s\n", hex.EncodeToString(titleID))

	// Find the encrypted titlekey
	var encryptedTitleKey []byte

	if _, err := os.Stat("title.tik"); err == nil {
		cetk, err := os.Open("title.tik")
		if err == nil {
			cetk.Seek(0x1BF, 0)
			encryptedTitleKey = make([]byte, 0x10)
			cetk.Read(encryptedTitleKey)
			cetk.Close()
		}
	}
	fmt.Printf("Encrypted Titlekey: %s\n", hex.EncodeToString(encryptedTitleKey))
	c, err := aes.NewCipher(ckey)
	if err != nil {
		panic(err)
	}

	blockSize := c.BlockSize()
	iv := make([]byte, blockSize)
	copy(iv, titleID)
	mode := cipher.NewCBCDecrypter(c, iv)

	decryptedTitleKey := make([]byte, len(encryptedTitleKey))
	mode.CryptBlocks(decryptedTitleKey, encryptedTitleKey)

	fmt.Printf("Decrypted Titlekey: %x\n", decryptedTitleKey)
	for _, c := range contents {
		fmt.Printf("Decrypting %v...\n", hex.EncodeToString(c.contentID))

		left, err := os.Stat(hex.EncodeToString(c.contentID) + ".app")
		if err != nil {
			panic(err)
		}
		leftSize := left.Size()

		//leftHash := c.contentHash

		if c.contentType&2 != 0 { // if has a hash tree
			chunkCount := leftSize / 0x10000
			//chunkNum := int64(0)
			h3Bytes, err := ioutil.ReadFile(hex.EncodeToString(c.contentID) + ".h3")
			if err != nil {
				panic(err)
			}
			h3BytesSHASum := sha1.Sum(h3Bytes)
			if hex.EncodeToString(h3BytesSHASum[:]) != hex.EncodeToString(c.contentHash) {
				fmt.Println("H3 Hash mismatch!")
				fmt.Println(" > TMD:    " + hex.EncodeToString(c.contentHash))
				fmt.Println(" > Result: " + hex.EncodeToString(h3BytesSHASum[:]))
			}

			h0HashNum := int64(0)
			h1HashNum := int64(0)
			h2HashNum := int64(0)
			h3HashNum := int64(0)

			encryptedFile, err := os.Open(hex.EncodeToString(c.contentID) + ".app")
			if err != nil {
				panic(err)
			}
			defer encryptedFile.Close()

			decryptedFile, err := os.Create(hex.EncodeToString(c.contentID) + ".app.dec")
			if err != nil {
				panic(err)
			}
			defer decryptedFile.Close()

			for chunkNum := 0; int64(chunkNum) < chunkCount; chunkNum++ {
				// decrypt and verify hash tree
				cipherHashTree, err := aes.NewCipher(decryptedTitleKey)
				if err != nil {
					fmt.Println(err)
					return
				}

				hashTree := make([]byte, 0x400)
				_, err = io.ReadFull(encryptedFile, hashTree)
				if err != nil {
					fmt.Println(err)
					return
				}

				cipherHashTree.Decrypt(hashTree, hashTree)

				h0Hashes := hashTree[0:0x140]
				/*h1Hashes := hashTree[0x140:0x280]
				h2Hashes := hashTree[0x280:0x3c0]*/

				h0Hash := h0Hashes[(h0HashNum * 0x14):((h0HashNum + 1) * 0x14)]
				/*h1Hash := h1Hashes[(h1HashNum * 0x14):((h1HashNum + 1) * 0x14)]
				  h2Hash := h2Hashes[(h2HashNum * 0x14):((h2HashNum + 1) * 0x14)]
				  h3Hash := h3Bytes[(h3HashNum * 0x14):((h3HashNum + 1) * 0x14)]*/

				/*h0HashesHash := sha1.Sum(h0Hashes)
				if !Equal(h0HashesHash[:], h1Hash) {
					fmt.Printf("\rH0 Hashes invalid in chunk %v\n", chunkNum)
				}
				h1HashesHash := sha1.Sum(h1Hashes)
				if !Equal(h1HashesHash[:], h2Hash) {
					fmt.Printf("\rH1 Hashes invalid in chunk %v\n", chunkNum)
				}
				h2HashesHash := sha1.Sum(h2Hashes)
				if !Equal(h2HashesHash[:], h3Hash) {
					fmt.Printf("\rH2 Hashes invalid in chunk %v\n", chunkNum)
				}*/
				iv := h0Hash[0:0x10]
				cipherContent, err := aes.NewCipher(decryptedTitleKey)
				if err != nil {
					fmt.Println(err)
					return
				}

				decryptedData := make([]byte, 0xFC00)
				_, err = io.ReadFull(encryptedFile, decryptedData)
				if err != nil {
					fmt.Println(err)
					return
				}

				cbc := cipher.NewCBCDecrypter(cipherContent, iv)
				cbc.CryptBlocks(decryptedData, decryptedData)

				/*decryptedDataHash := sha1.Sum(decryptedData)
				if !Equal(decryptedDataHash[:], h0Hash) {
					fmt.Printf("\rData block hash invalid in chunk %v\n", chunkNum)
				}*/
				decryptedFile.Write(hashTree)
				decryptedFile.Write(decryptedData)
				h0HashNum += 1
				if h0HashNum >= 16 {
					h0HashNum = 0
					h1HashNum += 1
				}
				if h1HashNum >= 16 {
					h1HashNum = 0
					h2HashNum += 1
				}
				if h2HashNum >= 16 {
					h2HashNum = 0
					h3HashNum += 1
				}
			}
		} else {
			cipherHashTree, err := aes.NewCipher(decryptedTitleKey)
			if err != nil {
				fmt.Println(err)
				return
			}
			cipherContent := cipher.NewCBCDecrypter(cipherHashTree, append(c.contentIndex, make([]byte, 14)...))
			contentHash := sha1.New()
			left := c.contentSize
			leftHash := c.contentSize

			encrypted, err := os.Open(hex.EncodeToString(c.contentID) + ".app")
			if err != nil {
				panic(err)
			}
			defer encrypted.Close()

			decrypted, err := os.Create(hex.EncodeToString(c.contentID) + ".app.dec")
			if err != nil {
				panic(err)
			}
			defer decrypted.Close()

			for i := 0; i <= int(math.Floor(float64(int64(c.contentSize)/int64(readSize)))+1); i++ {
				toRead := int64(math.Min(float64(readSize), float64(left)))
				toReadHash := int64(math.Min(float64(readSize), float64(leftHash)))

				encryptedContent := make([]byte, toRead)
				_, err = io.ReadFull(encrypted, encryptedContent)
				if err != nil {
					panic(err)
				}

				decryptedContent := make([]byte, len(encryptedContent))
				cipherContent.CryptBlocks(decryptedContent, encryptedContent)
				contentHash.Write(decryptedContent[:toReadHash])
				_, err = decrypted.Write(decryptedContent)
				if err != nil {
					panic(err)
				}

				left -= uint64(toRead)
				leftHash -= uint64(toRead)

				if leftHash < 0 {
					leftHash = 0
				}
				if left <= 0 {
					break
				}
			}
			if !Equal(c.contentHash, contentHash.Sum(nil)) {
				print("Content Hash mismatch!")
			}
		}
	}
}
