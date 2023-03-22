package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"os"
	"strings"
)

type Content struct {
	contentID    []byte
	contentIndex []byte
	contentType  uint16
}

func readInt(f *os.File, s int) uint32 {
	var num uint32
	binary.Read(f, binary.BigEndian, &num)
	return num
}

func readString(f *os.File) string {
	buf := []byte{}
	for {
		char := make([]byte, 1)
		f.Read(char)
		if char[0] == byte(0) || len(char) == 0 {
			return string(buf)
		}
		buf = append(buf, char[0])
	}
}

func fileChunkOffset(offset uint32) uint32 {
	chunks := uint32(math.Floor(float64(offset / 0xFC00)))
	singleChunkOffset := offset % 0xFC00
	actualOffset := singleChunkOffset + ((chunks + 1) * 0x400) + (chunks * 0xFC00)
	return actualOffset
}

func inSlice(s string, str []string) bool {
	for _, v := range s {
		if string(v) == strings.Join(str, "") {
			return true
		}
	}

	return false
}

func ifThenElse(condition bool, ret1 string, ret2 string) string {
	if condition {
		return ret1
	} else {
		return ret2
	}
}

func iterateDirectory(f *os.File, iterStart uint32, count uint32, namesOffset int64, depth uint32, topdir int32, contentRecords []Content, canExtract bool, tree []string) uint32 {
	i := iterStart
	for i < count {
		entryOffset, _ := f.Seek(0, os.SEEK_CUR)
		fType := make([]byte, 1)
		f.Read(fType)
		isDir := fType[0] & 1 & 1

		nameOffset := int64(readInt(f, 3)) + namesOffset
		origOffset, _ := f.Seek(0, os.SEEK_CUR)
		f.Seek(int64(nameOffset), os.SEEK_SET)
		fName := readString(f)
		f.Seek(origOffset, os.SEEK_SET)

		fOffset := readInt(f, 4)
		fSize := readInt(f, 4)
		fFlags := readInt(f, 2)
		if fFlags&4 != 4 {
			fOffset <<= 5
		}

		contentIndex := readInt(f, 2)

		// this should be based on fFlags, but I'm not sure if there is a reliable way to determine this yet.
		hasHashTree := contentRecords[contentIndex].contentType & 2
		fRealOffset := fileChunkOffset(fOffset)
		if hasHashTree == 0 {
			fRealOffset = fOffset
		}

		toPrint := ""
		if inSlice("--dump-info", os.Args) {
			toPrint += fmt.Sprintf("%05d entryO=%08X type=%02X flags=%03X O=%010X realO=%010X size=%08X cidx=%04X cid=%s ", i, entryOffset, fType[0], fFlags, fOffset, fRealOffset, fSize, contentIndex, contentRecords[contentIndex].contentID)
		}
		if inSlice("--full-paths", os.Args) {
			toPrint += fmt.Sprintf("%s%s", strings.Join(tree, ""), fName)
		} else {
			toPrint += fmt.Sprintf("%s%s%s", strings.Repeat("  ", int(depth)), ifThenElse(isDir != 0, "* ", "- "), fName)
		}
		if (fType[0]&0x80 == 0) || inSlice("--all", os.Args) {
			fmt.Println(toPrint, ifThenElse(fType[0]&0x80 == 0x80, " (deleted)", ""))
		}

		if isDir != 0 {
			if int32(fOffset) <= topdir {
				return i
			}
			tree = append(tree, ifThenElse(depth == 0, "", "/")+fName)
		}
		if isDir != 0 {
			if int32(fOffset) <= topdir {
				return i
			}
			tree = append(tree, ifThenElse(depth == 0, "", "/")+fName)
			if inSlice("--extract", os.Args) && canExtract {
				dirPath := strings.Join(tree, "/")
				if _, err := os.Stat(dirPath); os.IsNotExist(err) {
					os.MkdirAll(dirPath, 0755)
				}
			}
			i = iterateDirectory(f, i+1, count, namesOffset, depth+1, int32(fOffset), contentRecords, canExtract, tree)
			tree = tree[:len(tree)-1]
		} else {
			if inSlice("--extract", os.Args) && canExtract {
				filePath := strings.Join(tree, "/")
				if _, err := os.Stat(filePath); os.IsNotExist(err) {
					content := make([]byte, fSize)
					f.Seek(int64(fRealOffset), os.SEEK_SET)
					f.Read(content)
					err := ioutil.WriteFile(filePath, content, 0644)
					if err != nil {
						fmt.Printf("Error extracting %s: %v\n", filePath, err)
					}
				}
			}
		}
		i++
	}
	return i
}

func main() {
	var contentCount uint16
	tmd, err := os.Open("title.tmd")
	if err != nil {
		fmt.Println("Failed to open TMD:", err)
		os.Exit(1)
	}
	defer tmd.Close()

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
	}
	fstHeaderFilename := hex.EncodeToString(contents[0].contentID) + ".app.dec"
	fmt.Printf("FST header file: %s\n", fstHeaderFilename)
	if _, err := os.Stat(fstHeaderFilename); os.IsNotExist(err) {
		fmt.Println("No FST header file was found.")
	}
	canExtract := true
	for _, content := range contents[:1] {
		if _, err := os.Stat(hex.EncodeToString(content.contentID) + ".app.dec"); os.IsNotExist(err) {
			fmt.Println("No decrypted file was found.")
			canExtract = false
		}
	}
	fst, err := os.Open(fstHeaderFilename)
	if err != nil {
		fmt.Println("Failed to open FST Header file:", err)
		os.Exit(1)
	}
	defer fst.Close()

	fst.Seek(4, os.SEEK_SET)
	exhSize := readInt(fst, 4)
	exhCount := readInt(fst, 4)

	fmt.Printf("unknown: 0x%x\n", exhSize)
	fmt.Printf("exheader count: %v\n", exhCount)

	fst.Seek(0x14, os.SEEK_CUR)
	for i := uint16(0); i < uint16(exhCount); i++ {
		fmt.Printf("#%v (%x)\n", i, i)
		var discOffset = make([]byte, 4)
		fst.Read(discOffset)
		fmt.Printf("- DiscOffset?: 0x%s\n", hex.EncodeToString(discOffset))
		var unknown2 = make([]byte, 4)
		fst.Read(unknown2)
		fmt.Printf("- Unknown2:    0x%s\n", hex.EncodeToString(unknown2))
		var titleID = make([]byte, 8)
		fst.Read(titleID)
		fmt.Printf("- TitleID:     0x%s\n", hex.EncodeToString(titleID))
		var groupID = make([]byte, 4)
		fst.Read(groupID)
		fmt.Printf("- GroupID:     0x%s\n", hex.EncodeToString(groupID))
		var flags = make([]byte, 2)
		fst.Read(flags)
		fmt.Printf("- Flags?:      0x%s\n", hex.EncodeToString(flags))
		fmt.Printf("")
		fst.Seek(10, os.SEEK_CUR)
	}
	fileEntriesOffset, _ := fst.Seek(0, os.SEEK_CUR)
	fst.Seek(8, os.SEEK_CUR)
	totalEntries := readInt(fst, 4)
	fst.Seek(4, os.SEEK_CUR)
	namesOffset := fileEntriesOffset + int64(totalEntries*0x10)

	var tree []string
	iterateDirectory(fst, 1, totalEntries, namesOffset, 0, -1, contents, canExtract, tree)
}
