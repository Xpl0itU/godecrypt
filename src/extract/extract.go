package extract

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"os"
	"strings"

	"github.com/vardius/progress-go"
)

type Content struct {
	contentID    []byte
	contentIndex []byte
	contentType  uint16
}

var bar *progress.Bar

func readInt(f io.ReadSeeker, s int) uint32 {
	bufSize := 4 // Buffer size is always 4 for uint32
	buf := make([]byte, bufSize)

	n, err := f.Read(buf[:s])
	if err != nil {
		panic(err)
	}

	if n < s {
		// If we didn't read the expected number of bytes, seek back to the
		// previous position in the file and return an error.
		if _, err := f.Seek(int64(-n), os.SEEK_CUR); err != nil {
			panic(err)
		}
		panic(io.ErrUnexpectedEOF)
	}

	return binary.BigEndian.Uint32(buf)
}

func readInt16(f io.ReadSeeker, s int) uint16 {
	bufSize := 2 // Buffer size is always 2 for uint16
	buf := make([]byte, bufSize)

	n, err := f.Read(buf[:s])
	if err != nil {
		panic(err)
	}

	if n < s {
		// If we didn't read the expected number of bytes, seek back to the
		// previous position in the file and return an error.
		if _, err := f.Seek(int64(-n), os.SEEK_CUR); err != nil {
			panic(err)
		}
		panic(io.ErrUnexpectedEOF)
	}

	return binary.BigEndian.Uint16(buf)
}

func read3BytesBE(f io.ReadSeeker) int {
	b := make([]byte, 3)
	f.Read(b)
	return int(uint(b[2]) | uint(b[1])<<8 | uint(b[0])<<16)
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

func inSlice(s string, slice []string) bool {
	for _, v := range slice {
		if v == s {
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func iterateDirectory(f *os.File, iterStart uint32, count uint32, namesOffset int64, depth uint32, topdir int32, contentRecords []Content, canExtract bool, tree []string) uint32 {
	i := iterStart
	for i < count {
		entryOffset, _ := f.Seek(0, os.SEEK_CUR)
		fType := make([]byte, 1)
		f.Read(fType)
		isDir := fType[0] & 1

		nameOffset := int64(read3BytesBE(f)) + namesOffset

		origOffset, _ := f.Seek(0, os.SEEK_CUR)
		f.Seek(int64(nameOffset), os.SEEK_SET)
		fName := readString(f)
		f.Seek(origOffset, os.SEEK_SET)

		fOffset := readInt(f, 4)
		fSize := readInt(f, 4)
		fFlags := readInt16(f, 2)
		if fFlags&4 == 0 {
			fOffset <<= 5
		}

		contentIndex := readInt16(f, 2)

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
			bar.Advance(1)
		}

		if isDir != 0 {
			if int32(fOffset) <= topdir {
				return i
			}
			tree = append(tree, fName+"/")
			if canExtract && !inSlice("--no-extract", os.Args) {
				os.MkdirAll(strings.Join(tree, ""), 0755)
			}
			iterateDirectory(f, i+1, fSize, namesOffset, depth+1, int32(fOffset), contentRecords, canExtract, tree)
			tree = tree[:len(tree)-1]
			i = fSize - 1
		} else if canExtract {
			withC, err := os.Open(hex.EncodeToString(contentRecords[contentIndex].contentID) + ".app.dec")
			if err != nil {
				panic(err)
			}
			defer withC.Close()
			withO, err := os.Create(strings.Join(tree, "") + fName)
			if err != nil {
				panic(err)
			}
			defer withO.Close()

			_, err = withC.Seek(int64(fRealOffset), 0)
			if err != nil {
				panic(err)
			}

			buf := []byte{}
			left := fSize

			for left > 0 {
				toRead := min(0x20, int(left))
				readBuf := make([]byte, toRead)
				_, err = withC.Read(readBuf)
				if err != nil && err != io.EOF {
					panic(err)
				}
				buf = append(buf, readBuf...)
				left -= uint32(toRead)

				if len(buf) >= 0x200 {
					_, err = withO.Write(buf)
					if err != nil {
						panic(err)
					}
					buf = []byte{}
				}

				withCOffset, _ := withC.Seek(0, os.SEEK_CUR)

				if hasHashTree != 0 && withCOffset%0x10000 < 0x400 {
					_, err = withC.Seek(0x400, 1)
					if err != nil {
						panic(err)
					}
				}
			}

			if len(buf) > 0 {
				_, err = withO.Write(buf)
				if err != nil {
					panic(err)
				}
			}
		}
		i++
	}
	return i
}

func Extract() {
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

	bar = progress.New(0, int64(totalEntries), progress.Options{
		Verbose: true,
	})

	_, _ = bar.Start()
	defer func() {
		if _, err := bar.Stop(); err != nil {
			fmt.Printf("failed to finish progress: %v\n", err)
		}
	}()

	var tree []string
	iterateDirectory(fst, 1, totalEntries, namesOffset, 0, -1, contents, canExtract, tree)
}
