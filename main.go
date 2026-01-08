package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"hash"
	"hash/adler32"
	"hash/crc32"
	"hash/crc64"
	"hash/fnv"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"runtime"
    "sync"

	"github.com/c0mm4nd/go-ripemd"
	"github.com/cespare/xxhash/v2"
	"github.com/cxmcc/tiger"
	"github.com/gnabgib/gnablib-go/checksum/fletcher"
	"github.com/jzelinskie/whirlpool"
	"github.com/spaolacci/murmur3"
	"github.com/tjfoc/gmsm/sm3"
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/sha3"
)

const lzHashVersion = "v1.5.1"

const defaultAlgo = "sha256" // should do as default

// benchmark options
const defaultSeed = 42
const dataSize = 1 * 1024 * 1024 // 1MB
const iterations = 1024
const preview = 8 // symbols on each side

const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorDarkRed = "\033[31;2m"
)

var threads int

// some algos (blake2 family) return an error, so it's here to make it easy
func MustNewHash(h hash.Hash, err error) hash.Hash {
	if err != nil {
		panic(fmt.Sprintf("failed to initialize hash function: %v", err))
	}
	return h
}

// not sure if it truly needs to be separated, or it can be moved to crc64.New(...), but whatever 
var ecmaTable = crc64.MakeTable(crc64.ECMA)

var supportedAlgos = map[string]func() hash.Hash{
	"adler32":     func() hash.Hash { return adler32.New() },
	"blake2b-256": func() hash.Hash { return MustNewHash(blake2b.New256(nil)) },
	"blake2b-384": func() hash.Hash { return MustNewHash(blake2b.New384(nil)) },
	"blake2b-512": func() hash.Hash { return MustNewHash(blake2b.New512(nil)) },
	"blake2s-256": func() hash.Hash { return MustNewHash(blake2s.New256(nil)) }, // renamed from "blake2s" so it's easier to understand what this is
	"blake3":      func() hash.Hash { return blake3.New() },
	"crc32":       func() hash.Hash { return crc32.NewIEEE() },
	"crc64":       func() hash.Hash { return crc64.New(ecmaTable) },
	"fletcher32":  func() hash.Hash { return fletcher.New32() },
	"fnv-32":      func() hash.Hash { return fnv.New32() },
	"fnv-64a":     func() hash.Hash { return fnv.New64a() },
	"md4":         func() hash.Hash { return md4.New() },
	"md5":         func() hash.Hash { return md5.New() },
	"murmur3-32":  func() hash.Hash { return murmur3.New32() },
	"ripemd128":   func() hash.Hash { return ripemd.New128() },
	"ripemd160":   func() hash.Hash { return ripemd.New160() },
	"ripemd256":   func() hash.Hash { return ripemd.New256() },
	"ripemd320":   func() hash.Hash { return ripemd.New320() },
	"sha1":        func() hash.Hash { return sha1.New() },
	"sha224":      func() hash.Hash { return sha256.New224() },
	"sha256":      func() hash.Hash { return sha256.New() },
	"sha384":      func() hash.Hash { return sha512.New384() },
	"sha512":      func() hash.Hash { return sha512.New() },
	"sha512-256":  func() hash.Hash { return sha512.New512_256() },
	"sha3-224":    func() hash.Hash { return sha3.New224() },
	"sha3-256":    func() hash.Hash { return sha3.New256() },
	"sha3-384":    func() hash.Hash { return sha3.New384() },
	"sha3-512":    func() hash.Hash { return sha3.New512() },
	"shake128":    func() hash.Hash { return sha3.NewShake128() },
	"shake256":    func() hash.Hash { return sha3.NewShake256() },
	"sm3":         func() hash.Hash { return sm3.New() },
	"tiger":       func() hash.Hash { return tiger.New() },
	"tiger2":      func() hash.Hash { return tiger.New2() },
	"whirlpool":   func() hash.Hash { return whirlpool.New() },
	"xxh64":       func() hash.Hash { return xxhash.New() },
	// you can add more algos if you want, as long as they use simple hash.Hash
}

var selectedHash func() hash.Hash
var selectedAlgoName string
var benchmark bool
var benchSeed int64
var outputHashlist string
var inputHashlist string

func init() {
	// ugly ugly thing
	flag.StringVar(&selectedAlgoName, "type", defaultAlgo, "Specify the hash algorithm")
	flag.StringVar(&selectedAlgoName, "t", defaultAlgo, "Alias for -type")

	flag.BoolVar(&benchmark, "benchmark", false, "Run benchmark mode (hash all algorithms)")
	flag.BoolVar(&benchmark, "b", false, "Alias for -benchmark")
	flag.Int64Var(&benchSeed, "bench-seed", defaultSeed, "Benchmark RNG seed (only valid with -b)")
	flag.Int64Var(&benchSeed, "s", defaultSeed, "Alias for -bench-seed")

	flag.StringVar(&outputHashlist, "output-hashlist", "", "Create a checksum file")
	flag.StringVar(&outputHashlist, "O", "", "Alias for -output-hashlist")
	flag.StringVar(&inputHashlist, "input-hashlist", "", "Verify files against a checksum file")
	flag.StringVar(&inputHashlist, "I", "", "Alias for -input-hashlist")

	flag.IntVar(&threads, "threads", 1, "Number of threads to use (default 1, set to 0 to use all threads)")
	flag.IntVar(&threads, "T", 1, "Alias for -threads")

	flag.Parse()

	numCPU := runtime.NumCPU()
	if threads == 0 {
		threads = numCPU
	} else if threads > numCPU {
		fmt.Fprintf(os.Stderr, "Error: requested %d threads, but only %d cores are available\n", threads, numCPU)
		os.Exit(1)
	}

	if benchmark {
		if len(flag.Args()) > 0 {
			fmt.Fprintln(os.Stderr, "Error: user cannot decide (cannot use file arguments with -b/--benchmark)")
			os.Exit(1)
		}
		isTypeSet := false
		flag.Visit(func(f *flag.Flag) {
			if f.Name == "t" || f.Name == "type" {
				isTypeSet = true
			}
		})
		if isTypeSet {
			fmt.Fprintln(os.Stderr, "Error: user cannot decide (cannot use -t/--type with -b/--benchmark)")
			os.Exit(1)
		}
	}

	if benchSeed != defaultSeed && !benchmark {
		fmt.Fprintln(os.Stderr, "Error: -s/--bench-seed can only be used together with -b/--benchmark")
		os.Exit(1)
	}

	if benchmark {
		return
	}

	factory, ok := supportedAlgos[strings.ToLower(selectedAlgoName)]
	if !ok {
		fmt.Fprintf(os.Stderr, "Error: Unsupported hash algorithm '%s'.\nSupported algos: %s\n",
			selectedAlgoName, getSupportedAlgosList())
		os.Exit(1)
	}
	selectedHash = factory
}

func getSupportedAlgosList() string {
	keys := make([]string, 0, len(supportedAlgos))
	for k := range supportedAlgos {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

func benchAll() {
	rng := rand.New(rand.NewSource(benchSeed))
	data := make([]byte, dataSize)
	rng.Read(data)

	fmt.Printf(
		"Using %x...%x as input data (seed: %d)\n",
		data[:preview],
		data[len(data)-preview:],
		benchSeed,
	)

	fmt.Printf("Benchmarking all algorithms (%d bytes, %d iterations, %d threads):\n", dataSize, iterations, threads)
	fmt.Println("======================================================")

	keys := make([]string, 0, len(supportedAlgos))
	for name := range supportedAlgos {
		keys = append(keys, name)
	}
	sort.Strings(keys)

	for _, name := range keys {
		factory := supportedAlgos[name]
		
		var wg sync.WaitGroup
		var sum []byte
		start := time.Now()

		for t := 0; t < threads; t++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				h := factory()
				for i := 0; i < iterations; i++ {
					h.Reset()
					h.Write(data)
					localSum := h.Sum(nil)
					if sum == nil {
						sum = localSum
					}
				}
			}()
		}
		wg.Wait()

		totalDuration := time.Since(start)
		
		totalIters := iterations * threads
		avgPerIter := totalDuration / time.Duration(totalIters)
		
		seconds := totalDuration.Seconds()
		totalMB := float64(dataSize*totalIters) / (1024 * 1024)
		mbPerSecTotal := totalMB / seconds
		mbPerSecThread := (float64(dataSize*iterations) / (1024 * 1024)) / (totalDuration.Seconds())

		formatSpeed := func(mbs float64) string {
			if mbs >= 1024 {
				return fmt.Sprintf("%.2f GB/s", mbs/1024)
			}
			return fmt.Sprintf("%.2f MB/s", mbs)
		}

		fmt.Printf(
			"%s\n"+
			"╟─ avg/iter = %v\n"+
			"╟─ throughput = %s\n"+
			"╟─ throughput/thread = %s\n"+
			"╙─ result hash = %x\n\n",
			name,
			avgPerIter,
			formatSpeed(mbPerSecTotal),
			formatSpeed(mbPerSecThread),
			sum,
		)
	}

	fmt.Println("======================================================")
}

func hashFile(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("could not open file %s: %w", filePath, err)
	}
	defer file.Close()

	hasher := selectedHash()
	if _, err := io.Copy(hasher, file); err != nil {
		return fmt.Errorf("could not hash file %s: %w", filePath, err)
	}

	fmt.Printf("%s %s: %x\n", filePath, selectedAlgoName, hasher.Sum(nil))
	return nil
}

func hashDirectory(dirPath string) error {
	type task struct {
		path string
	}
	
	tasks := make(chan task)
	var wg sync.WaitGroup

	for w := 0; w < threads; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range tasks {
				file, err := os.Open(t.path)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Warning: Skipping file %s (error opening: %v)\n", t.path, err)
					continue
				}
				
				hasher := selectedHash()
				if _, err := io.Copy(hasher, file); err != nil {
					fmt.Fprintf(os.Stderr, "Error hashing %s: %v\n", t.path, err)
					file.Close()
					continue
				}
				file.Close()
				fmt.Printf("%s %s: %x\n", t.path, selectedAlgoName, hasher.Sum(nil))
			}
		}()
	}

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && info.Mode().IsRegular() {
			tasks <- task{path: path}
		}
		return nil
	})

	close(tasks)
	wg.Wait()
	return err
}

func writeHashlist(inputPath string, outputPath string) error {
	info, err := os.Stat(inputPath)
	if err != nil {
		return err
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		return fmt.Errorf("input is a special file, only regular files and directories are supported for hashlists")
	}

	type hashResult struct {
		line    string
		relPath string
	}

	tasks := make(chan string)
	results := make(chan hashResult)
	var wg sync.WaitGroup

	for w := 0; w < threads; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range tasks {
				f, err := os.Open(path)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Warning: Skipping file %s (error opening: %v)\n", path, err)
					continue
				}

				h := selectedHash()
				if _, err := io.Copy(h, f); err != nil {
					fmt.Fprintf(os.Stderr, "Error hashing %s: %v\n", path, err)
					f.Close()
					continue
				}
				f.Close()

				hashSum := h.Sum(nil)
				relPath, err := filepath.Rel(inputPath, path)
				if err != nil || relPath == "." {
					relPath = filepath.Base(path)
				}
				relPath = filepath.ToSlash(relPath)

				fmt.Printf("%s %s: %x\n", relPath, selectedAlgoName, hashSum)

				results <- hashResult{
					line:    fmt.Sprintf("%x:%s\n", hashSum, relPath),
					relPath: relPath,
				}
			}
		}()
	}

	var finalEntries []hashResult
	collectorDone := make(chan struct{})
	go func() {
		for r := range results {
			finalEntries = append(finalEntries, r)
		}
		close(collectorDone)
	}()

	if info.IsDir() {
		err = filepath.Walk(inputPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() && info.Mode().IsRegular() {
				tasks <- path
			}
			return nil
		})
	} else {
		tasks <- inputPath
	}

	close(tasks)
	wg.Wait()
	close(results)
	<-collectorDone

	if err != nil {
		return err
	}

	sort.Slice(finalEntries, func(i, j int) bool {
		return finalEntries[i].relPath < finalEntries[j].relPath
	})

	outFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outFile.Close()

	header := fmt.Sprintf("#lzhash!ver:%s!algo:%s#\n", lzHashVersion, selectedAlgoName)
	if _, err := outFile.WriteString(header); err != nil {
		return err
	}

	for _, entry := range finalEntries {
		if _, err := outFile.WriteString(entry.line); err != nil {
			return err
		}
	}

	fmt.Printf("\nTotal: %d\n", len(finalEntries))
	return nil
}

func verifyHashlist(listPath string, targetDir string) error {
	file, err := os.Open(listPath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return errors.New("hashlist file is empty")
	}

	header := scanner.Text()
	if !strings.HasPrefix(header, "#lzhash!") || !strings.HasSuffix(header, "#") {
		return errors.New("invalid hashlist header format")
	}

	parts := strings.Split(header, "!")
	var algo string
	for _, p := range parts {
		if strings.HasPrefix(p, "algo:") {
			algo = strings.TrimPrefix(p, "algo:")
			algo = strings.TrimSuffix(algo, "#")
		}
	}

	if algo == "" {
		return errors.New("no algorithm specified in hashlist header")
	}

	fmt.Printf("Used algo: %s\n", algo)

	factory, ok := supportedAlgos[strings.ToLower(algo)]
	if !ok {
		return fmt.Errorf("unsupported hash algorithm in hashlist: %s", algo)
	}

	baseDir := targetDir
	if baseDir == "" {
		baseDir = filepath.Dir(listPath)
	}

	type result struct {
		relPath string
		status  string // "PASS", "FAIL", "MISSING", "ERROR"
		err     string
	}

	type lineTask struct {
		expectedHex string
		relPath     string
	}

	tasks := make(chan lineTask)
	results := make(chan result)
	var wg sync.WaitGroup

	for w := 0; w < threads; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range tasks {
				fullPath := filepath.Join(baseDir, t.relPath)
				info, err := os.Stat(fullPath)
				if err != nil {
					if errors.Is(err, os.ErrNotExist) {
						results <- result{relPath: t.relPath, status: "MISSING"}
					} else {
						results <- result{relPath: t.relPath, status: "ERROR"}
					}
					continue
				}

				if info.IsDir() {
					results <- result{relPath: t.relPath, status: "ERROR", err: "(is a directory)"}
					continue
				}

				f, err := os.Open(fullPath)
				if err != nil {
					results <- result{relPath: t.relPath, status: "ERROR"}
					continue
				}

				h := factory()
				_, copyErr := io.Copy(h, f)
				f.Close()

				if copyErr != nil {
					results <- result{relPath: t.relPath, status: "ERROR"}
					continue
				}

				actualHex := hex.EncodeToString(h.Sum(nil))
				if actualHex == t.expectedHex {
					results <- result{relPath: t.relPath, status: "PASS"}
				} else {
					results <- result{relPath: t.relPath, status: "FAIL"}
				}
			}
		}()
	}

	var total, passed, failed, missing, errored int
	
	collectorDone := make(chan struct{})

	go func() {
		for r := range results {
			total++
			switch r.status {
			case "PASS":
				fmt.Printf("%s: %sPASS%s\n", r.relPath, colorGreen, colorReset)
				passed++
			case "FAIL":
				fmt.Printf("%s: %sFAIL%s\n", r.relPath, colorRed, colorReset)
				failed++
			case "MISSING":
				fmt.Printf("%s: %sMISSING%s\n", r.relPath, colorYellow, colorReset)
				missing++
			case "ERROR":
				suffix := ""
				if r.err != "" {
					suffix = " " + r.err
				}
				fmt.Printf("%s: %sERROR%s%s\n", r.relPath, colorDarkRed, colorReset, suffix)
				errored++
			}
		}
		close(collectorDone)
	}()

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" { continue }
		idx := strings.Index(line, ":")
		if idx == -1 { continue }
		tasks <- lineTask{
			expectedHex: line[:idx],
			relPath:     filepath.FromSlash(line[idx+1:]),
		}
	}

	close(tasks)
	wg.Wait()
	close(results)

	<-collectorDone

	fmt.Printf("\nTotal: %d. Passed: %d. Failed: %d. Missing: %d. Error: %d.\n",
		total, passed, failed, missing, errored)

	return scanner.Err()
}

func main() {
	fmt.Printf("lzHash %s, by Elzzie. BSD 2-Clause License\n\n", lzHashVersion)
	if benchmark {
		benchAll()
		return
	}

	if inputHashlist != "" {
		targetDir := ""
		if len(flag.Args()) > 0 {
			targetDir = flag.Args()[0]
		}
		
		err := verifyHashlist(inputHashlist, targetDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	args := flag.Args()

	if len(args) == 0 {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			hasher := selectedHash()
			if _, err := io.Copy(hasher, os.Stdin); err != nil {
				fmt.Fprintf(os.Stderr, "Error reading from stdin: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("(stdin) %s: %x\n", selectedAlgoName, hasher.Sum(nil))
			return
		}

		flag.Usage()
		fmt.Println("\nSupported algorithms:")
		fmt.Println(getSupportedAlgosList())
		os.Exit(0)
	}

	if len(args) != 1 {
		flag.Usage()
		os.Exit(1)
	}
	input := args[0]

	if outputHashlist != "" {
		err := writeHashlist(input, outputHashlist)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating hashlist: %v\n", err)
			os.Exit(1)
		}
		return
	}

	var err error
	info, statErr := os.Stat(input)

	if statErr == nil {
		if info.IsDir() {
			err = hashDirectory(input)
		} else if info.Mode().IsRegular() {
			err = hashFile(input)
		} else {
			err = fmt.Errorf("input is a special file, only regular files and directories are supported: %s", input)
		}
	} else if errors.Is(statErr, os.ErrNotExist) {
		var data []byte
		displayLabel := ""

		if strings.HasPrefix(input, "0x") {
			data, err = hex.DecodeString(input[2:])
			if err != nil {
				err = fmt.Errorf("invalid hex input: %w", err)
			}
			displayLabel = "(hex) "
		} else {
			data = []byte(input)
		}

		if err == nil {
			hasher := selectedHash()
			hasher.Write(data)
			fmt.Printf("'%s' %s%s: %x\n", input, displayLabel, selectedAlgoName, hasher.Sum(nil))
		}
	} else {
		err = fmt.Errorf("could not check input %s: %w", input, statErr)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}