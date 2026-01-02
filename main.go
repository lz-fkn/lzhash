package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"flag"
	"fmt"
	"sort"
	"hash"
	"hash/crc32"
	"hash/crc64"
	"hash/adler32"
	"hash/fnv"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zeebo/blake3"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/ripemd160"
	"github.com/spaolacci/murmur3"
	"github.com/cespare/xxhash/v2"
	"golang.org/x/crypto/sha3"
	"github.com/gnabgib/gnablib-go/checksum/fletcher"
	"github.com/tjfoc/gmsm/sm3"
	"github.com/dchest/siphash"
)

func MustNewHash(h hash.Hash, err error) hash.Hash {
	if err != nil {
		panic(fmt.Sprintf("failed to initialize hash function: %v", err))
	}
	return h
}

var supportedAlgos = map[string]func() hash.Hash{
	"adler32":      func() hash.Hash { return adler32.New() },
	"blake2b-256":  func() hash.Hash { return MustNewHash(blake2b.New256(nil)) },
	"blake2b-384":  func() hash.Hash { return MustNewHash(blake2b.New384(nil)) },
	"blake2b-512":  func() hash.Hash { return MustNewHash(blake2b.New512(nil)) },
	"blake2s-256":	func() hash.Hash { return MustNewHash(blake2s.New256(nil)) }, // renamed from "blake2s" so it's easier to understand what this is
 	"blake3":       func() hash.Hash { return blake3.New() },
	"crc32":        func() hash.Hash { return crc32.NewIEEE() },
	"crc64": 		func() hash.Hash { return crc64.New(crc64.MakeTable(crc64.ECMA)) },
	"fletcher32":   func() hash.Hash { return fletcher.New32() },
	"fnv-32":       func() hash.Hash { return fnv.New32() },
	"fnv-64a":      func() hash.Hash { return fnv.New64a() },
	"md4":          func() hash.Hash { return md4.New() },
	"md5":          func() hash.Hash { return md5.New() },
	"murmur3-32":   func() hash.Hash { return murmur3.New32() },
	"ripemd160":    func() hash.Hash { return ripemd160.New() },
	"sha1":         func() hash.Hash { return sha1.New() },
	"sha224": 		func() hash.Hash { return sha256.New224() },
	"sha256":       func() hash.Hash { return sha256.New() },
	"sha384":       func() hash.Hash { return sha512.New384() },
	"sha512":       func() hash.Hash { return sha512.New() },
	"sha512-256":   func() hash.Hash { return sha512.New512_256() },
	"sha3-224": 	func() hash.Hash { return sha3.New224() },
	"sha3-256":     func() hash.Hash { return sha3.New256() },
	"sha3-384": 	func() hash.Hash { return sha3.New384() },
	"sha3-512": 	func() hash.Hash { return sha3.New512() },
	"shake128": 	func() hash.Hash { return sha3.NewShake128() },
	"shake256": 	func() hash.Hash { return sha3.NewShake256() },
	"siphash": 		func() hash.Hash { return siphash.New(make([]byte, 16)) },
	"sm3": 			func() hash.Hash { return sm3.New() },
	"xxh64":        func() hash.Hash { return xxhash.New() },
}

var selectedHash func() hash.Hash
var selectedAlgoName string
var benchmark bool
var benchSeed int64

func init() {
	flag.StringVar(&selectedAlgoName, "t", "sha256",
		"Specify the hash algorithm")
	flag.StringVar(&selectedAlgoName, "type", "sha256",
		"Alias for -t")

	flag.BoolVar(&benchmark, "b", false, "Run benchmark mode (hash all algorithms)")
	flag.BoolVar(&benchmark, "benchmark", false, "Alias for -b")
	flag.Int64Var(&benchSeed, "s", 42, "Benchmark RNG seed (only valid with -b)")
	flag.Int64Var(&benchSeed, "bench-seed", 42, "Alias for -s")

	flag.Parse()

	if benchSeed != 42 && !benchmark {
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
    const dataSize = 1024 * 1024
    const iterations = 1024
	const preview = 8

    rng := rand.New(rand.NewSource(benchSeed))
	data := make([]byte, dataSize)
	rng.Read(data)

	fmt.Printf(
		"Using %x...%x as input data (seed: %d)\n",
		data[:preview],
		data[len(data)-preview:],
		benchSeed,
	)

    fmt.Println("Benchmarking all algorithms (1MB, 1024 iterations):")
    fmt.Println("=================================================")

    keys := make([]string, 0, len(supportedAlgos))
    for name := range supportedAlgos {
        keys = append(keys, name)
    }
    sort.Strings(keys)

    for _, name := range keys {
		factory := supportedAlgos[name]
		h := factory()

		var sum []byte

		start := time.Now()
		for i := 0; i < iterations; i++ {
			h.Reset()
			h.Write(data)
			sum = h.Sum(nil)
		}

		total := time.Since(start)
		avg := total / iterations

		seconds := avg.Seconds()
		mbPerSec := (float64(dataSize) / (1024 * 1024)) / seconds

		var speedStr string
		if mbPerSec >= 1024 {
			speedStr = fmt.Sprintf("%.2f GB/s", mbPerSec/1024)
		} else {
			speedStr = fmt.Sprintf("%.2f MB/s", mbPerSec)
		}

		fmt.Printf(
			"%-15s avg/iter = %-10v (%-11s), result hash = %x\n",
			name,
			avg,
			speedStr,
			sum,
		)
	}

    fmt.Println("=================================================")
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
	return filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() || !info.Mode().IsRegular() {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Skipping file %s (error opening: %v)\n", path, err)
			return nil
		}
		defer file.Close()

		hasher := selectedHash()
		if _, err := io.Copy(hasher, file); err != nil {
			return fmt.Errorf("failed to hash file %s: %w", path, err)
		}

		fmt.Printf("%s %s: %x\n", path, selectedAlgoName, hasher.Sum(nil))
		return nil
	})
}

func main() {
	fmt.Println("lzHash v1.3, by Elzzie. BSD 2-Clause License\n")
	if benchmark {
		benchAll()
		return
	}

	args := flag.Args()

	if len(args) == 0 {
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
		hasher := selectedHash()
		hasher.Write([]byte(input))
		hashResult := hasher.Sum(nil)
		fmt.Printf("'%s' %s: %x\n", input, selectedAlgoName, hashResult)
	} else {
		err = fmt.Errorf("could not check input %s: %w", input, statErr)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

