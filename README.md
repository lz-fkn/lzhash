# lzhash
simple hashing utility in go


## features
* many supported algos: adler32, blake2b-256, blake2b-384, blake2b-512, blake2s, blake3, crc32, fletcher32, fnv-32, fnv-64a, md4, md5, murmur3-32, ripemd160, sha1, sha256, sha3-256, sha384, sha512, xxh64.
* can hash files, directories and strings
* pure go, thus can be compiled nearly anywhere
* integrated benchmark

## how to use
`lzhash [-t/--type algo] [-b/--benchmark] <file, directory or string>`<br>
it's pretty easy to use, eh?

## how to compile
simply run
```
go mod init github.com/lz-fkn/lzhash
go mod tidy
go build -ldflags="-s -w" -o lzhash
```

---
lz-fkn, 2025. see LICENSE for license or something
