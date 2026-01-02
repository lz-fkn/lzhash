# lzhash
simple hashing utility in go


## features
* many supported algos: adler32, blake2b-256, blake2b-384, blake2b-512, blake2s-256, blake3, crc32, crc64, fletcher32, fnv-32, fnv-64a, md4, md5, murmur3-32, ripemd160, sha1, sha224, sha256, sha384, sha512, sha512-256, sha3-224, sha3-256, sha3-384, sha3-512, shake128, shake256, siphash, sm3, xxh64.
* can hash files, directories and strings
* pure go, thus can be compiled nearly anywhere
* integrated benchmark mode w/ seed

## how to use
![example](lzhash_pic.jpg)
`lzhash [-t/--type algo] [-b/--benchmark] [-s/--bench-seed] <file, directory or string>`<br>
it's pretty easy to use, eh?

## how to compile
simply run
```
go mod init github.com/lz-fkn/lzhash
go mod tidy
go build -ldflags="-s -w" -o lzhash
```

---
lz-fkn, 2026. see LICENSE for license or something
