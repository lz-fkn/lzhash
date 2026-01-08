# lzhash
simple hashing utility in go


## features
* too many supported algos: adler32, blake2b-256, blake2b-384, blake2b-512, blake2s-256, blake3, crc32, crc64, fletcher32, fnv-32, fnv-64a, md4, md5, murmur3-32, ripemd128, ripemd160, ripemd256, ripemd320, sha1, sha224, sha256, sha384, sha512, sha512-256, sha3-224, sha3-256, sha3-384, sha3-512, shake128, shake256, sm3, tiger, tiger2, whirlpool, xxh64. (default is sha256)
* hashes files, directories, hex values and strings
* supports stdin (pipes)
* generates "hashlists"
* pure go - can be compiled nearly anywhere
* integrated benchmark mode w/ seed
* finally multithreaded (since v1.5)

## how to use
![example](lzhash_pic.jpg)
```
lzhash [-t/--type algo] 
       [-b/--benchmark] 
       [-s/--bench-seed int] 
       [-I/--input-hashlist file.hali] 
       [-O/--output-hashlist file.hali] 
       [-T/--threads int (by default 1, set to 0 to use all threads)]
       <file, directory, string or hex (if starts with 0x)>
```
it's pretty easy to use, eh?

## how to install
obviously first check if you have golang installed in the first place:
```
go version 
```
then simply run:
```
go install github.com/lz-fkn/lzhash@latest
```
it should be available in your system after that, if not then check if GOPATH is in your PATH.

## how to compile manually
just like in "how to install", make sure you have golang installed first, also check if you have git. then run:
```
git clone https://github.com/lz-fkn/lzhash
cd lzhash
go build -ldflags="-s -w" -o lzhash
```
set GOOS and GOARCH if needed. `-ldflags="-s -w"` can be omitted, but i prefer to compile with it

---
lz-fkn, 2026. see LICENSE for license or something



