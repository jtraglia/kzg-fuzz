module fuzz

go 1.19

require (
	github.com/holiman/uint256 v1.2.1
	github.com/jtraglia/cgo-kzg-4844 v0.0.0-20230113032000-8f40fcfccc5b
	github.com/protolambda/go-kzg v0.0.0-20221224134646-c91cee5e954e
	github.com/trailofbits/go-fuzz-utils v0.0.0-20210901195358-9657fcfd256c
)

require (
	github.com/herumi/bls-eth-go-binary v1.28.1 // indirect
	github.com/jtraglia/blst v0.3.9-0.20230106202936-888ac24c1bda // indirect
	github.com/kilic/bls12-381 v0.1.1-0.20220929213557-ca162e8a70f4 // indirect
	golang.org/x/sys v0.4.0 // indirect
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stretchr/testify v1.8.1
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/jtraglia/cgo-kzg-4844 => ../cgo-kzg-4844
