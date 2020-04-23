module github.com/gobbc/qa

go 1.13

require (
	github.com/dabankio/bbrpc v1.0.0-beta.8
	github.com/lomocoin/gobbc v0.0.0-00010101000000-000000000000
	github.com/stretchr/testify v1.5.1
	golang.org/x/sys v0.0.0-20190813064441-fde4db37ae7a // indirect
)

replace github.com/lomocoin/gobbc => ../

replace github.com/dabankio/bbrpc => /Users/sunxiansong/Documents/lomo/projects/bbrpc
