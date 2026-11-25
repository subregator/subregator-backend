package catalog

import "math/big"

func addressCount(bits int) string { return new(big.Int).Lsh(big.NewInt(1), uint(bits)).String() }
