package main

import (
	"go.uber.org/zap"
)

var logger *zap.Logger

func main() {
	defer logger.Sync()
}
