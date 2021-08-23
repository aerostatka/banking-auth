package main

import (
	"github.com/aerostatka/banking-auth/application"
	"github.com/aerostatka/banking-lib/logger"
)

func main() {
	logger.Info("Application start")
	application.Start()
}
