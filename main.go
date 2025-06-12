package main

import (
	"go-recon-ai-modular/internal/handlers"
	"go-recon-ai-modular/internal/services"
	"log"
	"os"

	"github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()

    r.GET("/", func(c *gin.Context) {
        c.File("./web/index.html")
    })

    r.POST("/analyse", services.AnalyzeServiceHandler)

    r.POST("/recon", handlers.ReconHandler)

    port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }
    log.Printf("Iniciando servidor na porta %s...", port)

    r.Run(":" + port)
}
