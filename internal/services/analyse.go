package services

import (
	"bytes"
	"encoding/json"
	"log"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

type ServiceData struct {
	Service string `json:"service"`
	Port    int    `json:"port"`
}


func AnalyzeWithN8N(hostData interface{}) map[string]interface{} {
	webhookURL := "https://n8n.srv794951.hstgr.cloud/webhook/5d00c979-3cbc-402c-8be6-6dd92036e6a6"

	payload, _ := json.Marshal(hostData)

	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		log.Printf("[ERROR] Falha ao enviar dados ao n8n: %v", err)
		return nil
	}
	defer resp.Body.Close()

	var resultArr []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&resultArr); err == nil && len(resultArr) > 0 {
		return resultArr[0]
	}

	var wrapper []struct {
		Output string `json:"output"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err == nil && len(wrapper) > 0 {
		clean := strings.TrimSpace(wrapper[0].Output)
		clean = strings.TrimPrefix(clean, "```json")
		clean = strings.TrimSuffix(clean, "```")
		clean = strings.TrimSpace(clean)

		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(clean), &parsed); err == nil {
			return parsed
		}
		log.Printf("[ERROR] Falha ao parsear JSON limpo da string: %v", err)
		log.Printf("[DEBUG] Conteúdo retornado (limpo): %s", clean)
	}

	log.Printf("[ERROR] Falha ao decodificar resposta do n8n completamente")
	return nil
}

func AnalyzeServices(serviceData ServiceData) (map[string]interface{}, error) {
	webhookURL := "https://n8n.srv794951.hstgr.cloud/webhook/5d00c979-3cbc-402c-8be6-6dd92036e6a6" // Substitua com sua URL do n8n

	// Marshal os dados para JSON
	payload, err := json.Marshal(serviceData)
	if err != nil {
		log.Printf("[ERROR] Falha ao marshalling dados: %v", err)
		return nil, err
	}

	// Envia a requisição para o n8n
	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		log.Printf("[ERROR] Falha ao enviar dados ao n8n: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	// Processa a resposta do n8n
	var resultArr []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&resultArr); err == nil && len(resultArr) > 0 {
		return resultArr[0], nil
	}

	// Caso a resposta seja uma string com formato JSON, tenta parsear
	var wrapper []struct {
		Output string `json:"output"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err == nil && len(wrapper) > 0 {
		clean := strings.TrimSpace(wrapper[0].Output)
		clean = strings.TrimPrefix(clean, "```json")
		clean = strings.TrimSuffix(clean, "```")
		clean = strings.TrimSpace(clean)

		// Parse do JSON limpo
		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(clean), &parsed); err == nil {
			return parsed, nil
		}
		log.Printf("[ERROR] Falha ao parsear JSON limpo: %v", err)
		log.Printf("[DEBUG] Conteúdo retornado (limpo): %s", clean)
	}

	log.Printf("[ERROR] Falha ao decodificar resposta do n8n completamente")
	return nil, fmt.Errorf("Erro ao processar resposta do n8n")
}

func AnalyzeServiceHandler(c *gin.Context) {
	var serviceData ServiceData

	// Recebe os dados do corpo da requisição
	if err := c.ShouldBindJSON(&serviceData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Erro ao processar os dados"})
		return
	}

	// Envia os dados para o n8n
	result, err := AnalyzeServices(serviceData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Erro ao enviar dados para o n8n: %v", err)})
		return
	}

	// Retorna os dados para o frontend
	c.JSON(http.StatusOK, result)
}