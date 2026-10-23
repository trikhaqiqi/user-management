package router

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

const swaggerPage = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Godigi API</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>window.ui = SwaggerUIBundle({ url: "/docs/openapi.yaml", dom_id: "#swagger-ui" });</script>
</body>
</html>`

// registerDocs serves Swagger UI at /docs and the raw spec at
// /docs/openapi.yaml.
func registerDocs(r *gin.Engine, specPath string) {
	r.GET("/docs", func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache")
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(swaggerPage))
	})
	r.GET("/docs/openapi.yaml", func(c *gin.Context) {
		spec, err := os.ReadFile(specPath)
		if err != nil {
			c.String(http.StatusNotFound, "spec not found")
			return
		}
		c.Data(http.StatusOK, "application/yaml; charset=utf-8", spec)
	})
}
