package main

import (
	"database/sql"
	"fmt"
	"log"

	"authentication-service/config"
	"authentication-service/internal/api"
	"authentication-service/internal/middleware"
	"authentication-service/internal/repository"
	"authentication-service/internal/service"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
)

//TIP <p>To run your code, right-click the code and select <b>Run</b>.</p> <p>Alternatively, click
// the <icon src="AllIcons.Actions.Execute"/> icon in the gutter and select the <b>Run</b> menu item from here.</p>

func main() {
	// Загрузка конфигурации
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Подключение к базе данных
	db, err := sql.Open("postgres", cfg.Database.GetDSN())
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Проверка соединения с базой данных
	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	// Инициализация репозитория
	userRepo := repository.NewUserRepository(db)

	// Инициализация сервиса
	authService := service.NewAuthService(
		userRepo,
		cfg.JWT.SecretKey,
		cfg.Security.EncryptionKey,
		cfg.Security.MaxLoginAttempts,
		cfg.Security.RateLimitWindow,
	)

	// Инициализация middleware
	authMiddleware := middleware.NewAuthMiddleware(cfg.JWT.SecretKey)

	// Инициализация handlers
	authHandler := api.NewAuthHandler(authService)

	// Настройка Gin
	router := gin.Default()

	// Middleware для CORS
	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	// API routes
	api := router.Group("/api/v1")
	{
		// Публичные endpoints
		auth := api.Group("/auth")
		{
			auth.POST("/register", authHandler.Register)
			auth.POST("/login", authHandler.Login)
			auth.POST("/verify-totp", authHandler.VerifyTOTP)
		}

		// Защищенные endpoints
		protected := api.Group("/protected")
		protected.Use(authMiddleware.AuthRequired())
		{
			protected.POST("/setup-2fa", authHandler.SetupTOTP)
			protected.GET("/me", func(c *gin.Context) {
				userID, _ := c.Get("user_id")
				username, _ := c.Get("username")
				email, _ := c.Get("email")
				c.JSON(200, gin.H{
					"user_id":  userID,
					"username": username,
					"email":    email,
				})
			})
		}

		// Admin endpoints
		admin := api.Group("/admin")
		admin.Use(authMiddleware.AdminRequired())
		{
			admin.POST("/disable-2fa/:username", authHandler.DisableTOTP)
		}
	}

	// Статические файлы для веб-интерфейса
	router.Static("/static", "./web/static")
	router.LoadHTMLGlob("web/templates/*")

	// Главная страница
	router.GET("/", func(c *gin.Context) {
		c.HTML(200, "index.html", nil)
	})

	// Запуск сервера
	addr := fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port)
	if err := router.Run(addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
