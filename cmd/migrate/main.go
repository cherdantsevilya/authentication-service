package main

import (
	"flag"
	"fmt"
	"log"

	"authentication-service/config"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func main() {
	// Загрузка конфигурации
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Парсинг аргументов командной строки
	direction := flag.String("direction", "up", "migration direction (up or down)")
	flag.Parse()

	// Формирование URL для подключения к базе данных
	dbURL := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.DBName,
		cfg.Database.SSLMode)

	// Создание экземпляра migrate
	m, err := migrate.New(
		"file://migrations",
		dbURL)
	if err != nil {
		log.Fatal(err)
	}
	defer m.Close()

	// Выполнение миграций
	switch *direction {
	case "up":
		if err := m.Up(); err != nil && err != migrate.ErrNoChange {
			log.Fatal(err)
		}
		log.Println("Successfully applied up migrations")
	case "down":
		if err := m.Down(); err != nil && err != migrate.ErrNoChange {
			log.Fatal(err)
		}
		log.Println("Successfully applied down migrations")
	default:
		log.Fatal("Invalid direction. Use 'up' or 'down'")
	}
}
