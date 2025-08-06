package utils

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"edr-agent-windows/internal/config"
)

type Logger struct {
	config *config.LogConfig
	file   *os.File
	logger *log.Logger
}

func NewLogger(cfg *config.LogConfig) *Logger {
	logger := &Logger{
		config: cfg,
	}

	// Create log directory if it doesn't exist
	logDir := filepath.Dir(cfg.FilePath)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		log.Printf("Failed to create log directory: %v", err)
	}

	// Open log file
	file, err := os.OpenFile(cfg.FilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("Failed to open log file: %v", err)
		// Fallback to stdout
		logger.logger = log.New(os.Stdout, "", log.LstdFlags)
	} else {
		logger.file = file
		logger.logger = log.New(file, "", log.LstdFlags)
	}

	return logger
}

func (l *Logger) Info(format string, args ...interface{}) {
	l.log("INFO", format, args...)
}

func (l *Logger) Error(format string, args ...interface{}) {
	l.log("ERROR", format, args...)
}

func (l *Logger) Warn(format string, args ...interface{}) {
	l.log("WARN", format, args...)
}

func (l *Logger) Debug(format string, args ...interface{}) {
	if l.config.Level == "debug" {
		l.log("DEBUG", format, args...)
	}
}

func (l *Logger) log(level, format string, args ...interface{}) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	message := fmt.Sprintf(format, args...)
	
	if l.config.Format == "json" {
		l.logger.Printf(`{"timestamp":"%s","level":"%s","message":"%s"}`, timestamp, level, message)
	} else {
		l.logger.Printf("[%s] %s: %s", timestamp, level, message)
	}
}

func (l *Logger) Close() {
	if l.file != nil {
		l.file.Close()
	}
}

// WaitForInterrupt waits for interrupt signal
func WaitForInterrupt() {
	// Simple implementation - in production you'd use signal handling
	select {}
} 