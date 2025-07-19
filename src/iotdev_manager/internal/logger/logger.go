package logger

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
	"iotdev_manager/internal/config"
)

// Logger 日志接口
type Logger interface {
	Debug(format string, args ...interface{})
	Info(format string, args ...interface{})
	Warn(format string, args ...interface{})
	Error(format string, args ...interface{})
	Fatal(format string, args ...interface{})
}

// LogrusLogger logrus实现的日志
type LogrusLogger struct {
	logger *logrus.Logger
}

// NewLogger 创建新的日志实例
func NewLogger(config config.LogConfig) Logger {
	logger := logrus.New()

	// 设置日志级别
	level, err := logrus.ParseLevel(strings.ToLower(config.Level))
	if err != nil {
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)

	// 设置日志格式
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
	})

	// 设置输出
	var writers []io.Writer

	// 控制台输出
	if config.Console {
		writers = append(writers, os.Stdout)
	}

	// 文件输出
	if config.File != "" {
		// 确保日志目录存在
		logDir := filepath.Dir(config.File)
		if err := os.MkdirAll(logDir, 0755); err != nil {
			logrus.Errorf("Failed to create log directory: %v", err)
		} else {
			file, err := os.OpenFile(config.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
			if err == nil {
				writers = append(writers, file)
			} else {
				logrus.Errorf("Failed to open log file: %v", err)
			}
		}
	}

	// 设置多输出
	if len(writers) > 0 {
		logger.SetOutput(io.MultiWriter(writers...))
	}

	return &LogrusLogger{logger: logger}
}

// Debug 输出Debug级别日志
func (l *LogrusLogger) Debug(format string, args ...interface{}) {
	l.logger.Debugf(format, args...)
}

// Info 输出Info级别日志
func (l *LogrusLogger) Info(format string, args ...interface{}) {
	l.logger.Infof(format, args...)
}

// Warn 输出Warn级别日志
func (l *LogrusLogger) Warn(format string, args ...interface{}) {
	l.logger.Warnf(format, args...)
}

// Error 输出Error级别日志
func (l *LogrusLogger) Error(format string, args ...interface{}) {
	l.logger.Errorf(format, args...)
}

// Fatal 输出Fatal级别日志
func (l *LogrusLogger) Fatal(format string, args ...interface{}) {
	l.logger.Fatalf(format, args...)
}