package traefik_edgeone_ip

import (
	"context"
	"log/slog"
	"os"
	"strings"
)

type PluginLogger struct {
	logger *slog.Logger
}

func NewPluginLogger(pluginName, logLevelStr string) *PluginLogger {
	level := new(slog.LevelVar)
	switch strings.ToLower(logLevelStr) {
	case LogLevelDebug:
		level.Set(slog.LevelDebug)
	case LogLevelInfo, "":
		level.Set(slog.LevelInfo)
	case LogLevelWarn:
		level.Set(slog.LevelWarn)
	case LogLevelError:
		level.Set(slog.LevelError)
	default:
		level.Set(slog.LevelInfo)
	}

	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: false,
		Level:     level,
	})

	return &PluginLogger{
		logger: slog.New(handler).With(slog.String("plugin", pluginName)),
	}
}

func (l *PluginLogger) DebugContext(ctx context.Context, msg string, attrs ...any) {
	l.logger.Log(ctx, slog.LevelDebug, msg, attrs...)
}

func (l *PluginLogger) InfoContext(ctx context.Context, msg string, attrs ...any) {
	l.logger.Log(ctx, slog.LevelInfo, msg, attrs...)
}

func (l *PluginLogger) WarnContext(ctx context.Context, msg string, attrs ...any) {
	l.logger.Log(ctx, slog.LevelWarn, msg, attrs...)
}

func (l *PluginLogger) ErrorContext(ctx context.Context, msg string, attrs ...any) {
	l.logger.Log(ctx, slog.LevelError, msg, attrs...)
}
