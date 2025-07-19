package utils

import (
	"fmt"
	"runtime"
	"time"
)

// FormatTime 格式化时间
func FormatTime(t time.Time, layout string) string {
	if layout == "" {
		layout = "2006-01-02 15:04:05"
	}
	return t.Format(layout)
}

// GetCurrentTimeString 获取当前时间字符串
func GetCurrentTimeString(layout string) string {
	return FormatTime(time.Now(), layout)
}

// PanicIfError 如果错误不为nil则panic
func PanicIfError(err error) {
	if err != nil {
		panic(err)
	}
}

// PrintMemoryUsage 打印内存使用情况
func PrintMemoryUsage() string {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return fmt.Sprintf("Alloc = %v MiB, TotalAlloc = %v MiB, Sys = %v MiB, NumGC = %v",
		bToMb(m.Alloc),
		bToMb(m.TotalAlloc),
		bToMb(m.Sys),
		m.NumGC)
}

// bToMb 将字节转换为兆字节
func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}
