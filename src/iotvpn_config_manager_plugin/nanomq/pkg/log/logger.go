package log

import (
	"fmt"
	"log"
	"os"
)

var _errlog *log.Logger
var _outlog *log.Logger

var logEnable = true

func init() {
	if os.Getenv("NANOMQ_PLUGIN_LOG") == "disable" {
		logEnable = false
	}
	if logEnable {
		_outlog = log.New(os.Stdout, "", log.LstdFlags|log.Lshortfile)
		_errlog = log.New(os.Stderr, "", log.LstdFlags|log.Lshortfile)
	}
}

func LogDebug(format string, v ...any) {
	if logEnable {
		_outlog.Output(2, fmt.Sprintf("[DEBUG] nanomq plugin: "+format, v...))
	}
}

func LogWarn(format string, v ...any) {
	if logEnable {
		_outlog.Output(2, fmt.Sprintf("[WARN ] nanomq plugin: "+format, v...))
	}
}

func LogError(format string, v ...any) {
	if logEnable {
		_outlog.Output(2, fmt.Sprintf("[ERROR] nanomq plugin: "+format, v...))
	}
}
