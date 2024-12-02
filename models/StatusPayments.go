package models

var statusMap = map[int]string{
	200: "OK",
	400: "ERROR",
	206: "WAIT",
	408: "TIMEOUT",
}

func GetStatusDescription(statusCode int) string {
	if description, ok := statusMap[statusCode]; ok {
		return description
	}
	return "UNKNOWN"
}
