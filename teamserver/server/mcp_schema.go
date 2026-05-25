package server

type mcpToolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Mutating    bool           `json:"-"`
}

type mcpPropertyOption func(map[string]any)

func mcpEmptySchema() map[string]any {
	return mcpObjectSchema(map[string]any{}, nil)
}

func mcpObjectSchema(properties map[string]any, required []string) map[string]any {
	schema := map[string]any{
		"type":                 "object",
		"properties":           properties,
		"additionalProperties": false,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func mcpIntegerProperty(minimum int, maximum int, options ...mcpPropertyOption) map[string]any {
	property := map[string]any{"type": "integer", "minimum": minimum}
	if maximum > 0 {
		property["maximum"] = maximum
	}
	for _, option := range options {
		option(property)
	}
	return property
}

func mcpStringProperty(options ...mcpPropertyOption) map[string]any {
	property := map[string]any{"type": "string"}
	for _, option := range options {
		option(property)
	}
	return property
}

func mcpStringArrayProperty(defaultValue []string) map[string]any {
	return map[string]any{
		"type":    "array",
		"items":   map[string]any{"type": "string"},
		"default": defaultValue,
	}
}

func mcpStringMapProperty() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": map[string]any{"type": "string"},
	}
}

func mcpBooleanProperty(defaultValue bool) map[string]any {
	return map[string]any{"type": "boolean", "default": defaultValue}
}

func mcpEnumStringProperty(values []string, defaultValue string) map[string]any {
	return map[string]any{"type": "string", "enum": values, "default": defaultValue}
}

func mcpWithDefault(value any) mcpPropertyOption {
	return func(property map[string]any) {
		property["default"] = value
	}
}
