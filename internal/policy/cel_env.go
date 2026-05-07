package policy

import "github.com/google/cel-go/cel"

func newEnv() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable("bot", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("request", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("site", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("sets", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("labels", cel.MapType(cel.StringType, cel.DynType)),
	)
}
