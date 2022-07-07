package risk

import (
	"github.com/vela-security/vela-public/assert"
	"github.com/vela-security/vela-public/lua"
)

var xEnv assert.Environment

func newLuaRiskFunc(v TClass) lua.LValue {
	return lua.NewFunction(func(L *lua.LState) int {
		ev := newEvL(L)
		ev.Class = v
		ev.FromCode = L.CodeVM()
		L.Push(ev)
		return 1
	})
}

func newLuaRiskEv(L *lua.LState) int {
	L.Push(NewEv())
	return 1
}

func WithEnv(env assert.Environment) {
	xEnv = env
	xEnv.Set("TBrute", lua.LInt(TBrute))
	xEnv.Set("TVirus", lua.LInt(TVirus))
	xEnv.Set("TWeakPass", lua.LInt(TWeakPass))
	xEnv.Set("TCrawler", lua.LInt(TCrawler))
	xEnv.Set("THoneyPot", lua.LInt(THoneyPot))
	xEnv.Set("TWeb", lua.LInt(TWeb))
	xEnv.Set("TLogin", lua.LInt(TLogin))
	xEnv.Set("TMonitor", lua.LInt(TMonitor))

	risk := lua.NewUserKV()
	risk.Set("brute", newLuaRiskFunc(TBrute))
	risk.Set("virus", newLuaRiskFunc(TVirus))
	risk.Set("weak_pass", newLuaRiskFunc(TWeakPass))
	risk.Set("crawler", newLuaRiskFunc(TCrawler))
	risk.Set("web", newLuaRiskFunc(TWeb))
	risk.Set("login", newLuaRiskFunc(TLogin))
	risk.Set("monitor", newLuaRiskFunc(TMonitor))
	risk.Set("event", lua.NewFunction(newLuaRiskEv))
	xEnv.Set("risk", risk)
}
