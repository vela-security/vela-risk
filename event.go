package risk

import (
	"encoding/json"
	"fmt"
	opcode "github.com/vela-security/vela-opcode"
	"github.com/vela-security/vela-public/auxlib"
	"github.com/vela-security/vela-public/kind"
	"github.com/vela-security/vela-public/lua"
	"time"
)

var format = fmt.Sprintf

type Event struct {
	MinionId   string    `json:"minion_id"`
	Inet       string    `json:"inet"`
	Class      TClass    `json:"class"`
	Level      string    `json:"level"`
	Payload    string    `json:"payload"`
	Subject    string    `json:"subject"`
	LocalIP    string    `json:"local_ip"`
	LocalPort  int       `json:"local_port"`
	RemoteIP   string    `json:"remote_ip"`
	RemotePort int       `json:"remote_port"`
	Region     string    `json:"region"`
	Time       time.Time `json:"time"`
	Reference  string    `json:"reference"`
	FromCode   string    `json:"from_code"`
	Alert      bool      `json:"alert"`
}

func newEv() *Event {
	return &Event{
		MinionId: xEnv.ID(),
		Inet:     xEnv.Inet(),
		LocalIP:  xEnv.Inet(),
		Time:     time.Now(),
		Level:    NOTICE,
		Alert:    false,

		Payload:  "-",
		Subject:  "-",
		RemoteIP: "-",
		FromCode: "-",
	}
}

func NewEv(ov ...func(*Event)) *Event {
	ev := newEv()
	for _, fn := range ov {
		fn(ev)
	}
	return ev
}

func (ev *Event) SearchRegion() {
	info, err := xEnv.Region(ev.RemoteIP)
	if err != nil {
		xEnv.Infof("%s not found region info fail %v", ev.RemoteIP, err)
		return
	}

	ev.Region = auxlib.B2S(info.Byte())
	return
}

func (ev *Event) Subjectf(f string, v ...interface{}) {
	ev.Subject = format(f, v...)
}

func (ev *Event) Payloadf(f string, v ...interface{}) {
	ev.Payload = format(f, v...)
}

func (ev *Event) Local(v interface{}) {
	ip, port := decomposition(v)
	if ip == "" {
		return
	}

	ev.LocalIP = ip
	ev.LocalPort = port
}

func (ev *Event) Remote(v interface{}) {
	ip, port := decomposition(v)
	if ip == "" {
		return
	}

	ev.RemoteIP = ip
	ev.RemotePort = port
	ev.SearchRegion()
}

func (ev *Event) From(v interface{}) {
	switch c := v.(type) {
	case string:
		ev.FromCode = c
	case *lua.LState:
		ev.FromCode = c.CodeVM()
	case *lua.ProcData:
		ev.FromCode = c.CodeVM()
	}
}

func (ev *Event) High() {
	ev.Level = HIGH
}
func (ev *Event) Serious() {
	ev.Level = SERIOUS
}

func (ev *Event) Middle() {
	ev.Level = MIDDLE
}

func (ev *Event) Notice() {
	ev.Level = NOTICE
}

func (ev *Event) Leve(v string) {
	switch v {
	case SERIOUS, HIGH, MIDDLE, NOTICE:
		ev.Level = v
	default:
		ev.Level = NOTICE
	}
}

func (ev *Event) Byte() []byte {
	enc := kind.NewJsonEncoder()
	enc.Tab("")
	enc.KV("minion_id", ev.MinionId)
	enc.KV("inet", ev.Inet)
	enc.KV("class", ev.Class.String())
	enc.KV("Level", ev.Level)
	enc.KV("payload", ev.Payload)
	enc.KV("subject", ev.Subject)
	enc.KV("local_ip", ev.LocalIP)
	enc.KV("local_port", ev.LocalPort)
	enc.KV("remote_ip", ev.RemoteIP)
	enc.KV("remote_port", ev.RemotePort)
	enc.KV("region", ev.Region)
	enc.KV("time", ev.Time)
	enc.KV("reference", ev.Reference)
	enc.KV("time", ev.Time)
	enc.KV("from_code", ev.FromCode)
	enc.KV("alert", ev.Alert)
	enc.End("}")
	return enc.Bytes()
}

func (ev *Event) Send() {
	chunk := ev.Byte()
	err := xEnv.TnlSend(opcode.OpRisk, json.RawMessage(chunk))
	if err != nil {
		xEnv.Errorf("risk event %v send fail %v", ev, err)
	}
}

func (ev *Event) Log() {
	xEnv.Errorf("%v", ev)
}