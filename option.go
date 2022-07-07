package risk

func Class(v TClass) func(*Event) {
	return func(ev *Event) {
		ev.Class = v
	}
}

func Subject(f string, v ...interface{}) func(*Event) {
	return func(ev *Event) {
		ev.Subjectf(f, v...)
	}
}

func Remote(v interface{}) func(*Event) {
	return func(ev *Event) {
		ev.Remote(v)
	}
}

func RPort(v int) func(*Event) {
	return func(ev *Event) {
		ev.RemotePort = v
	}
}

func Local(v interface{}) func(*Event) {
	return func(ev *Event) {
		ev.Local(v)
	}
}

func LPort(v int) func(*Event) {
	return func(ev *Event) {
		ev.LocalPort = v
	}
}

func Payload(f string, v ...interface{}) func(*Event) {
	return func(ev *Event) {
		ev.Payloadf(f, v...)
	}
}

func Refer(v string) func(*Event) {
	return func(ev *Event) {
		ev.Reference = v
	}
}

func Leve(v string) func(*Event) {
	return func(ev *Event) {
		ev.Leve(v)
	}
}

func From(v interface{}) func(*Event) {
	return func(ev *Event) {
		ev.From(v)
	}
}

func Alert(v bool) func(*Event) {
	return func(ev *Event) {
		ev.Alert = v
	}
}
