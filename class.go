package risk

const (
	TBrute TClass = iota + 1
	TVirus
	TWeakPass
	TCrawler
	THoneyPot
	TWeb
	TLogin
	TMonitor
)

var classTab = []string{"暴力破解", "病毒事件", "弱口令", "数据爬虫", "蜜罐应用", "web攻击", "登录事件", "监控事件"}

const (
	SERIOUS string = "紧急"
	HIGH    string = "高危"
	MIDDLE  string = "中危"
	NOTICE  string = "低危"
)

type TClass int

func (tc TClass) String() string {
	if tc < 1 || tc > TMonitor {
		return ""
	}

	return classTab[tc-1]
}
