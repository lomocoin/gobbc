package gobbc

// TemplateType 模版类型
type TemplateType int16

// 模版类型
const (
	TemplateTypeMin TemplateType = iota
	TemplateTypeWeighted
	TemplateTypeMultisig //多重签名
	TemplateTypeFork
	TemplateTypeProof    //pow
	TemplateTypeDelegate //dpos
	TemplateTypeExchange
	TemplateTypeVote //dpos投票
	TemplateTypePayment
	TemplateTypeMax
)

// TemplateDataSpliter 使用,分隔多个template data
const TemplateDataSpliter = ","
