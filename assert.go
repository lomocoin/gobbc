package gobbc

import (
	"encoding/json"
	"reflect"
	"runtime/debug"
	"strings"
	"testing"
)

// TW testing.T wrap
type TW struct {
	*testing.T
	_continue bool //断言失败时是否继续测试(不执行FailNow)
}

// Copy .
func (tw *TW) Copy() *TW {
	return &TW{
		T:         tw.T,
		_continue: tw._continue,
	}
}

// Continue 断言失败时是否继续测试(不执行FailNow)
func (tw *TW) Continue(_continue bool) *TW {
	tw._continue = _continue
	return tw
}

func (tw *TW) assertFailed(msg string, args ...interface{}) {
	if tw._continue {
		stack := strings.Join(
			strings.SplitN(string(debug.Stack()), "\n", 7)[5:7],
			"\n",
		)
		args = append(args, "\n"+stack)
		tw.Errorf(msg, args...)
	} else {
		debug.PrintStack()
		tw.Fatalf(msg, args...)
	}
}

// Nil if x not nil, fatal
func (tw *TW) Nil(x interface{}, args ...interface{}) *TW {
	if x != nil {
		args = append(args, x)
		tw.assertFailed("[test failed] interface{} not nil: %v", args)
	}
	return tw
}

// True if flag == false, fatal
func (tw *TW) True(flag bool, args ...interface{}) *TW {
	if !flag {
		tw.assertFailed("[test fatal] flag false, args: %v", args)
	}
	return tw
}

// IsZero if flag == false, fatal
func (tw *TW) IsZero(v interface{}, args ...interface{}) *TW {
	if !reflect.ValueOf(v).IsZero() {
		tw.assertFailed("[test fatal] not zero value, args: %v, %v", v, args)
	}
	return tw
}

// Equal reflect.DeepEqual
func (tw *TW) Equal(expected, actual interface{}, args ...interface{}) *TW {
	if !reflect.DeepEqual(expected, actual) {
		args = append([]interface{}{expected, expected, actual, actual}, args...)
		tw.assertFailed("[test assert failed] should be equal: [%v(%T)] <-expected actual-> [%v(%T)]", args...)
	}
	return tw
}

func JSONIndent(v interface{}) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}
