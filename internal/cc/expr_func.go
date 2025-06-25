// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"fmt"

	"rsc.io/c2go/cc"
)

type funcCallValue struct {
	typ        EvalResultType
	expr       *cc.Expr
	dataOffset int64
	dataSize   int64
}

func compileFuncCall(expr *cc.Expr) (funcCallValue, error) {
	var (
		val funcCallValue
		err error
	)

	val.expr = expr.List[0]

	fnName := expr.Left.Text
	switch fnName {
	case "buf":
		switch len(expr.List) {
		case 2, 3:
			if expr.List[1].Op != cc.Number {
				return val, fmt.Errorf("%s() second argument must be a number", fnName)
			}

			val.dataSize, err = parseNumber(expr.List[1].Text)
			if err != nil {
				return val, fmt.Errorf("%s() second argument must be a number: %w", fnName, err)
			}

			if len(expr.List) == 3 {
				val.dataOffset = val.dataSize

				if expr.List[2].Op != cc.Number {
					return val, fmt.Errorf("%s() third argument must be a number", fnName)
				}
				val.dataSize, err = parseNumber(expr.List[2].Text)
				if err != nil {
					return val, fmt.Errorf("%s() third argument must be a number: %w", fnName, err)
				}
			}

		default:
			return val, fmt.Errorf("%s() must have 2 or 3 arguments", fnName)
		}

		if val.dataSize <= 0 {
			return val, fmt.Errorf("%s() size must be greater than 0", fnName)
		}

		val.typ = EvalResultTypeBuf

	case "str":
		if len(expr.List) != 1 && len(expr.List) != 2 {
			return val, fmt.Errorf("%s() must have 1 or 2 arguments", fnName)
		}

		val.dataSize = -1
		if len(expr.List) == 2 {
			if expr.List[1].Op != cc.Number {
				return val, fmt.Errorf("%s() second argument must be a number", fnName)
			}
			val.dataSize, err = parseNumber(expr.List[1].Text)
			if err != nil {
				return val, fmt.Errorf("%s() second argument must be a number: %w", fnName, err)
			}
			if val.dataSize <= 0 {
				return val, fmt.Errorf("%s() size must be greater than 0", fnName)
			}
		}

		val.typ = EvalResultTypeString

	default:
		return val, fmt.Errorf("unknown function call: %s", fnName)
	}

	return val, err
}
