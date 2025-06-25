// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"fmt"
	"slices"

	"rsc.io/c2go/cc"
)

const (
	PktTypeEth   = "eth"
	PktTypeIP    = "ip"
	PktTypeIP4   = "ip4"
	PktTypeIP6   = "ip6"
	PktTypeICMP  = "icmp"
	PktTypeICMP6 = "icmp6"
	PktTypeTCP   = "tcp"
	PktTypeUDP   = "udp"
)

type funcCallValue struct {
	typ        EvalResultType
	expr       *cc.Expr
	dataOffset int64
	dataSize   int64
	pkt        string
}

func parseExprNumber(expr *cc.Expr) (int64, error) {
	if expr.Op != cc.Number {
		return 0, fmt.Errorf("expected a number expression, got %s", expr.Op)
	}

	num, err := parseNumber(expr.Text)
	if err != nil {
		return 0, fmt.Errorf("failed to parse number: %w", err)
	}

	return num, nil
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
			val.dataSize, err = parseExprNumber(expr.List[1])
			if err != nil {
				return val, fmt.Errorf("%s() second argument must be a number: %w", fnName, err)
			}

			if len(expr.List) == 3 {
				val.dataOffset = val.dataSize

				val.dataSize, err = parseExprNumber(expr.List[2])
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
			val.dataSize, err = parseExprNumber(expr.List[1])
			if err != nil {
				return val, fmt.Errorf("%s() second argument must be a number: %w", fnName, err)
			}
			if val.dataSize <= 0 {
				return val, fmt.Errorf("%s() size must be greater than 0", fnName)
			}
		}

		val.typ = EvalResultTypeString

	case "pkt":
		allowedPktTypes := []string{
			PktTypeEth,
			PktTypeIP, PktTypeIP4, PktTypeIP6,
			PktTypeICMP, PktTypeICMP6,
			PktTypeTCP, PktTypeUDP,
		}

		switch len(expr.List) {
		case 2:
			val.dataSize, err = parseExprNumber(expr.List[1])
			if err != nil {
				return val, fmt.Errorf("%s() second argument must be a number: %w", fnName, err)
			}

			val.pkt = PktTypeEth // default pkt type

		case 3:
			val.dataSize, err = parseExprNumber(expr.List[1])
			if err != nil {
				return val, fmt.Errorf("%s() second argument must be a number: %w", fnName, err)
			}

			switch expr.List[2].Op {
			case cc.Name:
				pktType := expr.List[2].Text
				if !slices.Contains(allowedPktTypes, pktType) {
					return val, fmt.Errorf("%s() third argument as pkt type must be one of %v", fnName, allowedPktTypes)
				}

				val.pkt = pktType

			case cc.Number:
				val.dataOffset = val.dataSize
				val.dataSize, err = parseNumber(expr.List[2].Text)
				if err != nil {
					return val, fmt.Errorf("%s() third argument must be a number: %w", fnName, err)
				}

				val.pkt = PktTypeEth // default pkt type

			default:
				return val, fmt.Errorf("%s() third argument must be pkt type or a number", fnName)
			}

		case 4:
			val.dataOffset, err = parseExprNumber(expr.List[1])
			if err != nil {
				return val, fmt.Errorf("%s() second argument must be a number: %w", fnName, err)
			}

			val.dataSize, err = parseExprNumber(expr.List[2])
			if err != nil {
				return val, fmt.Errorf("%s() third argument must be a number: %w", fnName, err)
			}

			if expr.List[3].Op != cc.Name {
				return val, fmt.Errorf("%s() fourth argument must be pkt type", fnName)
			}
			pktType := expr.List[3].Text
			if !slices.Contains(allowedPktTypes, pktType) {
				return val, fmt.Errorf("%s() fourth argument as pkt type must be one of %v", fnName, allowedPktTypes)
			}

			val.pkt = pktType

		default:
			return val, fmt.Errorf("%s() must have 2, 3 or 4 arguments", fnName)
		}

		if val.dataSize <= 0 {
			return val, fmt.Errorf("%s() size must be greater than 0", fnName)
		}

		val.typ = EvalResultTypePkt

	default:
		return val, fmt.Errorf("unknown function call: %s", fnName)
	}

	return val, err
}
