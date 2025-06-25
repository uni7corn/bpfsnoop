// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"testing"

	"github.com/bpfsnoop/bpfsnoop/internal/test"
	"rsc.io/c2go/cc"
)

func TestCompileFuncCall(t *testing.T) {
	t.Run("buf", func(t *testing.T) {
		t.Run("buf(skb->cb, x)", func(t *testing.T) {
			expr, err := cc.ParseExpr("buf(skb->cb, x)")
			test.AssertNoErr(t, err)

			_, err = compileFuncCall(expr)
			test.AssertHaveErr(t, err)
			test.AssertErrorPrefix(t, err, "buf() second argument must be a number")
		})

		t.Run("buf(skb->cb, 0xFFULL)", func(t *testing.T) {
			expr, err := cc.ParseExpr("buf(skb->cb, 0xFFULL)")
			test.AssertNoErr(t, err)

			_, err = compileFuncCall(expr)
			test.AssertHaveErr(t, err)
			test.AssertErrorPrefix(t, err, "buf() second argument must be a number: strconv.ParseUint")
		})

		t.Run("buf(skb->cb, 0xFF, a)", func(t *testing.T) {
			expr, err := cc.ParseExpr("buf(skb->cb, 0xFF, a)")
			test.AssertNoErr(t, err)

			_, err = compileFuncCall(expr)
			test.AssertHaveErr(t, err)
			test.AssertErrorPrefix(t, err, "buf() third argument must be a number")
		})

		t.Run("buf(skb->cb, 0xFF, 0xFFULL)", func(t *testing.T) {
			expr, err := cc.ParseExpr("buf(skb->cb, 0xFF, 0xFFULL)")
			test.AssertNoErr(t, err)

			_, err = compileFuncCall(expr)
			test.AssertHaveErr(t, err)
			test.AssertErrorPrefix(t, err, "buf() third argument must be a number: strconv.ParseUint")
		})

		t.Run("buf(skb->cb)", func(t *testing.T) {
			expr, err := cc.ParseExpr("buf(skb->cb)")
			test.AssertNoErr(t, err)

			_, err = compileFuncCall(expr)
			test.AssertHaveErr(t, err)
			test.AssertErrorPrefix(t, err, "buf() must have 2 or 3 arguments")
		})

		t.Run("buf(skb->cb, 0)", func(t *testing.T) {
			expr, err := cc.ParseExpr("buf(skb->cb, 0)")
			test.AssertNoErr(t, err)

			_, err = compileFuncCall(expr)
			test.AssertHaveErr(t, err)
			test.AssertErrorPrefix(t, err, "buf() size must be greater than 0")
		})
	})

	t.Run("str", func(t *testing.T) {
		t.Run("str(skb->cb, a, b)", func(t *testing.T) {
			expr, err := cc.ParseExpr("str(skb->cb, a, b)")
			test.AssertNoErr(t, err)

			_, err = compileFuncCall(expr)
			test.AssertHaveErr(t, err)
			test.AssertErrorPrefix(t, err, "str() must have 1 or 2 arguments")
		})

		t.Run("str(skb->cb, a)", func(t *testing.T) {
			expr, err := cc.ParseExpr("str(skb->cb, a)")
			test.AssertNoErr(t, err)

			_, err = compileFuncCall(expr)
			test.AssertHaveErr(t, err)
			test.AssertErrorPrefix(t, err, "str() second argument must be a number")
		})

		t.Run("str(skb->cb, 0xFFULL)", func(t *testing.T) {
			expr, err := cc.ParseExpr("str(skb->cb, 0xFFULL)")
			test.AssertNoErr(t, err)

			_, err = compileFuncCall(expr)
			test.AssertHaveErr(t, err)
			test.AssertErrorPrefix(t, err, "str() second argument must be a number: strconv.ParseUint")
		})

		t.Run("str(skb->cb, 0)", func(t *testing.T) {
			expr, err := cc.ParseExpr("str(skb->cb, 0)")
			test.AssertNoErr(t, err)

			_, err = compileFuncCall(expr)
			test.AssertHaveErr(t, err)
			test.AssertErrorPrefix(t, err, "str() size must be greater than 0")
		})
	})

	t.Run("unsupported func call", func(t *testing.T) {
		expr, err := cc.ParseExpr("unsupported(skb->cb)")
		test.AssertNoErr(t, err)

		_, err = compileFuncCall(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "unknown function call: unsupported")
	})
}
