package query

import "fmt"

// --- AST Node Types ---

// Node is the interface for all AST nodes.
type Node interface {
	nodeType() string
}

// Query is the top-level AST node representing a complete query.
// It consists of a filter expression (the WHERE clause) and zero or
// more pipe stages (sort, limit, etc.).
type Query struct {
	Filter Node    // nil means "match all"
	Pipes  []Pipe  // pipeline stages after |
	Agg    *AggExpr // aggregation expression (count() by ...), nil if none
}

func (q *Query) nodeType() string { return "Query" }

// --- Filter Expressions ---

// CompareExpr represents a field-value comparison: field op value.
// Examples: process.name = "cmd.exe", @timestamp > "2026-01-01"
type CompareExpr struct {
	Field    string
	Operator CompareOp
	Value    string
}

func (c *CompareExpr) nodeType() string { return "Compare" }

// CompareOp is a comparison operator.
type CompareOp string

const (
	OpEquals    CompareOp = "="
	OpNotEquals CompareOp = "!="
	OpGreater   CompareOp = ">"
	OpLess      CompareOp = "<"
	OpGTE_Q     CompareOp = ">="
	OpLTE_Q     CompareOp = "<="
)

// BoolExpr represents a boolean combination of expressions.
type BoolExpr struct {
	Op    BoolOp
	Left  Node
	Right Node // nil for NOT (unary)
}

func (b *BoolExpr) nodeType() string { return "Bool" }

// BoolOp is a boolean operator.
type BoolOp string

const (
	BoolAnd BoolOp = "AND"
	BoolOr  BoolOp = "OR"
	BoolNot BoolOp = "NOT"
)

// ExistsExpr tests whether a field exists (is not null).
type ExistsExpr struct {
	Field string
}

func (e *ExistsExpr) nodeType() string { return "Exists" }

// InExpr represents a field IN (value1, value2, ...) expression.
type InExpr struct {
	Field  string
	Values []string
}

func (i *InExpr) nodeType() string { return "In" }

// --- Aggregation ---

// AggExpr represents an aggregation expression:
// count() by field1, field2 where <filter>
// The filter is stored in Query.Filter; the aggregation is separate.
type AggExpr struct {
	Function AggFunc  // count, sum, avg, min, max
	Field    string   // field for sum/avg/min/max (empty for count)
	GroupBy  []string // group-by fields
}

func (a *AggExpr) nodeType() string { return "Aggregation" }

// AggFunc is an aggregation function.
type AggFunc string

const (
	AggCount AggFunc = "count"
	AggSum   AggFunc = "sum"
	AggAvg   AggFunc = "avg"
	AggMin   AggFunc = "min"
	AggMax   AggFunc = "max"
)

// --- Pipe Stages ---

// Pipe is the interface for pipeline stages.
type Pipe interface {
	pipeType() string
}

// SortPipe represents | sort field [asc|desc]
type SortPipe struct {
	Field string
	Desc  bool
}

func (s *SortPipe) pipeType() string { return "Sort" }

// LimitPipe represents | limit N
type LimitPipe struct {
	N int
}

func (l *LimitPipe) pipeType() string { return "Limit" }

// FieldsPipe represents | fields field1, field2, ...
type FieldsPipe struct {
	Fields []string
}

func (f *FieldsPipe) pipeType() string { return "Fields" }

// HeadPipe represents | head N (alias for limit)
type HeadPipe struct {
	N int
}

func (h *HeadPipe) pipeType() string { return "Head" }

// TailPipe represents | tail N
type TailPipe struct {
	N int
}

func (t *TailPipe) pipeType() string { return "Tail" }

// --- String Representations ---

func (op CompareOp) String() string { return string(op) }
func (op BoolOp) String() string    { return string(op) }
func (f AggFunc) String() string    { return string(f) }

func (c *CompareExpr) String() string {
	return fmt.Sprintf("%s %s %q", c.Field, c.Operator, c.Value)
}

func (b *BoolExpr) String() string {
	if b.Op == BoolNot {
		return fmt.Sprintf("NOT (%v)", b.Left)
	}
	return fmt.Sprintf("(%v %s %v)", b.Left, b.Op, b.Right)
}
