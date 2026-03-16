package query

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// Parse converts a query string into an AST Query.
// Returns a descriptive error if the syntax is invalid.
//
// Grammar (informal):
//
//	query      = [agg_expr "where"] filter_expr ["|" pipe_stage]*
//	filter_expr = or_expr
//	or_expr    = and_expr ("OR" and_expr)*
//	and_expr   = unary_expr ("AND" unary_expr)*
//	unary_expr = "NOT" unary_expr | "(" or_expr ")" | compare_expr | exists_expr | in_expr
//	compare_expr = field op value
//	exists_expr  = field "exists"
//	in_expr    = field "IN" "(" value ("," value)* ")"
//	agg_expr   = agg_func "(" [field] ")" "by" field ("," field)*
//	pipe_stage = "sort" field ["asc"|"desc"] | "limit" N | "head" N | "tail" N | "fields" field ("," field)*
func Parse(input string) (*Query, error) {
	p := &parser{
		tokens: tokenize(input),
		pos:    0,
	}

	q, err := p.parseQuery()
	if err != nil {
		return nil, err
	}

	if !p.atEnd() {
		return nil, fmt.Errorf("unexpected token %q at position %d", p.current().value, p.current().pos)
	}

	return q, nil
}

// --- Token Types ---

type tokenType int

const (
	tokEOF tokenType = iota
	tokIdent
	tokString   // "quoted string"
	tokNumber   // integer
	tokOperator // =, !=, >, <, >=, <=
	tokPipe     // |
	tokLParen   // (
	tokRParen   // )
	tokComma    // ,
	tokStar     // *
)

type token struct {
	typ   tokenType
	value string
	pos   int // position in original input
}

// --- Tokenizer ---

func tokenize(input string) []token {
	var tokens []token
	i := 0

	for i < len(input) {
		// Skip whitespace.
		if unicode.IsSpace(rune(input[i])) {
			i++
			continue
		}

		pos := i

		switch input[i] {
		case '|':
			tokens = append(tokens, token{tokPipe, "|", pos})
			i++
		case '(':
			tokens = append(tokens, token{tokLParen, "(", pos})
			i++
		case ')':
			tokens = append(tokens, token{tokRParen, ")", pos})
			i++
		case ',':
			tokens = append(tokens, token{tokComma, ",", pos})
			i++
		case '*':
			tokens = append(tokens, token{tokStar, "*", pos})
			i++
		case '"', '\'':
			// Quoted string.
			quote := input[i]
			i++
			start := i
			for i < len(input) && input[i] != quote {
				if input[i] == '\\' && i+1 < len(input) {
					i++ // skip escaped char
				}
				i++
			}
			val := input[start:i]
			if i < len(input) {
				i++ // skip closing quote
			}
			tokens = append(tokens, token{tokString, val, pos})
		case '!':
			if i+1 < len(input) && input[i+1] == '=' {
				tokens = append(tokens, token{tokOperator, "!=", pos})
				i += 2
			} else {
				tokens = append(tokens, token{tokIdent, "!", pos})
				i++
			}
		case '=':
			tokens = append(tokens, token{tokOperator, "=", pos})
			i++
		case '>':
			if i+1 < len(input) && input[i+1] == '=' {
				tokens = append(tokens, token{tokOperator, ">=", pos})
				i += 2
			} else {
				tokens = append(tokens, token{tokOperator, ">", pos})
				i++
			}
		case '<':
			if i+1 < len(input) && input[i+1] == '=' {
				tokens = append(tokens, token{tokOperator, "<=", pos})
				i += 2
			} else {
				tokens = append(tokens, token{tokOperator, "<", pos})
				i++
			}
		default:
			// Identifier, keyword, or number.
			if unicode.IsDigit(rune(input[i])) {
				start := i
				for i < len(input) && unicode.IsDigit(rune(input[i])) {
					i++
				}
				tokens = append(tokens, token{tokNumber, input[start:i], pos})
			} else if isIdentStart(rune(input[i])) {
				start := i
				for i < len(input) && isIdentChar(rune(input[i])) {
					i++
				}
				// Check for wildcard suffix: field*
				word := input[start:i]
				tokens = append(tokens, token{tokIdent, word, pos})
			} else {
				// Unknown character — skip it.
				i++
			}
		}
	}

	tokens = append(tokens, token{tokEOF, "", len(input)})
	return tokens
}

func isIdentStart(r rune) bool {
	return unicode.IsLetter(r) || r == '_' || r == '@'
}

func isIdentChar(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '.' || r == '-' || r == '@' || r == '*'
}

// --- Parser ---

type parser struct {
	tokens []token
	pos    int
}

func (p *parser) current() token {
	if p.pos >= len(p.tokens) {
		return token{tokEOF, "", -1}
	}
	return p.tokens[p.pos]
}

func (p *parser) peek() token {
	return p.current()
}

func (p *parser) advance() token {
	t := p.current()
	if p.pos < len(p.tokens) {
		p.pos++
	}
	return t
}

func (p *parser) atEnd() bool {
	return p.current().typ == tokEOF
}

func (p *parser) expect(typ tokenType) (token, error) {
	t := p.current()
	if t.typ != typ {
		return t, fmt.Errorf("expected %v, got %q at position %d", typ, t.value, t.pos)
	}
	p.advance()
	return t, nil
}

func (p *parser) matchKeyword(keyword string) bool {
	t := p.current()
	if t.typ == tokIdent && strings.EqualFold(t.value, keyword) {
		return true
	}
	return false
}

func (p *parser) consumeKeyword(keyword string) bool {
	if p.matchKeyword(keyword) {
		p.advance()
		return true
	}
	return false
}

// --- Parse Methods ---

func (p *parser) parseQuery() (*Query, error) {
	q := &Query{}

	// Check for aggregation: agg_func(...) by ... [where ...]
	if p.isAggStart() {
		agg, err := p.parseAgg()
		if err != nil {
			return nil, err
		}
		q.Agg = agg

		// Optional "where" clause after aggregation.
		if p.consumeKeyword("where") {
			filter, err := p.parseOrExpr()
			if err != nil {
				return nil, err
			}
			q.Filter = filter
		}
	} else if !p.atEnd() && p.current().typ != tokPipe {
		// Parse filter expression.
		filter, err := p.parseOrExpr()
		if err != nil {
			return nil, err
		}
		q.Filter = filter
	}

	// Parse pipe stages.
	for p.current().typ == tokPipe {
		p.advance() // consume |
		pipe, err := p.parsePipeStage()
		if err != nil {
			return nil, err
		}
		q.Pipes = append(q.Pipes, pipe)
	}

	return q, nil
}

func (p *parser) isAggStart() bool {
	if p.current().typ != tokIdent {
		return false
	}
	name := strings.ToLower(p.current().value)
	if name != "count" && name != "sum" && name != "avg" && name != "min" && name != "max" {
		return false
	}
	// Check if next token is "(".
	if p.pos+1 < len(p.tokens) && p.tokens[p.pos+1].typ == tokLParen {
		return true
	}
	return false
}

func (p *parser) parseAgg() (*AggExpr, error) {
	funcName := strings.ToLower(p.advance().value)
	aggFunc, err := toAggFunc(funcName)
	if err != nil {
		return nil, err
	}

	if _, err := p.expect(tokLParen); err != nil {
		return nil, fmt.Errorf("expected '(' after %s", funcName)
	}

	// Optional field inside parens.
	var field string
	if p.current().typ == tokIdent {
		field = p.advance().value
	}

	if _, err := p.expect(tokRParen); err != nil {
		return nil, fmt.Errorf("expected ')' after aggregation field")
	}

	// Expect "by".
	if !p.consumeKeyword("by") {
		return nil, fmt.Errorf("expected 'by' after aggregation function")
	}

	// Parse group-by fields.
	var groupBy []string
	for {
		if p.current().typ != tokIdent {
			return nil, fmt.Errorf("expected field name in group-by clause")
		}
		groupBy = append(groupBy, p.advance().value)
		if p.current().typ != tokComma {
			break
		}
		p.advance() // consume comma
	}

	return &AggExpr{
		Function: aggFunc,
		Field:    field,
		GroupBy:  groupBy,
	}, nil
}

func toAggFunc(name string) (AggFunc, error) {
	switch name {
	case "count":
		return AggCount, nil
	case "sum":
		return AggSum, nil
	case "avg":
		return AggAvg, nil
	case "min":
		return AggMin, nil
	case "max":
		return AggMax, nil
	default:
		return "", fmt.Errorf("unknown aggregation function %q", name)
	}
}

func (p *parser) parseOrExpr() (Node, error) {
	left, err := p.parseAndExpr()
	if err != nil {
		return nil, err
	}

	for p.matchKeyword("OR") {
		p.advance()
		right, err := p.parseAndExpr()
		if err != nil {
			return nil, err
		}
		left = &BoolExpr{Op: BoolOr, Left: left, Right: right}
	}

	return left, nil
}

func (p *parser) parseAndExpr() (Node, error) {
	left, err := p.parseUnaryExpr()
	if err != nil {
		return nil, err
	}

	for p.matchKeyword("AND") {
		p.advance()
		right, err := p.parseUnaryExpr()
		if err != nil {
			return nil, err
		}
		left = &BoolExpr{Op: BoolAnd, Left: left, Right: right}
	}

	return left, nil
}

func (p *parser) parseUnaryExpr() (Node, error) {
	// NOT expr
	if p.matchKeyword("NOT") {
		p.advance()
		expr, err := p.parseUnaryExpr()
		if err != nil {
			return nil, err
		}
		return &BoolExpr{Op: BoolNot, Left: expr}, nil
	}

	// Parenthesized expression.
	if p.current().typ == tokLParen {
		p.advance()
		expr, err := p.parseOrExpr()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(tokRParen); err != nil {
			return nil, fmt.Errorf("expected closing ')'")
		}
		return expr, nil
	}

	// field op value | field "exists" | field "IN" (...)
	return p.parseFieldExpr()
}

func (p *parser) parseFieldExpr() (Node, error) {
	if p.current().typ == tokStar {
		// Wildcard match-all.
		p.advance()
		return nil, nil // match all
	}

	if p.current().typ != tokIdent {
		return nil, fmt.Errorf("expected field name, got %q at position %d", p.current().value, p.current().pos)
	}

	field := p.advance().value

	// field "exists"
	if p.matchKeyword("exists") {
		p.advance()
		return &ExistsExpr{Field: field}, nil
	}

	// field "IN" (value, value, ...)
	if p.matchKeyword("IN") {
		p.advance()
		return p.parseInExpr(field)
	}

	// field op value
	if p.current().typ != tokOperator {
		return nil, fmt.Errorf("expected operator after field %q, got %q at position %d",
			field, p.current().value, p.current().pos)
	}

	op := CompareOp(p.advance().value)

	// Value can be a string, number, or unquoted identifier (with wildcards).
	val, err := p.parseValue()
	if err != nil {
		return nil, fmt.Errorf("expected value after %s %s: %w", field, op, err)
	}

	return &CompareExpr{
		Field:    field,
		Operator: op,
		Value:    val,
	}, nil
}

func (p *parser) parseInExpr(field string) (Node, error) {
	if _, err := p.expect(tokLParen); err != nil {
		return nil, fmt.Errorf("expected '(' after IN")
	}

	var values []string
	for {
		val, err := p.parseValue()
		if err != nil {
			return nil, fmt.Errorf("expected value in IN list: %w", err)
		}
		values = append(values, val)

		if p.current().typ != tokComma {
			break
		}
		p.advance() // consume comma
	}

	if _, err := p.expect(tokRParen); err != nil {
		return nil, fmt.Errorf("expected ')' to close IN list")
	}

	return &InExpr{Field: field, Values: values}, nil
}

func (p *parser) parseValue() (string, error) {
	t := p.current()

	switch t.typ {
	case tokString:
		p.advance()
		return t.value, nil
	case tokNumber:
		p.advance()
		return t.value, nil
	case tokIdent:
		// Unquoted value — may contain wildcards (e.g., "cmd*").
		p.advance()
		val := t.value
		// Absorb trailing * if separate token.
		if p.current().typ == tokStar {
			val += p.advance().value
		}
		return val, nil
	case tokStar:
		p.advance()
		return "*", nil
	default:
		return "", fmt.Errorf("unexpected %q at position %d", t.value, t.pos)
	}
}

func (p *parser) parsePipeStage() (Pipe, error) {
	if p.current().typ != tokIdent {
		return nil, fmt.Errorf("expected pipe command, got %q at position %d", p.current().value, p.current().pos)
	}

	cmd := strings.ToLower(p.advance().value)

	switch cmd {
	case "sort":
		return p.parseSortPipe()
	case "limit", "head":
		return p.parseLimitPipe(cmd)
	case "tail":
		return p.parseTailPipe()
	case "fields":
		return p.parseFieldsPipe()
	default:
		return nil, fmt.Errorf("unknown pipe command %q", cmd)
	}
}

func (p *parser) parseSortPipe() (Pipe, error) {
	if p.current().typ != tokIdent {
		return nil, fmt.Errorf("expected field name for sort")
	}

	field := p.advance().value
	desc := false

	if p.matchKeyword("desc") {
		p.advance()
		desc = true
	} else if p.matchKeyword("asc") {
		p.advance()
	}

	return &SortPipe{Field: field, Desc: desc}, nil
}

func (p *parser) parseLimitPipe(cmd string) (Pipe, error) {
	if p.current().typ != tokNumber {
		return nil, fmt.Errorf("expected number after %s", cmd)
	}

	n, err := strconv.Atoi(p.advance().value)
	if err != nil {
		return nil, fmt.Errorf("invalid number for %s: %w", cmd, err)
	}

	if cmd == "head" {
		return &HeadPipe{N: n}, nil
	}
	return &LimitPipe{N: n}, nil
}

func (p *parser) parseTailPipe() (Pipe, error) {
	if p.current().typ != tokNumber {
		return nil, fmt.Errorf("expected number after tail")
	}

	n, err := strconv.Atoi(p.advance().value)
	if err != nil {
		return nil, fmt.Errorf("invalid number for tail: %w", err)
	}

	return &TailPipe{N: n}, nil
}

func (p *parser) parseFieldsPipe() (Pipe, error) {
	var fields []string

	for {
		if p.current().typ != tokIdent {
			if len(fields) == 0 {
				return nil, fmt.Errorf("expected at least one field name after 'fields'")
			}
			break
		}
		fields = append(fields, p.advance().value)
		if p.current().typ != tokComma {
			break
		}
		p.advance() // consume comma
	}

	return &FieldsPipe{Fields: fields}, nil
}
