package query

import (
	"strings"
	"testing"
)

// --- Simple field comparisons ---

func TestParse_SimpleEquals(t *testing.T) {
	q, err := Parse(`process.name = "cmd.exe"`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cmp, ok := q.Filter.(*CompareExpr)
	if !ok {
		t.Fatalf("expected CompareExpr, got %T", q.Filter)
	}
	if cmp.Field != "process.name" {
		t.Errorf("expected field process.name, got %s", cmp.Field)
	}
	if cmp.Operator != OpEquals {
		t.Errorf("expected operator =, got %s", cmp.Operator)
	}
	if cmp.Value != "cmd.exe" {
		t.Errorf("expected value cmd.exe, got %s", cmp.Value)
	}
}

func TestParse_NotEquals(t *testing.T) {
	q, err := Parse(`event.action != "logoff"`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cmp := q.Filter.(*CompareExpr)
	if cmp.Operator != OpNotEquals {
		t.Errorf("expected !=, got %s", cmp.Operator)
	}
}

func TestParse_GreaterThan(t *testing.T) {
	q, err := Parse(`event.severity > 5`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cmp := q.Filter.(*CompareExpr)
	if cmp.Field != "event.severity" || cmp.Operator != OpGreater || cmp.Value != "5" {
		t.Errorf("unexpected: %s %s %s", cmp.Field, cmp.Operator, cmp.Value)
	}
}

func TestParse_LessThanOrEqual(t *testing.T) {
	q, err := Parse(`event.risk_score <= 50`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cmp := q.Filter.(*CompareExpr)
	if cmp.Operator != OpLTE_Q {
		t.Errorf("expected <=, got %s", cmp.Operator)
	}
}

func TestParse_TimestampField(t *testing.T) {
	q, err := Parse(`@timestamp > "2026-01-01T00:00:00Z"`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cmp := q.Filter.(*CompareExpr)
	if cmp.Field != "@timestamp" {
		t.Errorf("expected @timestamp, got %s", cmp.Field)
	}
}

// --- Wildcards ---

func TestParse_WildcardValue(t *testing.T) {
	q, err := Parse(`process.name = "cmd*"`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cmp := q.Filter.(*CompareExpr)
	if cmp.Value != "cmd*" {
		t.Errorf("expected cmd*, got %s", cmp.Value)
	}
}

func TestParse_UnquotedWildcard(t *testing.T) {
	q, err := Parse(`process.name = cmd*`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cmp := q.Filter.(*CompareExpr)
	if cmp.Value != "cmd*" {
		t.Errorf("expected cmd*, got %s", cmp.Value)
	}
}

// --- Boolean logic ---

func TestParse_AND(t *testing.T) {
	q, err := Parse(`process.name = "cmd.exe" AND user.name = "admin"`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	boolExpr, ok := q.Filter.(*BoolExpr)
	if !ok {
		t.Fatalf("expected BoolExpr, got %T", q.Filter)
	}
	if boolExpr.Op != BoolAnd {
		t.Errorf("expected AND, got %s", boolExpr.Op)
	}

	left := boolExpr.Left.(*CompareExpr)
	right := boolExpr.Right.(*CompareExpr)
	if left.Field != "process.name" || right.Field != "user.name" {
		t.Errorf("unexpected fields: %s, %s", left.Field, right.Field)
	}
}

func TestParse_OR(t *testing.T) {
	q, err := Parse(`event.action = "logon" OR event.action = "logoff"`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	boolExpr := q.Filter.(*BoolExpr)
	if boolExpr.Op != BoolOr {
		t.Errorf("expected OR, got %s", boolExpr.Op)
	}
}

func TestParse_NOT(t *testing.T) {
	q, err := Parse(`NOT process.name = "explorer.exe"`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	boolExpr := q.Filter.(*BoolExpr)
	if boolExpr.Op != BoolNot {
		t.Errorf("expected NOT, got %s", boolExpr.Op)
	}
	if boolExpr.Right != nil {
		t.Error("NOT should have nil Right")
	}
}

func TestParse_ComplexBoolean(t *testing.T) {
	// (A AND B) OR NOT C
	q, err := Parse(`(process.name = "cmd.exe" AND user.name = "admin") OR NOT event.action = "logoff"`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	boolExpr := q.Filter.(*BoolExpr)
	if boolExpr.Op != BoolOr {
		t.Errorf("expected top-level OR, got %s", boolExpr.Op)
	}

	// Left should be AND.
	leftBool := boolExpr.Left.(*BoolExpr)
	if leftBool.Op != BoolAnd {
		t.Errorf("expected left AND, got %s", leftBool.Op)
	}

	// Right should be NOT.
	rightBool := boolExpr.Right.(*BoolExpr)
	if rightBool.Op != BoolNot {
		t.Errorf("expected right NOT, got %s", rightBool.Op)
	}
}

func TestParse_OperatorPrecedence_AND_before_OR(t *testing.T) {
	// A OR B AND C should parse as A OR (B AND C)
	q, err := Parse(`a = "1" OR b = "2" AND c = "3"`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	boolExpr := q.Filter.(*BoolExpr)
	if boolExpr.Op != BoolOr {
		t.Errorf("expected top-level OR, got %s", boolExpr.Op)
	}

	// Right should be AND (higher precedence).
	rightBool := boolExpr.Right.(*BoolExpr)
	if rightBool.Op != BoolAnd {
		t.Errorf("expected right AND, got %s", rightBool.Op)
	}
}

// --- Exists ---

func TestParse_Exists(t *testing.T) {
	q, err := Parse(`process.parent.name exists`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	exists, ok := q.Filter.(*ExistsExpr)
	if !ok {
		t.Fatalf("expected ExistsExpr, got %T", q.Filter)
	}
	if exists.Field != "process.parent.name" {
		t.Errorf("expected process.parent.name, got %s", exists.Field)
	}
}

// --- IN expression ---

func TestParse_IN(t *testing.T) {
	q, err := Parse(`event.action IN ("logon", "logoff", "failed_logon")`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	in, ok := q.Filter.(*InExpr)
	if !ok {
		t.Fatalf("expected InExpr, got %T", q.Filter)
	}
	if in.Field != "event.action" {
		t.Errorf("expected event.action, got %s", in.Field)
	}
	if len(in.Values) != 3 {
		t.Fatalf("expected 3 values, got %d", len(in.Values))
	}
	if in.Values[0] != "logon" || in.Values[1] != "logoff" || in.Values[2] != "failed_logon" {
		t.Errorf("unexpected values: %v", in.Values)
	}
}

// --- Pipe stages ---

func TestParse_SortPipe(t *testing.T) {
	q, err := Parse(`process.name = "cmd.exe" | sort @timestamp desc`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(q.Pipes) != 1 {
		t.Fatalf("expected 1 pipe, got %d", len(q.Pipes))
	}
	sort, ok := q.Pipes[0].(*SortPipe)
	if !ok {
		t.Fatalf("expected SortPipe, got %T", q.Pipes[0])
	}
	if sort.Field != "@timestamp" || !sort.Desc {
		t.Errorf("expected @timestamp desc, got %s desc=%v", sort.Field, sort.Desc)
	}
}

func TestParse_SortAsc(t *testing.T) {
	q, err := Parse(`* | sort event.severity asc`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sort := q.Pipes[0].(*SortPipe)
	if sort.Desc {
		t.Error("expected asc (desc=false)")
	}
}

func TestParse_LimitPipe(t *testing.T) {
	q, err := Parse(`user.name = "admin" | limit 100`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lim := q.Pipes[0].(*LimitPipe)
	if lim.N != 100 {
		t.Errorf("expected limit 100, got %d", lim.N)
	}
}

func TestParse_HeadPipe(t *testing.T) {
	q, err := Parse(`user.name = "admin" | head 50`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	head := q.Pipes[0].(*HeadPipe)
	if head.N != 50 {
		t.Errorf("expected head 50, got %d", head.N)
	}
}

func TestParse_TailPipe(t *testing.T) {
	q, err := Parse(`user.name = "admin" | tail 25`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tail := q.Pipes[0].(*TailPipe)
	if tail.N != 25 {
		t.Errorf("expected tail 25, got %d", tail.N)
	}
}

func TestParse_FieldsPipe(t *testing.T) {
	q, err := Parse(`user.name = "admin" | fields user.name, process.name, @timestamp`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	fields := q.Pipes[0].(*FieldsPipe)
	if len(fields.Fields) != 3 {
		t.Fatalf("expected 3 fields, got %d", len(fields.Fields))
	}
	if fields.Fields[0] != "user.name" || fields.Fields[1] != "process.name" || fields.Fields[2] != "@timestamp" {
		t.Errorf("unexpected fields: %v", fields.Fields)
	}
}

func TestParse_MultiplePipes(t *testing.T) {
	q, err := Parse(`process.name = "cmd.exe" | sort @timestamp desc | limit 100`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(q.Pipes) != 2 {
		t.Fatalf("expected 2 pipes, got %d", len(q.Pipes))
	}

	if _, ok := q.Pipes[0].(*SortPipe); !ok {
		t.Errorf("expected SortPipe first, got %T", q.Pipes[0])
	}
	if _, ok := q.Pipes[1].(*LimitPipe); !ok {
		t.Errorf("expected LimitPipe second, got %T", q.Pipes[1])
	}
}

// --- Aggregation ---

func TestParse_CountAgg(t *testing.T) {
	q, err := Parse(`count() by user.name where event.action = "failed_logon"`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if q.Agg == nil {
		t.Fatal("expected aggregation")
	}
	if q.Agg.Function != AggCount {
		t.Errorf("expected count, got %s", q.Agg.Function)
	}
	if q.Agg.Field != "" {
		t.Errorf("expected empty field for count(), got %s", q.Agg.Field)
	}
	if len(q.Agg.GroupBy) != 1 || q.Agg.GroupBy[0] != "user.name" {
		t.Errorf("expected group-by [user.name], got %v", q.Agg.GroupBy)
	}
	if q.Filter == nil {
		t.Fatal("expected where filter")
	}
}

func TestParse_SumAgg(t *testing.T) {
	q, err := Parse(`sum(event.risk_score) by host.name`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if q.Agg.Function != AggSum {
		t.Errorf("expected sum, got %s", q.Agg.Function)
	}
	if q.Agg.Field != "event.risk_score" {
		t.Errorf("expected field event.risk_score, got %s", q.Agg.Field)
	}
}

func TestParse_CountMultiGroupBy(t *testing.T) {
	q, err := Parse(`count() by user.name, host.name`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(q.Agg.GroupBy) != 2 {
		t.Fatalf("expected 2 group-by fields, got %d", len(q.Agg.GroupBy))
	}
	if q.Agg.GroupBy[0] != "user.name" || q.Agg.GroupBy[1] != "host.name" {
		t.Errorf("unexpected group-by: %v", q.Agg.GroupBy)
	}
}

func TestParse_AggWithPipe(t *testing.T) {
	q, err := Parse(`count() by user.name where event.action = "logon" | sort user.name asc | limit 10`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if q.Agg == nil {
		t.Fatal("expected aggregation")
	}
	if q.Filter == nil {
		t.Fatal("expected filter")
	}
	if len(q.Pipes) != 2 {
		t.Fatalf("expected 2 pipes, got %d", len(q.Pipes))
	}
}

// --- Full complex query from requirements ---

func TestParse_FullComplexQuery(t *testing.T) {
	input := `process.name = "cmd.exe" AND user.name != "SYSTEM" | sort @timestamp desc | limit 100`
	q, err := Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	boolExpr := q.Filter.(*BoolExpr)
	if boolExpr.Op != BoolAnd {
		t.Errorf("expected AND, got %s", boolExpr.Op)
	}

	if len(q.Pipes) != 2 {
		t.Fatalf("expected 2 pipes, got %d", len(q.Pipes))
	}
}

// --- Error cases ---

func TestParse_EmptyQuery(t *testing.T) {
	q, err := Parse("")
	if err != nil {
		t.Fatalf("empty query should be valid (match all): %v", err)
	}
	if q.Filter != nil {
		t.Error("expected nil filter for empty query")
	}
}

func TestParse_InvalidOperator(t *testing.T) {
	_, err := Parse(`process.name ~ "cmd"`)
	if err == nil {
		t.Fatal("expected error for invalid operator")
	}
}

func TestParse_MissingValue(t *testing.T) {
	_, err := Parse(`process.name =`)
	if err == nil {
		t.Fatal("expected error for missing value")
	}
}

func TestParse_UnclosedParen(t *testing.T) {
	_, err := Parse(`(process.name = "cmd.exe"`)
	if err == nil {
		t.Fatal("expected error for unclosed paren")
	}
}

func TestParse_UnknownPipeCommand(t *testing.T) {
	_, err := Parse(`process.name = "cmd.exe" | bogus`)
	if err == nil {
		t.Fatal("expected error for unknown pipe command")
	}
}

func TestParse_LimitMissingNumber(t *testing.T) {
	_, err := Parse(`process.name = "cmd.exe" | limit`)
	if err == nil {
		t.Fatal("expected error for limit without number")
	}
}

func TestParse_MissingByInAgg(t *testing.T) {
	_, err := Parse(`count() user.name`)
	if err == nil {
		t.Fatal("expected error for aggregation missing 'by'")
	}
}

func TestParse_SingleQuotedString(t *testing.T) {
	q, err := Parse(`process.name = 'cmd.exe'`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cmp := q.Filter.(*CompareExpr)
	if cmp.Value != "cmd.exe" {
		t.Errorf("expected cmd.exe, got %s", cmp.Value)
	}
}

// --- Tokenizer edge cases ---

func TestTokenize_Operators(t *testing.T) {
	tokens := tokenize(`= != > < >= <=`)
	ops := []string{"=", "!=", ">", "<", ">=", "<="}
	for i, expected := range ops {
		if tokens[i].value != expected {
			t.Errorf("token %d: expected %s, got %s", i, expected, tokens[i].value)
		}
	}
}

func TestTokenize_DottedField(t *testing.T) {
	tokens := tokenize(`process.parent.name`)
	if tokens[0].value != "process.parent.name" {
		t.Errorf("expected single dotted token, got %s", tokens[0].value)
	}
}

func TestTokenize_AtField(t *testing.T) {
	tokens := tokenize(`@timestamp`)
	if tokens[0].value != "@timestamp" {
		t.Errorf("expected @timestamp, got %s", tokens[0].value)
	}
}

// =============================================================
// Adversarial / injection / edge-case tests
// =============================================================

// --- Injection: values containing query syntax ---

func TestAdversarial_ValueContainsOperators(t *testing.T) {
	// Value with > and AND inside — must not confuse parser.
	q, err := Parse(`field = "a > b AND c = d"`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cmp := q.Filter.(*CompareExpr)
	if cmp.Value != "a > b AND c = d" {
		t.Errorf("value not preserved: got %q", cmp.Value)
	}
}

func TestAdversarial_ValueContainsPipe(t *testing.T) {
	q, err := Parse(`field = "hello | world"`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cmp := q.Filter.(*CompareExpr)
	if cmp.Value != "hello | world" {
		t.Errorf("pipe in value not preserved: got %q", cmp.Value)
	}
	if len(q.Pipes) != 0 {
		t.Error("pipe inside quotes should not create a pipe stage")
	}
}

func TestAdversarial_ValueContainsParens(t *testing.T) {
	q, err := Parse(`field = "(not a group)"`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cmp := q.Filter.(*CompareExpr)
	if cmp.Value != "(not a group)" {
		t.Errorf("parens in value not preserved: got %q", cmp.Value)
	}
}

func TestAdversarial_EscapedQuotes(t *testing.T) {
	q, err := Parse(`field = "value with \"escaped\" quotes"`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cmp := q.Filter.(*CompareExpr)
	// The tokenizer preserves the backslash — downstream can unescape.
	if !strings.Contains(cmp.Value, "escaped") {
		t.Errorf("escaped quotes not handled: got %q", cmp.Value)
	}
}

func TestAdversarial_EmptyString(t *testing.T) {
	q, err := Parse(`field = ""`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cmp := q.Filter.(*CompareExpr)
	if cmp.Value != "" {
		t.Errorf("expected empty string value, got %q", cmp.Value)
	}
}

func TestAdversarial_SingleQuoteInDouble(t *testing.T) {
	q, err := Parse(`field = "it's a test"`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cmp := q.Filter.(*CompareExpr)
	if cmp.Value != "it's a test" {
		t.Errorf("single quote in double-quoted string: got %q", cmp.Value)
	}
}

// --- Parser confusion: keywords as field/value names ---

func TestAdversarial_KeywordAsFieldName_AND(t *testing.T) {
	// "AND" used as a field name — parser should treat first AND as field.
	// This is ambiguous by design; the parser should either handle it or
	// give a clear error. Testing that it doesn't panic.
	_, _ = Parse(`AND = "true"`)
	// No panic = pass. Parser may error or succeed depending on design.
}

func TestAdversarial_KeywordAsFieldName_NOT(t *testing.T) {
	_, _ = Parse(`NOT = "value"`)
	// NOT is parsed as a unary operator, so this likely errors. No panic = pass.
}

func TestAdversarial_KeywordAsValue(t *testing.T) {
	// Unquoted AND as a value — should be treated as keyword, not value.
	// This should error since AND starts a new boolean clause.
	_, err := Parse(`field = AND`)
	// Either error or treats AND as value — must not panic.
	_ = err
}

func TestAdversarial_CountAsFieldName(t *testing.T) {
	// "count" used as a regular field name (no parens after).
	q, err := Parse(`count = 5`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cmp := q.Filter.(*CompareExpr)
	if cmp.Field != "count" || cmp.Value != "5" {
		t.Errorf("expected count = 5, got %s = %s", cmp.Field, cmp.Value)
	}
}

func TestAdversarial_FieldWithHyphens(t *testing.T) {
	q, err := Parse(`source-ip = "10.0.0.1"`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cmp := q.Filter.(*CompareExpr)
	if cmp.Field != "source-ip" {
		t.Errorf("expected source-ip, got %s", cmp.Field)
	}
}

// --- Deeply nested / structural edge cases ---

func TestAdversarial_DeeplyNestedParens(t *testing.T) {
	q, err := Parse(`(((((a = "1")))))`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cmp := q.Filter.(*CompareExpr)
	if cmp.Field != "a" || cmp.Value != "1" {
		t.Errorf("deeply nested parse failed: %s = %s", cmp.Field, cmp.Value)
	}
}

func TestAdversarial_EmptyParens(t *testing.T) {
	_, err := Parse(`()`)
	if err == nil {
		t.Fatal("expected error for empty parens")
	}
}

func TestAdversarial_DoubleNOT(t *testing.T) {
	q, err := Parse(`NOT NOT field = "x"`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	outer := q.Filter.(*BoolExpr)
	if outer.Op != BoolNot {
		t.Errorf("expected outer NOT, got %s", outer.Op)
	}
	inner := outer.Left.(*BoolExpr)
	if inner.Op != BoolNot {
		t.Errorf("expected inner NOT, got %s", inner.Op)
	}
}

func TestAdversarial_DeepFieldPath(t *testing.T) {
	q, err := Parse(`a.b.c.d.e.f.g.h = "deep"`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cmp := q.Filter.(*CompareExpr)
	if cmp.Field != "a.b.c.d.e.f.g.h" {
		t.Errorf("expected deep field path, got %s", cmp.Field)
	}
}

// --- Malformed input ---

func TestAdversarial_OnlyWhitespace(t *testing.T) {
	q, err := Parse("   \t\n  ")
	if err != nil {
		t.Fatalf("whitespace-only should be valid (match all): %v", err)
	}
	if q.Filter != nil {
		t.Error("expected nil filter for whitespace-only")
	}
}

func TestAdversarial_OnlyPipe(t *testing.T) {
	_, err := Parse(`|`)
	if err == nil {
		t.Fatal("expected error for bare pipe")
	}
}

func TestAdversarial_PipeWithNoFilter(t *testing.T) {
	// Should parse as match-all with pipe stages.
	q, err := Parse(`| sort @timestamp desc | limit 10`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if q.Filter != nil {
		t.Error("expected nil filter before pipe")
	}
	if len(q.Pipes) != 2 {
		t.Fatalf("expected 2 pipes, got %d", len(q.Pipes))
	}
}

func TestAdversarial_DoublePipe(t *testing.T) {
	_, err := Parse(`field = "x" | | sort a`)
	if err == nil {
		t.Fatal("expected error for consecutive pipes")
	}
}

func TestAdversarial_TrailingPipe(t *testing.T) {
	_, err := Parse(`field = "x" |`)
	if err == nil {
		t.Fatal("expected error for trailing pipe")
	}
}

func TestAdversarial_UnmatchedClosingParen(t *testing.T) {
	_, err := Parse(`field = "x")`)
	if err == nil {
		t.Fatal("expected error for unmatched closing paren")
	}
}

func TestAdversarial_MissingField(t *testing.T) {
	_, err := Parse(`= "value"`)
	if err == nil {
		t.Fatal("expected error for missing field")
	}
}

func TestAdversarial_UnclosedQuote(t *testing.T) {
	// Unclosed quote — tokenizer should handle gracefully.
	// The parser should either succeed with partial value or error.
	// Must not panic.
	_, _ = Parse(`field = "unclosed`)
}

func TestAdversarial_NullBytes(t *testing.T) {
	// Input with null bytes — must not panic.
	_, _ = Parse("field = \"val\x00ue\"")
}

func TestAdversarial_ControlChars(t *testing.T) {
	// Input with control characters — must not panic.
	_, _ = Parse("field\x01 = \x02\"value\x03\"")
}

func TestAdversarial_VeryLongInput(t *testing.T) {
	// 10,000+ character query — must not panic or hang.
	var sb strings.Builder
	sb.WriteString(`a = "1"`)
	for i := 0; i < 1000; i++ {
		sb.WriteString(` AND b = "2"`)
	}
	q, err := Parse(sb.String())
	if err != nil {
		t.Fatalf("unexpected error on long input: %v", err)
	}
	if q.Filter == nil {
		t.Error("expected non-nil filter for long input")
	}
}

// --- IN edge cases ---

func TestAdversarial_IN_SingleValue(t *testing.T) {
	q, err := Parse(`field IN ("only_one")`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	in := q.Filter.(*InExpr)
	if len(in.Values) != 1 || in.Values[0] != "only_one" {
		t.Errorf("expected single value, got %v", in.Values)
	}
}

func TestAdversarial_IN_EmptyList(t *testing.T) {
	_, err := Parse(`field IN ()`)
	if err == nil {
		t.Fatal("expected error for empty IN list")
	}
}

// --- Star / match-all ---

func TestAdversarial_StarOnly(t *testing.T) {
	q, err := Parse(`*`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Star means match-all → nil filter.
	if q.Filter != nil {
		t.Error("expected nil filter for star query")
	}
}

func TestAdversarial_StarWithPipes(t *testing.T) {
	q, err := Parse(`* | sort @timestamp desc | limit 50`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if q.Filter != nil {
		t.Error("expected nil filter for star")
	}
	if len(q.Pipes) != 2 {
		t.Fatalf("expected 2 pipes, got %d", len(q.Pipes))
	}
}

// --- Adjacent / duplicate operators ---

func TestAdversarial_AdjacentOperators(t *testing.T) {
	_, err := Parse(`field >= <= "value"`)
	if err == nil {
		t.Fatal("expected error for adjacent operators")
	}
}

func TestAdversarial_OperatorOnly(t *testing.T) {
	_, err := Parse(`>=`)
	if err == nil {
		t.Fatal("expected error for operator only")
	}
}

// --- Case insensitivity of keywords ---

func TestAdversarial_CaseInsensitiveKeywords(t *testing.T) {
	q, err := Parse(`a = "1" and b = "2" or c = "3"`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should parse same as AND/OR.
	boolExpr := q.Filter.(*BoolExpr)
	if boolExpr.Op != BoolOr {
		t.Errorf("expected OR at top level, got %s", boolExpr.Op)
	}
}

func TestAdversarial_MixedCaseNOT(t *testing.T) {
	q, err := Parse(`Not field = "x"`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	boolExpr := q.Filter.(*BoolExpr)
	if boolExpr.Op != BoolNot {
		t.Errorf("expected NOT, got %s", boolExpr.Op)
	}
}

func TestAdversarial_CaseInsensitiveIN(t *testing.T) {
	q, err := Parse(`field in ("a", "b")`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, ok := q.Filter.(*InExpr)
	if !ok {
		t.Fatalf("expected InExpr, got %T", q.Filter)
	}
}

func TestAdversarial_CaseInsensitiveExists(t *testing.T) {
	q, err := Parse(`field EXISTS`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, ok := q.Filter.(*ExistsExpr)
	if !ok {
		t.Fatalf("expected ExistsExpr, got %T", q.Filter)
	}
}

// --- Pipe edge cases ---

func TestAdversarial_SortDefaultDirection(t *testing.T) {
	q, err := Parse(`a = "1" | sort @timestamp`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sort := q.Pipes[0].(*SortPipe)
	if sort.Desc {
		t.Error("expected default asc when no direction specified")
	}
}

func TestAdversarial_FieldsPipeSingle(t *testing.T) {
	q, err := Parse(`a = "1" | fields user.name`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	fields := q.Pipes[0].(*FieldsPipe)
	if len(fields.Fields) != 1 || fields.Fields[0] != "user.name" {
		t.Errorf("expected single field, got %v", fields.Fields)
	}
}

// --- Numeric field names ---

func TestAdversarial_NumericStartFieldName(t *testing.T) {
	// Field starting with number — "123" is tokenized as number, not ident.
	_, err := Parse(`123 = "bad"`)
	if err == nil {
		t.Fatal("expected error for numeric field name")
	}
}
