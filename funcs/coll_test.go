package funcs

import (
	"context"
	"reflect"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateCollFuncs(t *testing.T) {
	t.Parallel()

	for i := 0; i < 10; i++ {
		// Run this a bunch to catch race conditions
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			fmap := CreateCollFuncs(ctx)
			actual := fmap["coll"].(func() interface{})

			assert.Equal(t, ctx, actual().(*CollFuncs).ctx)
		})
	}
}

func TestFlatten(t *testing.T) {
	t.Parallel()

	c := CollFuncs{}

	_, err := c.Flatten()
	assert.Error(t, err)

	_, err = c.Flatten(42)
	assert.Error(t, err)

	out, err := c.Flatten([]interface{}{1, []interface{}{[]int{2}, 3}})
	assert.NoError(t, err)
	assert.EqualValues(t, []interface{}{1, 2, 3}, out)

	out, err = c.Flatten(1, []interface{}{1, []interface{}{[]int{2}, 3}})
	assert.NoError(t, err)
	assert.EqualValues(t, []interface{}{1, []int{2}, 3}, out)
}

func TestPick(t *testing.T) {
	t.Parallel()

	c := &CollFuncs{}

	_, err := c.Pick()
	assert.Error(t, err)

	_, err = c.Pick("")
	assert.Error(t, err)

	_, err = c.Pick("foo", nil)
	assert.Error(t, err)

	_, err = c.Pick("foo", "bar")
	assert.Error(t, err)

	_, err = c.Pick(map[string]interface{}{}, "foo", "bar", map[string]interface{}{})
	assert.Error(t, err)

	in := map[string]interface{}{
		"foo": "bar",
		"bar": true,
		"":    "baz",
	}
	out, err := c.Pick("baz", in)
	assert.NoError(t, err)
	assert.EqualValues(t, map[string]interface{}{}, out)

	expected := map[string]interface{}{
		"foo": "bar",
		"bar": true,
	}
	out, err = c.Pick("foo", "bar", in)
	assert.NoError(t, err)
	assert.EqualValues(t, expected, out)

	expected = map[string]interface{}{
		"": "baz",
	}
	out, err = c.Pick("", in)
	assert.NoError(t, err)
	assert.EqualValues(t, expected, out)

	out, err = c.Pick("foo", "bar", "", in)
	assert.NoError(t, err)
	assert.EqualValues(t, in, out)
}

func TestOmit(t *testing.T) {
	t.Parallel()

	c := &CollFuncs{}

	_, err := c.Omit()
	assert.Error(t, err)

	_, err = c.Omit("")
	assert.Error(t, err)

	_, err = c.Omit("foo", nil)
	assert.Error(t, err)

	_, err = c.Omit("foo", "bar")
	assert.Error(t, err)

	_, err = c.Omit(map[string]interface{}{}, "foo", "bar", map[string]interface{}{})
	assert.Error(t, err)

	in := map[string]interface{}{
		"foo": "bar",
		"bar": true,
		"":    "baz",
	}
	out, err := c.Omit("baz", in)
	assert.NoError(t, err)
	assert.EqualValues(t, in, out)

	expected := map[string]interface{}{
		"foo": "bar",
		"bar": true,
	}
	out, err = c.Omit("", in)
	assert.NoError(t, err)
	assert.EqualValues(t, expected, out)

	expected = map[string]interface{}{
		"": "baz",
	}
	out, err = c.Omit("foo", "bar", in)
	assert.NoError(t, err)
	assert.EqualValues(t, expected, out)

	out, err = c.Omit("foo", "bar", "", in)
	assert.NoError(t, err)
	assert.EqualValues(t, map[string]interface{}{}, out)
}

func TestGoSlice(t *testing.T) {
	t.Parallel()

	c := &CollFuncs{}

	in := reflect.ValueOf(nil)
	_, err := c.GoSlice(in)
	assert.Error(t, err)

	in = reflect.ValueOf(42)
	_, err = c.GoSlice(in)
	assert.Error(t, err)

	// invalid index type
	in = reflect.ValueOf([]interface{}{1})
	_, err = c.GoSlice(in, reflect.ValueOf([]interface{}{[]int{2}}))
	assert.Error(t, err)

	// valid slice, no slicing
	in = reflect.ValueOf([]int{1})
	out, err := c.GoSlice(in)
	assert.NoError(t, err)
	assert.Equal(t, reflect.TypeOf([]int{}), out.Type())
	assert.EqualValues(t, []int{1}, out.Interface())

	// valid slice, slicing
	in = reflect.ValueOf([]string{"foo", "bar", "baz"})
	out, err = c.GoSlice(in, reflect.ValueOf(1), reflect.ValueOf(3))
	assert.NoError(t, err)
	assert.Equal(t, reflect.TypeOf([]string{}), out.Type())
	assert.EqualValues(t, []string{"bar", "baz"}, out.Interface())
}
