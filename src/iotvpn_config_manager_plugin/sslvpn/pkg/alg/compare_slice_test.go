package alg

import (
	"testing"
)

// 测试用的简单结构体
type TestUser struct {
	ID   string
	Name string
	Age  int
}

// 测试CompareSlice函数
func TestCompareSlice(t *testing.T) {
	// 定义key函数
	keyFunc := func(user TestUser) string {
		return user.ID
	}

	// 定义compare函数
	compareFunc := func(left, right TestUser) bool {
		return left.Name == right.Name && left.Age == right.Age
	}

	// 测试数据
	left := []TestUser{
		{ID: "1", Name: "Alice", Age: 25},
		{ID: "2", Name: "Bob", Age: 30},
		{ID: "3", Name: "Charlie", Age: 35},
		{ID: "4", Name: "David", Age: 40},
	}

	right := []TestUser{
		{ID: "1", Name: "Alice", Age: 25},   // 相同
		{ID: "2", Name: "Bob", Age: 31},     // 修改（年龄变化）
		{ID: "3", Name: "Charlie", Age: 35}, // 相同
		{ID: "5", Name: "Eve", Age: 28},     // 新增
	}
	// ID "4" (David) 被删除

	// 执行比较
	same, del, add, modify := CompareSlice(left, right, keyFunc, compareFunc)

	// 验证结果
	// 应该有2个相同的元素
	if len(same) != 2 {
		t.Errorf("Expected 2 same elements, got %d", len(same))
	}

	// 验证相同元素的内容
	sameIDs := make(map[string]bool)
	for _, user := range same {
		sameIDs[user.ID] = true
	}
	if !sameIDs["1"] || !sameIDs["3"] {
		t.Error("Same elements should contain users with ID 1 and 3")
	}

	// 应该有1个删除的元素
	if len(del) != 1 {
		t.Errorf("Expected 1 deleted element, got %d", len(del))
	}
	if del[0].ID != "4" {
		t.Errorf("Expected deleted element ID to be '4', got '%s'", del[0].ID)
	}

	// 应该有1个新增的元素
	if len(add) != 1 {
		t.Errorf("Expected 1 added element, got %d", len(add))
	}
	if add[0].ID != "5" {
		t.Errorf("Expected added element ID to be '5', got '%s'", add[0].ID)
	}

	// 应该有1个修改的元素
	if len(modify) != 1 {
		t.Errorf("Expected 1 modified element, got %d", len(modify))
	}
	if modify[0].ID != "2" {
		t.Errorf("Expected modified element ID to be '2', got '%s'", modify[0].ID)
	}
	if modify[0].Age != 31 {
		t.Errorf("Expected modified element age to be 31, got %d", modify[0].Age)
	}
}

// 测试空切片的情况
func TestCompareSliceEmpty(t *testing.T) {
	keyFunc := func(user TestUser) string {
		return user.ID
	}
	compareFunc := func(left, right TestUser) bool {
		return left.Name == right.Name && left.Age == right.Age
	}

	// 测试空切片
	left := []TestUser{}
	right := []TestUser{
		{ID: "1", Name: "Alice", Age: 25},
	}

	same, del, add, modify := CompareSlice(left, right, keyFunc, compareFunc)

	if len(same) != 0 {
		t.Errorf("Expected 0 same elements, got %d", len(same))
	}
	if len(del) != 0 {
		t.Errorf("Expected 0 deleted elements, got %d", len(del))
	}
	if len(add) != 1 {
		t.Errorf("Expected 1 added element, got %d", len(add))
	}
	if len(modify) != 0 {
		t.Errorf("Expected 0 modified elements, got %d", len(modify))
	}
}

// 测试全部相同的情况
func TestCompareSliceAllSame(t *testing.T) {
	keyFunc := func(user TestUser) string {
		return user.ID
	}
	compareFunc := func(left, right TestUser) bool {
		return left.Name == right.Name && left.Age == right.Age
	}

	users := []TestUser{
		{ID: "1", Name: "Alice", Age: 25},
		{ID: "2", Name: "Bob", Age: 30},
	}

	same, del, add, modify := CompareSlice(users, users, keyFunc, compareFunc)

	if len(same) != 2 {
		t.Errorf("Expected 2 same elements, got %d", len(same))
	}
	if len(del) != 0 {
		t.Errorf("Expected 0 deleted elements, got %d", len(del))
	}
	if len(add) != 0 {
		t.Errorf("Expected 0 added elements, got %d", len(add))
	}
	if len(modify) != 0 {
		t.Errorf("Expected 0 modified elements, got %d", len(modify))
	}
}
