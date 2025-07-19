package alg

//通用的数组对比函数， 对比两个切片成员， 通过key 和比较函数，来确定left right 两个数组有什么差异
//一般是为了避免更新操作时， 对所有数据都进行修改， 只修改差异部分

func CompareSlice[T any](left []T, right []T, key func(T) string, compare func(T, T) bool) (same []T, del []T, add []T, modify []T) {
	leftMap := make(map[string]T)
	rightMap := make(map[string]T)

	for _, item := range left {
		leftMap[key(item)] = item
	}

	for _, item := range right {
		rightMap[key(item)] = item
	}

	// 遍历左侧切片（原始数据）
	for k, leftItem := range leftMap {
		if rightItem, exists := rightMap[k]; exists {
			// 在右侧切片中存在相同key的元素
			if compare(leftItem, rightItem) {
				// 内容相同，加入same切片
				same = append(same, leftItem)
			} else {
				// 内容不同，加入modify切片（使用右侧的新值）
				modify = append(modify, rightItem)
			}
		} else {
			// 在右侧切片中不存在，需要删除
			del = append(del, leftItem)
		}
	}

	// 遍历右侧切片（新数据）
	for k, rightItem := range rightMap {
		if _, exists := leftMap[k]; !exists {
			// 在左侧切片中不存在，需要添加
			add = append(add, rightItem)
		}
	}

	return same, del, add, modify
}
