export function add(...nums: number[]) {
	return nums.reduce((acc, num) => acc + num, 0)
}
