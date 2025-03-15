import { add } from '../utils'

it('adds numbers', () => {
	expect(add(1, 2)).toBe(3)
	expect(add(1, 2, 3)).toBe(6)
	expect(add(1, 2, 3, 4)).toBe(10)
})
