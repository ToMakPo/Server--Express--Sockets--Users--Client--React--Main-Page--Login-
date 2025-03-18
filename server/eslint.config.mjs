import globals from 'globals'
import pluginJs from '@eslint/js'
import tseslint from 'typescript-eslint'
import jest from 'eslint-plugin-jest'
import eslintPluginPrettierRecommended from 'eslint-plugin-prettier/recommended'

export default [
	{ ignores: ['dist/'] },
	{ files: ['src/**/*.{js,ts}'] },
	{ files: ['**/*.js'], languageOptions: { sourceType: 'commonjs' } },
	{ languageOptions: { globals: globals.node } },
	pluginJs.configs.recommended,
	...tseslint.configs.recommended,
	{
		files: ['src/tests/**/*.{js,ts}'],
		...jest.configs['flat/recommended'],
		rules: { ...jest.configs['flat/recommended'].rules, 'jest/prefer-expect-assertions': 'off' }
	},
	{
		rules: {
			'@typescript-eslint/no-unused-vars': 'off',
			'prettier/prettier': [
				'error',
				{
					singleQuote: true,
					semi: false,
					trailingComma: 'none',
					endOfLine: 'auto',
					useTabs: true,
					tabWidth: 4,
					printWidth: 140,
					bracketSpacing: true,
					bracketSameLine: false,
					arrowParens: 'avoid'
				}
			],
			'no-console': 'off',
			'no-unused-vars': 'off',
			'no-explicit-any': 'off',
			'@typescript-eslint/no-explicit-any': 'off',
			'import/no-unresolved': 'off',
			'import/extensions': 'off',
			'import/prefer-default-export': 'off'
		}
	},
	eslintPluginPrettierRecommended
]
