import express, { Request, Response } from 'express'
import morgan from 'morgan'
import cors from 'cors'

export const createServer = () => {
	const app = express()

	app.disable('x-powered-by')
		.use(morgan('dev'))
		.use(express.urlencoded({ extended: true }))
		.use(express.json())
		.use(cors())

	app.get('/', (req: Request, res: Response) => {
		res.send('<h1 style="font-family: \'quicksand\', sans-serif;">Hello World</h1>')
	})

	app.get('/health', (req: Request, res: Response) => {
		res.json({ ok: true })
	})

	return app
}
