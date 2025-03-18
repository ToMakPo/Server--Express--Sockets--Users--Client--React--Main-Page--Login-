import express, { Request, Response } from 'express'
import dotenv from 'dotenv'
import mongoose from 'mongoose'
import morgan from 'morgan'
import cors from 'cors'
import routes from './routes/Routes'
import User from './models/User'
import cookieParser from 'cookie-parser'

dotenv.config()

const app = express()

app.disable('x-powered-by')
	.use(morgan('dev'))
	.use(express.urlencoded({ extended: true }))
	.use(express.json())
	.use(cors())
	.use(cookieParser())

// Connect to the database
const connectToDatabase = async () => {
	if (process.env.MONGODB_URI) {
		await mongoose
			.connect(process.env.MONGODB_URI)
			.then(() => console.info('MongoDB connected'))
			.catch((err: Error) => console.error('MongoDB connection error:', err))
	}
}
connectToDatabase()

// Set EJS as the view engine
app.set('view engine', 'ejs')
app.set('views', './src/pages')

// Middleware for authentication
app.use('/api', routes)

app.get('/', User.getUserInfo, (req: Request, res: Response) => {
	const user = req.body.user
	res.render('home/HomePage', { title: 'Home Page', user })
})

app.get('/login', User.dontAuthenticate, (req: Request, res: Response) => {
	res.render('login/LoginPage')
})

app.get('/test', User.authenticate, (req: Request, res: Response) => {
	res.status(200).send(`Hello ${req.body.user.username}!`)
})

const PORT = process.env.PORT || 5500

app.listen(PORT, () => {
	console.info(`Server is running on http://localhost:${PORT}`)
})
